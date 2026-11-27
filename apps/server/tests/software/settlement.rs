//! The Software owner acknowledges dispatch and appends its audit fact in the original transaction.
use super::*;
use rss_transactional_messaging_postgres::PgTransactionFault;

pub(super) async fn check_dispatch(c: &Context, a: &Fixture, id: Uuid) -> Result<()> {
    let row = || {
        sqlx::query_as::<_, (Vec<u8>, bool)>(
            "SELECT dispatch_fingerprint, gateway_accepted FROM mdm_software_deployment.action_runs
             WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .fetch_one(&c.operator)
    };
    let (fingerprint, accepted) = row().await?;
    assert!(!accepted);
    let before = c.audit_count("mdm.business", &id.to_string()).await?;
    let service = &a.software.service;
    let runtime = &a.resources.storage.runtime;
    // Sequence advances survive rollback and prove the actual row update fired this trigger.
    let probe = format!("t2_dispatch_{}", id.simple());
    let table = "mdm_software_deployment.action_runs";
    let install = format!(
        "CREATE SEQUENCE public.{probe};
         GRANT USAGE ON SEQUENCE public.{probe} TO mdm_command_runtime;
         CREATE FUNCTION public.{probe}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM nextval('public.{probe}'); RAISE EXCEPTION 'dispatch update rejected'; END; $$;
         CREATE TRIGGER {probe} AFTER UPDATE OF gateway_accepted ON {table}
         FOR EACH ROW WHEN (NEW.tenant_id='{}'::uuid AND NEW.id='{id}'::uuid
             AND NEW.gateway_accepted AND NOT OLD.gateway_accepted)
         EXECUTE FUNCTION public.{probe}()", c.tenant
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(install))
        .execute(&c.operator)
        .await?;
    runtime.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    let rejected = service
        .accept_action_dispatch(c.execution(), id, fingerprint.clone())
        .await;
    let fired = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
        "SELECT is_called FROM public.{probe}"
    )))
    .fetch_one(&c.operator)
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {probe} ON {table}; DROP FUNCTION public.{probe}(); DROP SEQUENCE public.{probe}"
    ))).execute(&c.operator).await?;
    assert!(
        fired?,
        "the owner must update the original operation before rollback"
    );
    assert!(matches!(rejected, Err(owner::Error::RollbackFailed)));
    assert_eq!(row().await?, (fingerprint.clone(), false));
    assert_eq!(
        c.audit_count("mdm.business", &id.to_string()).await?,
        before
    );

    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(
        service
            .accept_action_dispatch(c.execution(), id, fingerprint.clone())
            .await,
        Err(owner::Error::CommitUnknown)
    ));
    assert_eq!(row().await?, (fingerprint.clone(), true));
    assert_eq!(
        c.audit_count("mdm.business", &id.to_string()).await?,
        before + 1
    );
    service
        .accept_action_dispatch(c.execution(), id, fingerprint.clone())
        .await?;
    assert_eq!(row().await?, (fingerprint, true));
    assert_eq!(
        c.audit_count("mdm.business", &id.to_string()).await?,
        before + 1
    );
    Ok(())
}
