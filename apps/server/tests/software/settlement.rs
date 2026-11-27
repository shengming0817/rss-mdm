//! The Software owner acknowledges dispatch and appends its audit fact in the original transaction.
use super::*;
use rss_transactional_messaging_postgres::PgTransactionFault;

async fn reject_after_dispatch_update(
    c: &Context,
    a: &Fixture,
    id: Uuid,
    fingerprint: Vec<u8>,
) -> Result<()> {
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
    a.resources
        .storage
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    let rejected = a
        .software
        .service
        .accept_action_dispatch(c.execution(), id, fingerprint)
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
    Ok(())
}

async fn dispatch_state(c: &Context, id: Uuid) -> Result<(Vec<u8>, bool, i64)> {
    let (fingerprint, accepted): (Vec<u8>, bool) = sqlx::query_as(
        "SELECT dispatch_fingerprint, gateway_accepted FROM mdm_software_deployment.action_runs
         WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    let facts = c.audit_count("mdm.business", &id.to_string()).await?;
    Ok((fingerprint, accepted, facts))
}

pub(super) async fn check_dispatch(c: &Context, a: &Fixture, id: Uuid) -> Result<()> {
    let initial = dispatch_state(c, id).await?;
    let (fingerprint, accepted, before) = initial.clone();
    assert!(!accepted);
    reject_after_dispatch_update(c, a, id, fingerprint.clone()).await?;
    assert_eq!(dispatch_state(c, id).await?, initial);

    let service = &a.software.service;
    a.resources
        .storage
        .runtime
        .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let lost = service
        .accept_action_dispatch(c.execution(), id, fingerprint.clone())
        .await;
    assert!(matches!(lost, Err(owner::Error::CommitUnknown)));
    let committed = (fingerprint.clone(), true, before + 1);
    assert_eq!(dispatch_state(c, id).await?, committed);
    service
        .accept_action_dispatch(c.execution(), id, fingerprint)
        .await?;
    assert_eq!(dispatch_state(c, id).await?, committed);
    Ok(())
}
