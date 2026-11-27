//! Faults target this profile's actual registered Software projection.
use super::*;
use crate::assembly::task_relay::{Owner, lanes::SOFTWARE};
use rss_mdm_recovery_observation::Phase;
use rss_reconcile::ErrorKind;
use rss_transactional_messaging_postgres::PgTransactionFault;

pub(super) async fn check_dispatch(c: &Context, a: &Fixture, id: Uuid) -> Result<()> {
    let lane = a.resources.projection(c, SOFTWARE).await?;
    let service = &a.software.service;
    let scope = service.relay_scope(c.execution()).unwrap();
    let original = format!("action.{id}");
    let state = async || -> Result<(bool, String, Option<String>, Vec<u8>, i64)> {
        let (accepted,status,disposition,fingerprint) = sqlx::query_as("SELECT r.gateway_accepted,o.status,i.disposition,o.fingerprint FROM mdm_software_deployment.action_runs r JOIN rss_transactional_messaging.outbox o ON o.tenant_id=r.tenant_id AND o.message_id=$2 AND o.fingerprint=r.dispatch_fingerprint LEFT JOIN rss_transactional_messaging.inbox i ON i.tenant_id=o.tenant_id AND i.message_id=o.message_id AND i.fingerprint=o.fingerprint AND i.consumer_group=$3 WHERE r.tenant_id=$1::uuid AND r.id=$4 AND o.domain=$5")
            .bind(c.tenant.to_string()).bind(&original).bind(SOFTWARE.role).bind(id).bind(SOFTWARE.domain).fetch_one(&c.operator).await?;
        Ok((
            accepted,
            status,
            disposition,
            fingerprint,
            c.audit_count("mdm.business", &id.to_string()).await?,
        ))
    };
    let initial = state().await?;
    assert!(!initial.0 && initial.2.is_none());
    let register = || command::register_relay(c, Owner::Software(service.clone()), lane.clone());
    // Reject only this source row until the provider has settled an acknowledged rollback as Retry.
    let trigger = format!(
        "CREATE FUNCTION public.t2_transient_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'busy' USING ERRCODE='40001'; END $$; CREATE TRIGGER t2_transient_dispatch BEFORE UPDATE OF gateway_accepted ON mdm_software_deployment.action_runs FOR EACH ROW WHEN (NEW.id='{id}'::uuid) EXECUTE FUNCTION public.t2_transient_dispatch()"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(trigger))
        .execute(&c.operator)
        .await?;
    let stack = register()?;
    command::wait_relay(async || {
        Ok(service.health().relay == Some(Phase::Failed(ErrorKind::Transient)))
    })
    .await?;
    assert!(stack.shutdown().join().await?.is_clean());
    let retry:(i32,bool,bool) = sqlx::query_as("SELECT retry_count,retry_after>clock_timestamp(),retry_after<=automatic_retry_deadline FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2 AND status='pending'")
        .bind(c.tenant.to_string()).bind(&original).fetch_one(&c.operator).await?;
    assert_eq!(retry, (1, true, true));
    assert_eq!(state().await?, initial);
    sqlx::raw_sql("DROP TRIGGER t2_transient_dispatch ON mdm_software_deployment.action_runs; DROP FUNCTION public.t2_transient_dispatch()").execute(&c.operator).await?;
    command::check_uncommitted_command(
        c,
        |fault| Ok(lane.inject(fault)?),
        &format!("action:{id}:dispatch"),
        async |expected| {
            let expected = if expected == rss_mdm_audit_integration::WriteOutcome::RollbackFailed {
                ErrorKind::RollbackFailed
            } else {
                ErrorKind::CommitUnknown
            };
            let stack = register()?;
            command::wait_relay(async || {
                Ok(service.health().relay == Some(Phase::Failed(expected)))
            })
            .await?;
            assert!(stack.shutdown().join().await?.is_clean());
            let message = scope.check().unwrap().message().clone();
            assert_eq!(message.id.as_str(), original);
            assert_eq!(
                message.fingerprint.unwrap().as_bytes().as_slice(),
                initial.3
            );
            let observed = state().await?;
            assert_eq!(
                observed,
                (
                    false,
                    "publishing".into(),
                    None,
                    initial.3.clone(),
                    initial.4
                )
            );
            Ok(())
        },
    )
    .await?;
    lane.inject(PgTransactionFault::CommitUnknownAfterAck)?;
    let stack = register()?;
    command::wait_relay(async || Ok(state().await?.1 == "published" && scope.check().is_none()))
        .await?;
    assert!(stack.shutdown().join().await?.is_clean());
    let committed = (
        true,
        "published".into(),
        Some("succeeded".into()),
        initial.3,
        initial.4 + 1,
    );
    assert_eq!(state().await?, committed);
    assert_eq!(
        lane.poll(c.execution(), vec![()], Some(&scope))
            .await
            .map_err(rss_reconcile::Error::new)?
            .advanced,
        0
    );
    assert_eq!(state().await?, committed);
    lane.runtime.close().await;
    Ok(())
}
