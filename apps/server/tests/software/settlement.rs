//! The Software owner acknowledges dispatch and appends its audit fact in the original transaction.
use super::*;
use rss_transactional_messaging_postgres::PgTransactionFault;

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
    let runtime = &a.resources.storage.runtime;
    let key = format!("action:{id}:dispatch");
    command::check_uncommitted_command(c, runtime, &key, async |expected| {
        use rss_mdm_audit_integration::WriteOutcome;
        let rejected = a
            .software
            .service
            .accept_action_dispatch(c.execution(), id, fingerprint.clone())
            .await;
        anyhow::ensure!(matches!(
            (rejected, expected),
            (
                Err(owner::Error::RollbackFailed),
                WriteOutcome::RollbackFailed
            ) | (Err(owner::Error::CommitUnknown), WriteOutcome::Unknown)
        ));
        anyhow::ensure!(
            dispatch_state(c, id).await? == initial,
            "software dispatch or audit survived rollback"
        );
        Ok(())
    })
    .await?;

    let service = &a.software.service;
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
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
