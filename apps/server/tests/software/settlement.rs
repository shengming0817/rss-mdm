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
    let mut mismatch = fingerprint.clone();
    mismatch[0] ^= 1;
    runtime.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(
        service
            .accept_action_dispatch(c.execution(), id, mismatch)
            .await,
        Err(owner::Error::RollbackFailed)
    ));
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
