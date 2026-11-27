//! A lost acknowledgement is resolved against the original command and request receipt.
use super::*;
use rss_mdm_audit_integration::{
    AuditIntent, FailureReason, RequestAudit, WriteOutcome, operation::OperationOwner,
};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_service::control::{Error, device_control::Input};
use rss_transactional_messaging_postgres::PgTransactionFault;

pub(super) async fn check_create(
    c: &Context,
    fixture: &Fixture,
    proof: &AuthorizedPrincipal,
    device: &rss_mdm_agent_wire::DeviceId,
    input: &Input,
) -> Result<()> {
    let id = input.operation_id;
    let request = || -> Result<_> {
        let audit = c.request(proof)?;
        audit.owned_operation(
            OperationOwner::DeviceControl,
            id,
            "command_accept",
            AuditIntent::Management,
        );
        audit.target_device(device);
        Ok(audit)
    };
    let create = async |audit: &RequestAudit| {
        let result = fixture
            .service
            .create_control(proof, device, input, audit)
            .await;
        audit.finalize(result.as_ref().err().map(|_| FailureReason::Transaction));
        result
    };
    let evidence = || {
        sqlx::query_as::<_, (i64, i64, i64, i64)>(
            "SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2),
                    (SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid AND id=$2),
                    (SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2::uuid::text),
                    (SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id='dispatch.'||$2::uuid::text)",
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .fetch_one(&c.operator)
    };
    // The producer checks this generation after queuing the command on the same transaction.
    let recovery_epoch = |epoch: i64| {
        sqlx::query("UPDATE mdm_devices.control_recovery SET expected_epoch=$3 WHERE tenant_id=$1::uuid AND device=$2")
            .bind(c.tenant.to_string()).bind(device.into_uuid()).bind(epoch).execute(&c.operator)
    };
    assert_eq!(recovery_epoch(2).await?.rows_affected(), 1);
    let runtime = &fixture.resources.storage.runtime;
    let audit = request()?;
    runtime.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    assert!(matches!(create(&audit).await, Err(Error::RollbackFailed)));
    assert_eq!(audit.snapshot().write_outcome, WriteOutcome::RollbackFailed);
    assert_eq!(evidence().await?, (0, 0, 0, 0));
    assert_eq!(c.audit_count("mdm.business", &id.to_string()).await?, 0);

    assert_eq!(recovery_epoch(1).await?.rows_affected(), 1);
    let audit = request()?;
    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    assert!(matches!(create(&audit).await, Err(Error::CommitUnknown)));
    assert_eq!(audit.snapshot().write_outcome, WriteOutcome::Unknown);
    assert_eq!(evidence().await?, (1, 1, 1, 1));
    assert_eq!(c.audit_count("mdm.business", &id.to_string()).await?, 1);

    let replay = request()?;
    let receipt = create(&replay).await?;
    assert_eq!(
        (
            receipt.operation_id,
            receipt.command_id,
            receipt.revision,
            receipt.accepted
        ),
        (id, id, 1, true)
    );
    assert_eq!(replay.snapshot().write_outcome, WriteOutcome::Committed);
    assert_eq!(evidence().await?, (1, 1, 1, 1));
    assert_eq!(c.audit_count("mdm.business", &id.to_string()).await?, 1);
    Ok(())
}
