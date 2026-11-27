//! A lost acknowledgement is resolved against the original command and request receipt.
use super::*;
use rss_mdm_agent_wire::DeviceId;
use rss_mdm_audit_integration::{
    AuditIntent, FailureReason, WriteOutcome, operation::OperationOwner,
};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_service::control::{AcceptedReceipt, Error, device_control::Input};
use rss_transactional_messaging_postgres::PgTransactionFault;

async fn evidence(c: &Context, id: Uuid, expected: i64) -> Result<()> {
    let rows: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2),
                (SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid AND id=$2),
                (SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2::uuid::text),
                (SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id='dispatch.'||$2::uuid::text)",
    ).bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(rows, (expected, expected, expected, expected));
    assert_eq!(
        c.audit_count("mdm.business", &id.to_string()).await?,
        expected
    );
    Ok(())
}
fn check_outcome(
    result: std::result::Result<AcceptedReceipt, Error>,
    outcome: WriteOutcome,
    expected: WriteOutcome,
    id: Uuid,
) -> Result<()> {
    assert_eq!(outcome, expected);
    match expected {
        WriteOutcome::RollbackFailed => assert!(matches!(result, Err(Error::RollbackFailed))),
        WriteOutcome::Unknown => assert!(matches!(result, Err(Error::CommitUnknown))),
        WriteOutcome::Committed => {
            let receipt = result?;
            assert_eq!(
                (
                    receipt.operation_id,
                    receipt.command_id,
                    receipt.revision,
                    receipt.accepted
                ),
                (id, id, 1, true)
            );
        }
        other => anyhow::bail!("unexpected settlement case {other:?}"),
    }
    Ok(())
}
pub(super) async fn check_create(
    c: &Context,
    fixture: &Fixture,
    proof: &AuthorizedPrincipal,
    device: &DeviceId,
    input: &Input,
) -> Result<()> {
    let id = input.operation_id;
    // The producer checks this generation after enqueuing on the original transaction.
    for (epoch, fault, expected, rows) in [
        (
            2_i64,
            Some(PgTransactionFault::RollbackFailedAfterAck),
            WriteOutcome::RollbackFailed,
            0,
        ),
        (
            1,
            Some(PgTransactionFault::CommitUnknownAfterAck),
            WriteOutcome::Unknown,
            1,
        ),
        (1, None, WriteOutcome::Committed, 1),
    ] {
        let audit = c.request(proof)?;
        audit.owned_operation(
            OperationOwner::DeviceControl,
            id,
            "command_accept",
            AuditIntent::Management,
        );
        audit.target_device(device);
        if let Some(fault) = fault {
            let updated = sqlx::query("UPDATE mdm_devices.control_recovery SET expected_epoch=$3 WHERE tenant_id=$1::uuid AND device=$2")
            .bind(c.tenant.to_string()).bind(device.into_uuid()).bind(epoch)
            .execute(&c.operator).await?;
            assert_eq!(updated.rows_affected(), 1);
            fixture
                .resources
                .storage
                .runtime
                .inject_next_transaction_fault(fault);
        }
        let result = fixture
            .service
            .create_control(proof, device, input, &audit)
            .await;
        audit.finalize(result.as_ref().err().map(|_| FailureReason::Transaction));
        check_outcome(result, audit.snapshot().write_outcome, expected, id)?;
        evidence(c, id, rows).await?;
    }
    Ok(())
}
