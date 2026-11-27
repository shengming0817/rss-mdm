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
    anyhow::ensure!(
        rows == (expected, expected, expected, expected),
        "persisted command counts {rows:?}, expected {expected} each"
    );
    anyhow::ensure!(
        c.audit_count("mdm.business", &id.to_string()).await? == expected,
        "unexpected durable audit count"
    );
    Ok(())
}
async fn check_create(
    c: &Context,
    fixture: &Fixture,
    proof: &AuthorizedPrincipal,
    device: &DeviceId,
    input: &Input,
) -> Result<()> {
    let id = input.operation_id;
    let key = format!("command:{}:{id}:accept", proof.principal_id());
    let runtime = &fixture.resources.storage.runtime;
    let submit = async || -> Result<(std::result::Result<AcceptedReceipt, Error>, WriteOutcome)> {
        let audit = c.request(proof)?;
        audit.owned_operation(
            OperationOwner::DeviceControl,
            id,
            "command_accept",
            AuditIntent::Management,
        );
        audit.target_device(device);
        let result = fixture
            .service
            .create_control(proof, device, input, &audit)
            .await;
        audit.finalize(result.as_ref().err().map(|_| FailureReason::Transaction));
        Ok((result, audit.snapshot().write_outcome))
    };
    command::check_uncommitted_command(c, runtime, &key, async |expected| {
        let (result, outcome) = submit().await?;
        anyhow::ensure!(
            outcome == expected,
            "expected {expected:?}, found {outcome:?}"
        );
        anyhow::ensure!(matches!(
            (result, expected),
            (Err(Error::RollbackFailed), WriteOutcome::RollbackFailed)
                | (Err(Error::CommitUnknown), WriteOutcome::Unknown)
        ));
        evidence(c, id, 0).await
    })
    .await?;

    runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    let (lost, outcome) = submit().await?;
    assert!(matches!(lost, Err(Error::CommitUnknown)));
    assert_eq!(outcome, WriteOutcome::Unknown);
    evidence(c, id, 1).await?;
    let (replay, outcome) = submit().await?;
    let receipt = replay?;
    assert_eq!(
        (
            receipt.operation_id,
            receipt.command_id,
            receipt.revision,
            receipt.accepted
        ),
        (id, id, 1, true)
    );
    assert_eq!(outcome, WriteOutcome::Committed);
    evidence(c, id, 1).await
}

#[tokio::test]
#[ignore = "T2: device command, receipt, outbox and audit settle on the original transaction"]
async fn device_creation_settles_with_its_audit_and_receipt() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_device_service::control::device_control::Action;
    let c = Context::open("device_command_settlement", &[]).await?;
    let device = windows_control_device(&c).await?;
    let account = c.account(&[Permission::DeviceWipe]).await?;
    let proof = c.authenticate(&account).await?;
    let fixture = Fixture::open(&c).await?;
    let input = Input {
        operation_id: Uuid::new_v4(),
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        action: Action::Wipe { confirmed: true },
    };
    let checked = check_create(&c, &fixture, &proof, &device, &input).await;
    fixture.close().await?;
    c.close().await;
    checked
}
