use super::{Error, stored};
use super::{Result, checked_input};
use super::{Target, storage as db};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;

use rss_mdm_task_state::RunState;
use rss_transactional_messaging::{
    message::*,
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn dispatch(
    tenant: rss_request_context::TenantId,
    version: Uuid,
    id: Uuid,
    target: &Target,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(
        &json!({"version":1,"policyVersion":version,"taskId":id,"device":target.device}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("access.{id}")))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(now))?,
                messaging_domain(),
                checked_input(MessageRoute::parse("agent.task"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.access-dispatch"))?,
                    ContractVersion::from_static_major(1),
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(b"mdm.access-dispatch/v1:policyVersion,taskId,device")
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}

pub fn messaging_domain() -> MessagingDomain {
    MessagingDomain::parse("mdm.registration.access.v1").expect("fixed access domain")
}
pub(crate) async fn occurrence_available_in(
    service: &super::Transactions,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &Target,
    occurrence: &str,
    now: i64,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device;
    let occurrence = occurrence.to_owned();
    let exists=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND occurrence=$4)").bind(tenant).bind(version).bind(device.into_uuid()).bind(occurrence).fetch_one(c).await})).await?;
    Ok(!exists
        && service
            .capacity
            .available_in(tx, &target.device, now)
            .await?)
}
#[allow(
    clippy::too_many_arguments,
    reason = "one immutable binding and its original delivery coordinates"
)]
pub(crate) async fn queue_run_in(
    service: &super::Transactions,
    tx: &mut PgTransaction<'_>,
    mut binding: &crate::device_access::Binding,
    id: Uuid,
    occurrence: String,
    now: i64,
    deadline: i64,
    origin: rss_mdm_audit_integration::activity::ActivityOrigin,
) -> Result<()> {
    service.validate_in(tx)?;
    let agent = tx
        .with_connection_context(&mut binding, |b, c| {
            Box::pin(async move { Ok(crate::delivery::for_binding_on(c, b).await) })
        })
        .await??
        .ok_or(Error::Forbidden)?;
    let target = Target {
        device: agent.device,
    };
    let message = dispatch(tx.tenant_id(), binding.policy_version, id, &target, now)?;
    let fingerprint = message.fingerprint().as_bytes().to_vec();
    let writer = rss_transactional_messaging_postgres::PgOutboxWriter::new(
        service.runtime.clone(),
        messaging_domain(),
    );
    if writer
        .append(tx, message)
        .await
        .map_err(rss_transactional_messaging_postgres::PgError::from)?
        != AppendOutcome::Inserted
    {
        return Err(Error::Conflict.into());
    }
    let tenant = tx.tenant_id().to_string();
    let version = binding.policy_version;
    let document = stored(serde_json::to_value(binding))?;
    let state = stored(serde_json::to_value(RunState::new(deadline, now)?))?;
    let origin = stored(serde_json::to_value(origin))?;
    tx.with_connection(move|c|Box::pin(async move{
        sqlx::query("INSERT INTO rss_da.access_runs (tenant_id, id, policy_version, device, occurrence, available_at, deadline, state, dispatch_fingerprint, created_at, origin, access_binding) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8, $9, $6, $10, $11)")
            .bind(tenant).bind(id).bind(version).bind(target.device.into_uuid()).bind(occurrence).bind(now).bind(deadline).bind(state).bind(fingerprint).bind(origin).bind(document).execute(c).await?;Ok(())
    })).await?;
    super::wake::run_in(&service.reconcile_messaging, tx, id).await?;
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Da,
        tx.tenant_id().to_string(),
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceAccessTask,
        id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("access-admission");
    audit.plan(version);
    audit.target(&id.to_string());
    audit.target_device(&binding.device);
    let run = db::read_run(tx, id).await?;
    let fact = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceAccessTask,
        &format!("access:{id}:accept"),
        202,
        "success",
        None,
    )?
    .with_activity(&super::activity::run(
        &run,
        rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
    ))?;
    let result = service.audit_store.append_in(tx, &fact).await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result?;
    Ok(())
}
