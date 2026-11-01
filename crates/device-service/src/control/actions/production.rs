use super::storage as db;
use crate::control::Error;
use crate::control::{Result, checked_input, messaging_domain};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_mdm_policy::schedule::Trigger;
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
    source: db::Source,
    id: Uuid,
    target: &crate::control::Target,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(
        &json!({"version":1,"source":source,"taskId":id,"device":target.device,"registrationId":target.registration,"generation":target.generation}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("action.{id}")))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(now))?,
                messaging_domain(),
                checked_input(MessageRoute::parse("agent.task"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.action-dispatch"))?,
                    ContractVersion::from_static_major(1),
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v1.json"))
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}

pub struct RunInput<'a> {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,

    pub source: db::Source,
    pub target: &'a crate::control::Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub(crate) async fn queue_run_in(
    service: &crate::control::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    input: RunInput<'_>,
) -> Result<()> {
    let RunInput {
        origin,

        source,
        target,
        id,
        occurrence,
        available,
        deadline,
        now,
    } = input;
    crate::control::action_admission::lock_device(tx, &target.device).await?;
    if !service
        .capacity
        .available_in(tx, &target.device, now)
        .await?
    {
        return Err(Error::Conflict.into());
    }
    let evidence: Vec<rss_mdm_inventory_service::objects::DeviceObject> = Vec::new();
    let evidence = checked_input(serde_json::to_value(evidence))?;
    let message = dispatch(tx.tenant_id(), source, id, target, now)?;
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
    let registration = target.registration;
    let target = target.clone();
    let digest = fingerprint.clone();
    let origin = checked_input(serde_json::to_value(origin))?;
    let (kind, version) = source.columns();
    let state = checked_input(serde_json::to_value(RunState::new(deadline, now)?))?;
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_devices.unmanage_runs(tenant_id,id,source_kind,policy_version,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at,source_objects,origin) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(tenant).bind(id).bind(kind).bind(version).bind(target.device).bind(target.registration).bind(target.generation).bind(occurrence).bind(available).bind(deadline).bind(state).bind(digest).bind(now).bind(evidence).bind(origin).execute(c).await?;Ok(())
    })).await?;
    super::run_recovery::wake_run(&service.reconcile_messaging, tx, id).await?;

    let audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::StorageProfile::Mdm,
        tx.tenant_id().to_string(),
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.operation(
        id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("execution-admission");
    source.audit(&audit);
    audit.target(&id.to_string());
    audit.registration(registration);
    let result: Result<()> = async {
        let run = super::storage::read_run(tx, id).await?;
        let fact = Fact::business(&audit, &format!("action:{id}:accept"), 202, "success", None)?
            .with_activity(&super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
            ))?;
        service.audit_store.append_in(tx, &fact).await?;
        crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::CommandRelay)
            .await?;
        crate::control::worker_wake::notify_in(
            tx,
            crate::control::worker_wake::Work::CommandRecovery,
        )
        .await?;
        Ok(())
    }
    .await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}

/// Unknown writes remain fenced across registration changes. Expired or confirmed
/// cancelled read-only native collections can admit a fresh observation.
pub async fn policy_pending_in(
    tx: &mut PgTransaction<'_>,
    owner: Uuid,
    version: Uuid,
    target: &crate::control::Target,
    now: i64,
) -> Result<(bool, Option<i64>)> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let registration = target.registration.to_string();
    let value=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as::<_,(bool,Option<i64>)>("SELECT coalesce(bool_or(state->>'execution'='unknown' OR ((state->>'execution'='running' OR (state->>'execution'='not_started' AND deadline>$4)) AND state->>'cancellation'<>'confirmed')),false),max(created_at) FILTER(WHERE policy_version=$6) FROM mdm_devices.unmanage_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND device=$3 AND (registration=$5::uuid OR state->>'execution'='unknown')")
            .bind(tenant).bind(owner.to_string()).bind(device).bind(now).bind(registration).bind(version).fetch_one(c).await
    })).await?;
    Ok(value)
}
/// Check-in timing is shared by automatic and targeted admission.
pub fn check_in_interval_elapsed(trigger: &Trigger, last: Option<i64>, now: i64) -> bool {
    match trigger {
        Trigger::CheckIn { minimum_seconds } => {
            last.is_none_or(|at| now.saturating_sub(at) >= i64::from(*minimum_seconds))
        }
        _ => true,
    }
}
/// The same frequency coordinate is consumed by check-in and targeted calls.
pub fn policy_occurrence(
    frequency: rss_mdm_policy::Frequency,
    target: &crate::control::Target,
    entry_source: &str,
    entry: i64,
    event: &str,
) -> String {
    match frequency {
        rss_mdm_policy::Frequency::OncePerVersion => format!("version:{}", target.registration),
        rss_mdm_policy::Frequency::OncePerEntry => {
            format!("entry:{entry_source}:{entry}:{}", target.registration)
        }
        rss_mdm_policy::Frequency::EveryTrigger => format!("{event}:{}", target.registration),
    }
}
