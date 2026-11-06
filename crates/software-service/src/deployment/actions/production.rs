use super::storage as db;
use crate::deployment::Error;
use crate::deployment::{Result, checked_input, messaging_domain};
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
    source: db::Source,
    id: Uuid,
    target: &crate::deployment::Target,
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

/// Admission cause is fixed before the asynchronous worker evaluates current authority.
#[derive(Clone, Copy)]
pub enum AdmissionTrigger {
    Agent(Uuid),
    Scheduled,
    Custom {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        request: Uuid,
        at: i64,
        deadline: i64,
    },
}
impl AdmissionTrigger {}

/// Only the authenticated device can cause its own recurring execution to be admitted.
pub struct RunInput<'a> {
    pub request: Option<&'a rss_mdm_audit_integration::RequestAudit>,
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub invocation: Option<crate::deployment::self_service::Invocation>,
    pub source: db::Source,
    pub target: &'a crate::deployment::Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub(crate) async fn queue_run_in(
    service: &crate::deployment::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    input: RunInput<'_>,
) -> Result<()> {
    let RunInput {
        request,
        origin,
        invocation,
        source,
        target,
        id,
        occurrence,
        available,
        deadline,
        now,
    } = input;
    crate::deployment::action_admission::lock_device(tx, &target.device).await?;
    if !service
        .capacity
        .available_in(tx, &target.device, now)
        .await?
    {
        return Err(Error::Conflict.into());
    }
    let (_, version) = source.columns();
    let (policy, _) =
        crate::deployment::sources::storage::version_in(&service.policy_reader, tx, version)
            .await?;
    let retirement = match source {
        db::Source::RetirementSoftware { retirement, .. } => Some(retirement),
        _ => None,
    };
    let reader = service.source.clone();
    let tenant = tx.tenant_id();
    let scope = policy.definition.scope;
    let device = target.device.clone();
    // Device Access carries its own exact binding and rechecks its current scope at Start.
    // Unlink cleanup must also be dispatchable after that scope has excluded the device.
    let evidence = if let Some(retirement) = retirement {
        vec![
            crate::deployment::retirement::context_in(service.lifecycle.clone(), tx, retirement)
                .await?
                .target,
        ]
    } else {
        let channel =
            crate::deployment::sources::candidates::action_channel(&policy.definition.action)?;
        tx.with_connection(move |c| {
            Box::pin(
                async move { Ok(reader.evidence_on(c, tenant, scope, channel, &device).await) },
            )
        })
        .await??
    };
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
    let invocation = invocation
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Malformed)?;
    let (kind, version) = source.columns();
    let state = checked_input(serde_json::to_value(RunState::new(deadline, now)?))?;
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_software_deployment.action_runs(tenant_id,id,source_kind,policy_version,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at,source_objects,origin,invocation,retirement) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)")
            .bind(tenant).bind(id).bind(kind).bind(version).bind(target.device).bind(target.registration).bind(target.generation).bind(occurrence).bind(available).bind(deadline).bind(state).bind(digest).bind(now).bind(evidence).bind(origin).bind(invocation).bind(retirement).execute(c).await?;Ok(())
    })).await?;
    super::run_recovery::wake_run(&service.reconcile_messaging, tx, id).await?;

    let audit = request
        .map(|a| a.fact_copy("command_accept"))
        .unwrap_or_else(|| {
            rss_mdm_audit_integration::RequestAudit::new(
                rss_mdm_audit_integration::Origin::Background,
                rss_mdm_audit_integration::StorageProfile::Mdm,
                tx.tenant_id().to_string(),
                "command_accept",
                rss_mdm_audit_integration::AuditIntent::Management,
            )
        });
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
        id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    if request.is_none() {
        audit.identify_service("execution-admission");
    }
    source.audit(&audit);
    audit.target(&id.to_string());
    audit.registration(registration);
    let result: Result<()> = async {
        let run = super::storage::read_run(tx, id).await?;
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareAction,
            &format!("action:{id}:accept"),
            202,
            "success",
            None,
        )?
        .with_activity(&super::activity::run(
            &run,
            rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
        ))?;
        service.audit_store.append_in(tx, &fact).await?;
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRelay,
        )
        .await?;
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRecovery,
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

pub(crate) async fn occurrence_available_in(
    service: &crate::deployment::transactions::Transactions,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &crate::deployment::Target,
    occurrence: &str,
    now: i64,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let key = occurrence.to_owned();
    let exists: bool = tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4)").bind(tenant).bind(version).bind(device).bind(key).fetch_one(c).await
    })).await?;
    Ok(!exists
        && service
            .capacity
            .available_in(tx, &target.device, now)
            .await?)
}
