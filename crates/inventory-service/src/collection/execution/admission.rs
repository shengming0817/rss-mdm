//! Collection scheduling and admission on the initiating owner's connection.
use super::{model::Target, policy::CollectionPolicy, service::Transactions, storage};
use crate::{
    Error,
    transaction::{Result, checked_input},
};
use rss_mdm_audit_integration::{Fact, RequestAudit, activity::ActivityOrigin};
use rss_mdm_policy::{Frequency, schedule::Trigger};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum TriggerInput {
    Agent(Uuid),
    CheckIn {
        event: Uuid,
        at: i64,
    },
    Registration {
        at: i64,
    },
    Scheduled,
    Custom {
        origin: ActivityOrigin,
        request: Uuid,
        at: i64,
        deadline: i64,
    },
}
pub async fn accept_for_device(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    policy: &CollectionPolicy,
    target: &Target,
    trigger: TriggerInput,
    now: i64,
    id: Uuid,
) -> Result<()> {
    service.validate_in(tx)?;
    storage::lock_device(tx, &target.device).await?;
    if !policy.run_admission_in(service, tx, target).await? {
        return Ok(());
    }
    let native = policy.frozen.channel() == rss_mdm_inventory::Channel::Mdm;
    if !matches!(trigger, TriggerInput::Custom { .. })
        && native == matches!(trigger, TriggerInput::Agent(_))
    {
        return Err(Error::Malformed.into());
    }
    let Some(entry) = policy.entry_in(service, tx, &target.device, now).await? else {
        return Ok(());
    };
    let (pending, last) = storage::pending_in(tx, policy.owner, policy.id, target, now).await?;
    if pending && !matches!(trigger, TriggerInput::Custom { .. }) {
        return Ok(());
    }
    let tenant = tx.tenant_id();
    let explicit_allowed = matches!(trigger, TriggerInput::Agent(_) | TriggerInput::Scheduled);
    let explicit = tx
        .with_connection_context(&mut (policy, target), |(policy, target), c| {
            Box::pin(async move {
                Ok(explicit_on(c, tenant, policy.id, &target.device, now, explicit_allowed).await)
            })
        })
        .await??;
    let started = storage::last_started_in(tx, policy.id, target).await?;
    let Some(candidate) = candidate(
        policy,
        target,
        Some(trigger),
        now,
        last,
        started,
        explicit,
        entry,
    )?
    else {
        return Ok(());
    };
    let Candidate {
        occurrence,
        available,
        deadline,
        coordinate: _coordinate,
    } = candidate;
    if deadline <= available
        || !occurrence_available_in(service, tx, policy.id, target, &occurrence, now).await?
    {
        return Ok(());
    }
    queue_run_in(
        service,
        tx,
        policy,
        RunInput {
            origin: match trigger {
                TriggerInput::Custom { origin, .. } => origin,
                _ => ActivityOrigin::Policy,
            },
            triggered_at: native.then_some(_coordinate),
            target,
            id,
            occurrence,
            available,
            deadline,
            now,
        },
    )
    .await
}
pub(crate) struct Candidate {
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub coordinate: i64,
}
/// Pure production trigger/slot selection, also consumed by read-only explanations.
#[expect(
    clippy::too_many_arguments,
    reason = "the owner's existing trigger facts stay explicit"
)]
pub(crate) fn candidate(
    policy: &CollectionPolicy,
    target: &Target,
    trigger: Option<TriggerInput>,
    now: i64,
    last: Option<i64>,
    started: Option<i64>,
    explicit: Option<(Uuid, i64, i64)>,
    entry: i64,
) -> Result<Option<Candidate>> {
    let schedule = &policy.frozen.input().schedule;
    let (coordinate, event) = if let Some(TriggerInput::Custom { request, at, .. }) = trigger {
        (at, format!("event:{request}"))
    } else if let Some((request, at, _)) = explicit {
        (at, format!("explicit:{request}"))
    } else {
        match (&schedule.trigger, trigger) {
            (Trigger::Manual, _) => return Ok(None),
            (Trigger::CheckIn { .. }, Some(TriggerInput::Agent(request))) => {
                if !check_in_interval_elapsed(&schedule.trigger, last, now) {
                    return Ok(None);
                }
                (now, format!("checkin:{request}"))
            }
            (Trigger::CheckIn { .. }, Some(TriggerInput::CheckIn { event, at })) => {
                if !check_in_interval_elapsed(&schedule.trigger, last, at) {
                    return Ok(None);
                }
                (at, format!("checkin:{event}"))
            }
            (Trigger::Registration, Some(TriggerInput::Agent(_)) | None) => {
                (now, format!("device:{}", target.device))
            }
            (Trigger::Registration, Some(TriggerInput::Registration { at })) => {
                (at, format!("device:{}", target.device))
            }
            (Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. }, _) => {
                let Some(due) = schedule.collection_due(started, now, target.device.as_bytes())?
                else {
                    return Ok(None);
                };
                (due.coordinate, format!("timer:{}", due.coordinate))
            }
            _ => return Ok(None),
        }
    };
    let occurrence = if explicit.is_some() {
        event.clone()
    } else {
        policy_occurrence(
            policy.frozen.frequency(),
            target,
            &policy.entry_source(),
            entry,
            &event,
        )
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(None);
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(policy.frozen.input().run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX))
        .min(explicit.map_or(i64::MAX, |v| v.2))
        .min(match trigger {
            Some(TriggerInput::Custom { deadline, .. }) => deadline,
            _ => i64::MAX,
        });
    Ok((deadline > available).then_some(Candidate {
        occurrence,
        available,
        deadline,
        coordinate,
    }))
}
pub(crate) async fn explicit_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    version: Uuid,
    device: &str,
    now: i64,
    allowed: bool,
) -> Result<Option<(Uuid, i64, i64)>> {
    Ok(sqlx::query_as("SELECT t.id,t.created_at,t.deadline FROM mdm_policy.triggers t WHERE t.tenant_id=$1::uuid AND t.version=$2 AND t.deadline>$4 AND $5 AND NOT EXISTS(SELECT 1 FROM mdm_inventory.collection_tasks r WHERE r.tenant_id=t.tenant_id AND r.policy_version=t.version AND r.device=$3 AND r.occurrence='explicit:'||t.id::text) ORDER BY t.created_at,t.id LIMIT 1")
        .bind(tenant.to_string()).bind(version).bind(&device).bind(now).bind(allowed).fetch_optional(c).await?)
}
/// Exact production deduplication identity; absence is never inferred from version history.
pub(crate) async fn occurrence_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    version: Uuid,
    device: &str,
    occurrence: &str,
) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar("SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND occurrence=$4")
        .bind(tenant.to_string()).bind(version).bind(&device).bind(occurrence).fetch_optional(c).await?)
}
pub struct RunInput<'a> {
    pub origin: ActivityOrigin,
    pub triggered_at: Option<i64>,
    pub target: &'a Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub async fn queue_run_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    policy: &CollectionPolicy,
    input: RunInput<'_>,
) -> Result<()> {
    use rss_transactional_messaging::outbox::{AppendOutcome, OutboxWriter};
    service.validate_in(tx)?;
    storage::lock_device(tx, &input.target.device).await?;
    if !occurrence_available_in(
        service,
        tx,
        policy.id,
        input.target,
        &input.occurrence,
        input.now,
    )
    .await?
    {
        return Err(Error::Conflict.into());
    }
    let source = service.source.clone();
    let tenant = tx.tenant_id();
    let device = input.target.device.clone();
    let scope = policy.policy.definition.scope;
    let channel = policy.frozen.channel();
    let evidence = tx
        .with_connection(move |c| {
            Box::pin(
                async move { Ok(source.evidence_on(c, tenant, scope, channel, &device).await) },
            )
        })
        .await??;
    let message = dispatch(tx.tenant_id(), policy.id, &input)?;
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
    let version = policy.id;
    let target = input.target.clone();
    let origin = checked_input(serde_json::to_value(input.origin))?;
    let evidence = checked_input(serde_json::to_value(evidence))?;
    let state = if channel == rss_mdm_inventory::Channel::Agent {
        Some(checked_input(serde_json::to_value(
            rss_mdm_task_state::RunState::new(input.deadline, input.now)?,
        ))?)
    } else {
        None
    };
    let delivery = (channel == rss_mdm_inventory::Channel::Mdm).then_some("queued");
    let channel = if channel == rss_mdm_inventory::Channel::Agent {
        "agent"
    } else {
        "mdm"
    };
    let id = input.id;
    let now = input.now;
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_inventory.collection_tasks (tenant_id, id, policy_version, channel, device, occurrence, available_at, deadline, agent_state, dispatch_fingerprint, created_at, source_objects, origin, native_delivery, triggered_at) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)")
            .bind(tenant).bind(id).bind(version).bind(channel).bind(target.device).bind(input.occurrence).bind(input.available).bind(input.deadline)
            .bind(state).bind(fingerprint).bind(now).bind(evidence).bind(origin).bind(delivery).bind(input.triggered_at).execute(c).await?;
        Ok(())
    })).await?;
    super::wake::run_in(&service.reconcile_messaging, tx, id).await?;
    tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'command_relay')").execute(c).await?;Ok(())})).await?;
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        tx.tenant_id().to_string(),
        "collection_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::CollectionExecution,
        id,
        "collection_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("collection-admission");
    audit.plan(version);
    audit.target(&id.to_string());
    audit.target_device(&input.target.device);
    let result: Result<()> = async {
        let activity = super::activity::accepted(id, version, input.target, input.origin);
        let fact = Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::CollectionExecution,
            &format!("collection:{id}:accept"),
            202,
            "success",
            None,
        )?
        .with_activity(&activity)?;
        service.audit_store.append_in(tx, &fact).await?;
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
pub fn check_in_interval_elapsed(trigger: &Trigger, last: Option<i64>, now: i64) -> bool {
    match trigger {
        Trigger::CheckIn { minimum_seconds } => {
            last.is_none_or(|at| now.saturating_sub(at) >= i64::from(*minimum_seconds))
        }
        _ => true,
    }
}
pub fn policy_occurrence(
    frequency: Frequency,
    target: &Target,
    source: &str,
    entry: i64,
    event: &str,
) -> String {
    match frequency {
        Frequency::OncePerVersion => format!("version:{}", target.device),
        Frequency::OncePerEntry => format!("entry:{source}:{entry}:{}", target.device),
        Frequency::EveryTrigger => format!("{event}:{}", target.device),
    }
}
pub async fn occurrence_available_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &Target,
    occurrence: &str,
    now: i64,
) -> Result<bool> {
    let tenant = tx.tenant_id();
    let exists = tx
        .with_connection_context(&mut (target, occurrence), |(target, key), c| {
            Box::pin(async move {
                Ok(occurrence_on(c, tenant, version, &target.device, key)
                    .await
                    .map(|id| id.is_some()))
            })
        })
        .await??;
    Ok(!exists
        && service
            .capacity
            .available_in(tx, &target.device, now)
            .await?)
}
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse("mdm.collection.v1")
        .expect("fixed Collection domain")
}
fn dispatch(
    tenant: rss_request_context::TenantId,
    version: Uuid,
    input: &RunInput<'_>,
) -> Result<rss_transactional_messaging::outbox::PendingMessage<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_transactional_messaging::{message::*, outbox::PendingMessage};
    use sha2::{Digest, Sha256};
    let payload = checked_input(serde_json::to_vec(
        &serde_json::json!({"version":1,"policyVersion":version,"taskId":input.id,"device":input.target.device}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("collection.{}", input.id)))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(input.now))?,
                messaging_domain(),
                checked_input(MessageRoute::parse("collection.task"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.collection-dispatch"))?,
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
