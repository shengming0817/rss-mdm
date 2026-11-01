use crate::tasks::Error;
use crate::tasks::{Result, checked_input};
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
    profile: rss_mdm_install_support::StorageProfile,
    tenant: rss_request_context::TenantId,
    version: Uuid,
    id: Uuid,
    target: &crate::tasks::Target,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(
        &json!({"version":1,"policyVersion":version,"taskId":id,"device":target.device,"registrationId":target.registration,"generation":target.generation}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("credential.{id}")))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(now))?,
                messaging_domain(profile),
                checked_input(MessageRoute::parse("agent.task"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.credential-dispatch"))?,
                    ContractVersion::from_static_major(1),
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(b"mdm.credential-dispatch/v1:policyVersion,taskId,device,registrationId,generation")
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
impl AdmissionTrigger {
    fn explicit(self) -> bool {
        matches!(self, Self::Agent(_) | Self::Scheduled)
    }
}

/// Only the authenticated device can cause its own recurring execution to be admitted.
pub(crate) async fn accept_for_device(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    policy: &crate::tasks::policy::CredentialPolicy,
    target: &crate::tasks::Target,
    trigger: AdmissionTrigger,
    now: i64,
    id: Uuid,
) -> Result<()> {
    if !policy.authorized_in(service, tx, target, now).await? {
        return Ok(());
    }
    let Some(entry) = policy
        .entry_in(&service.source, tx, &target.device, now)
        .await?
    else {
        return Ok(());
    };
    let (version, owner, schedule, lifetime, frequency, entry_source) = (
        policy.id,
        policy.owner,
        &policy.frozen.input.schedule,
        policy.frozen.input.run_lifetime_seconds,
        policy.frequency,
        policy.entry_source(),
    );
    let (pending, last) = policy_pending_in(profile, tx, owner, version, target, now).await?;
    if pending {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let allow_explicit = trigger.explicit();
    let explicit = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_as::<_, (Uuid, i64, i64)>(
                    crate::storage_profile::sql(profile)
                        .tasks_actions_production_accept_for_device_1,
                )
                .bind(tenant)
                .bind(version)
                .bind(device)
                .bind(now)
                .bind(allow_explicit)
                .fetch_optional(c)
                .await
            })
        })
        .await?;

    let (coordinate, event) = if let AdmissionTrigger::Custom { request, at, .. } = trigger {
        (at, format!("event:{request}"))
    } else if let Some((id, at, _)) = explicit {
        (at, format!("explicit:{id}"))
    } else {
        match &schedule.trigger {
            Trigger::Manual => return Ok(()),
            Trigger::CheckIn { .. } => {
                if !check_in_interval_elapsed(&schedule.trigger, last, now) {
                    return Ok(());
                }
                match trigger {
                    AdmissionTrigger::Agent(request) => (now, format!("checkin:{request}")),
                    _ => return Ok(()),
                }
            }
            Trigger::Registration => match trigger {
                AdmissionTrigger::Agent(_) => {
                    (now, format!("registration:{}", target.registration))
                }
                _ => return Ok(()),
            },
            Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. } => {
                let due = schedule.due(-1, now, target.device.as_bytes())?;
                let Some(due) = due else {
                    return Ok(());
                };
                (due.coordinate, format!("timer:{}", due.coordinate))
            }
        }
    };
    let occurrence = if explicit.is_some() {
        event.clone()
    } else {
        policy_occurrence(frequency, target, &entry_source, entry, &event)
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(());
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(lifetime))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX))
        .min(explicit.map_or(i64::MAX, |v| v.2))
        .min(match trigger {
            AdmissionTrigger::Custom { deadline, .. } => deadline,
            _ => i64::MAX,
        });
    if deadline <= available {
        return Ok(());
    }
    if !occurrence_available_in(profile, service, tx, version, target, &occurrence, now).await? {
        return Ok(());
    }
    queue_run_in(
        profile,
        service,
        tx,
        RunInput {
            origin: match trigger {
                AdmissionTrigger::Custom { origin, .. } => origin,
                _ => rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
            },
            version,
            target,
            id,
            occurrence,
            available,
            deadline,
            now,
        },
    )
    .await?;

    Ok(())
}
pub struct RunInput<'a> {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,

    pub version: Uuid,
    pub target: &'a crate::tasks::Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub(crate) async fn queue_run_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    input: RunInput<'_>,
) -> Result<()> {
    let RunInput {
        origin,

        version,
        target,
        id,
        occurrence,
        available,
        deadline,
        now,
    } = input;
    super::agent::lock_device(profile, tx, &target.device).await?;
    if !service
        .capacity
        .available_in(tx, &target.device, now)
        .await?
    {
        return Err(Error::Conflict.into());
    }
    let policy = crate::tasks::policy::read_in(&service.policy_reader, tx, version).await?;
    let reader = service.source.clone();
    let tenant = tx.tenant_id();
    let scope = policy.policy.definition.scope;
    let device = target.device.clone();
    let evidence = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(reader
                    .evidence_on(c, tenant, scope, rss_mdm_inventory::Channel::Agent, &device)
                    .await)
            })
        })
        .await??;
    let evidence = checked_input(serde_json::to_value(evidence))?;
    let message = dispatch(profile, tx.tenant_id(), version, id, target, now)?;
    let fingerprint = message.fingerprint().as_bytes().to_vec();
    let writer = rss_transactional_messaging_postgres::PgOutboxWriter::new(
        service.runtime.clone(),
        messaging_domain(profile),
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
    let state = checked_input(serde_json::to_value(RunState::new(deadline, now)?))?;
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                crate::storage_profile::sql(profile).tasks_actions_production_queue_run_in_1,
            )
            .bind(tenant)
            .bind(id)
            .bind(version)
            .bind(target.device)
            .bind(target.registration)
            .bind(target.generation)
            .bind(occurrence)
            .bind(available)
            .bind(deadline)
            .bind(state)
            .bind(digest)
            .bind(now)
            .bind(evidence)
            .bind(origin)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    crate::tasks::wake::run_in(profile, &service.reconcile_messaging, tx, id).await?;

    let audit = rss_mdm_audit_integration::RequestAudit::new(
        profile,
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
    audit.plan(version);
    audit.target(&id.to_string());
    audit.registration(registration);
    let result: Result<()> = async {
        let run = super::storage::read_run(profile, tx, id).await?;
        let fact = Fact::business(&audit, &format!("action:{id}:accept"), 202, "success", None)?
            .with_activity(&super::activity::run(
                &run,
                rss_mdm_audit_integration::activity::ActivityPhase::Accepted,
            ))?;
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

/// Unknown writes remain fenced across registration changes. Expired or confirmed
/// cancelled read-only native collections can admit a fresh observation.
pub async fn policy_pending_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    owner: Uuid,
    version: Uuid,
    target: &crate::tasks::Target,
    now: i64,
) -> Result<(bool, Option<i64>)> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let registration = target.registration.to_string();
    let value = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_as::<_, (bool, Option<i64>)>(
                    crate::storage_profile::sql(profile)
                        .tasks_actions_production_policy_pending_in_1,
                )
                .bind(tenant)
                .bind(owner.to_string())
                .bind(device)
                .bind(now)
                .bind(registration)
                .bind(version)
                .fetch_one(c)
                .await
            })
        })
        .await?;
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
    target: &crate::tasks::Target,
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
pub(crate) async fn occurrence_available_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &crate::tasks::Target,
    occurrence: &str,
    now: i64,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let key = occurrence.to_owned();
    let exists: bool = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    crate::storage_profile::sql(profile)
                        .tasks_actions_production_occurrence_available_in_1,
                )
                .bind(tenant)
                .bind(version)
                .bind(device)
                .bind(key)
                .fetch_one(c)
                .await
            })
        })
        .await?;
    Ok(!exists
        && service
            .capacity
            .available_in(tx, &target.device, now)
            .await?)
}

pub fn messaging_domain(
    profile: rss_mdm_install_support::StorageProfile,
) -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(match profile {
        rss_mdm_install_support::StorageProfile::Mdm => "mdm.recovery.credentials.v1",
        rss_mdm_install_support::StorageProfile::Da => "da.recovery.credentials.v1",
    })
    .expect("fixed credential domain")
}
