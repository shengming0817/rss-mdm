//! Enrollment scheduling and admission on the initiating owner's connection.
use crate::enrollment::tasks::{
    Error, Result, Target, Transactions, checked_input, policy::EnrollmentPolicy, runs::Invocation,
    storage,
};
use rss_mdm_audit_integration::{
    Fact, RequestAudit,
    activity::{ActivityOrigin, ActivityPhase},
};
use rss_mdm_policy::{Frequency, schedule::Trigger};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum TriggerInput {
    Agent(Uuid),
    Custom {
        origin: ActivityOrigin,
        request: Uuid,
        at: i64,
        deadline: i64,
    },
}
pub async fn accept_for_device(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    policy: &EnrollmentPolicy,
    target: &Target,
    trigger: TriggerInput,
    now: i64,
    id: Uuid,
) -> Result<()> {
    service.validate_in(tx)?;
    storage::lock_device(profile, tx, &target.device).await?;
    if !crate::enrollment::tasks::eligibility::require_in(
        profile,
        service,
        tx,
        target,
        &policy.frozen,
    )
    .await?
    {
        return Ok(());
    }
    let Some(entry) = policy.entry_in(service, tx, &target.device, now).await? else {
        return Ok(());
    };
    let (pending, last) =
        storage::pending_in(profile, tx, policy.owner, policy.id, target, now).await?;
    if pending {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let version = policy.id;
    let device = target.device.clone();
    let explicit_allowed = matches!(trigger, TriggerInput::Agent(_));
    let explicit = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_as::<_, (Uuid, i64, i64)>(
                    crate::storage_profile::sql(profile)
                        .enrollment_tasks_admission_accept_for_device_1,
                )
                .bind(tenant)
                .bind(version)
                .bind(device)
                .bind(now)
                .bind(explicit_allowed)
                .fetch_optional(c)
                .await
            })
        })
        .await?;
    if explicit.is_none() {
        let tenant = tx.tenant_id().to_string();
        let registration = target.registration;
        let previous = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, bool>(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_admission_accept_for_device_2,
                    )
                    .bind(tenant)
                    .bind(registration)
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        if previous {
            return Ok(());
        }
    }
    let schedule = &policy.frozen.schedule;
    let (coordinate, event) = if let TriggerInput::Custom { request, at, .. } = trigger {
        (at, format!("event:{request}"))
    } else if let Some((request, at, _)) = explicit {
        (at, format!("explicit:{request}"))
    } else {
        match (&schedule.trigger, trigger) {
            (Trigger::Manual, _) => return Ok(()),
            (Trigger::CheckIn { .. }, TriggerInput::Agent(request)) => {
                if !check_in_interval_elapsed(&schedule.trigger, last, now) {
                    return Ok(());
                }
                (now, format!("checkin:{request}"))
            }
            (Trigger::Registration, _) => (now, format!("registration:{}", target.registration)),
            (Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. }, _) => {
                let Some(due) = schedule.due(-1, now, target.device.as_bytes())? else {
                    return Ok(());
                };
                (due.coordinate, format!("timer:{}", due.coordinate))
            }
            _ => return Ok(()),
        }
    };
    let occurrence = if explicit.is_some() {
        event.clone()
    } else {
        policy_occurrence(
            policy.frequency,
            target,
            &policy.entry_source(),
            entry,
            &event,
        )
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(());
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(policy.frozen.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX))
        .min(explicit.map_or(i64::MAX, |v| v.2))
        .min(match trigger {
            TriggerInput::Custom { deadline, .. } => deadline,
            _ => i64::MAX,
        });
    if deadline <= available
        || !occurrence_available_in(profile, service, tx, policy.id, target, &occurrence, now)
            .await?
    {
        return Ok(());
    }
    queue_run_in(
        profile,
        service,
        tx,
        policy,
        RunInput {
            origin: match trigger {
                TriggerInput::Custom { origin, .. } => origin,
                _ => ActivityOrigin::Policy,
            },
            invocation: None,
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
pub struct RunInput<'a> {
    pub origin: ActivityOrigin,
    pub invocation: Option<Invocation>,
    pub target: &'a Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub async fn queue_run_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    policy: &EnrollmentPolicy,
    input: RunInput<'_>,
) -> Result<()> {
    use rss_transactional_messaging::outbox::{AppendOutcome, OutboxWriter};
    service.validate_in(tx)?;
    storage::lock_device(profile, tx, &input.target.device).await?;
    if storage::pending_in(
        profile,
        tx,
        policy.owner,
        policy.id,
        input.target,
        input.now,
    )
    .await?
    .0 || !occurrence_available_in(
        profile,
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
    let evidence = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(source
                    .evidence_on(c, tenant, scope, rss_mdm_inventory::Channel::Agent, &device)
                    .await)
            })
        })
        .await??;
    let message = dispatch(profile, tx.tenant_id(), policy.id, &input)?;
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
    let version = policy.id;
    let target = input.target.clone();
    let origin = checked_input(serde_json::to_value(input.origin))?;
    let evidence = checked_input(serde_json::to_value(evidence))?;
    let invocation = input
        .invocation
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Malformed)?;
    let state = checked_input(serde_json::to_value(rss_mdm_task_state::RunState::new(
        input.deadline,
        input.now,
    )?))?;
    let id = input.id;
    let now = input.now;
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                crate::storage_profile::sql(profile).enrollment_tasks_admission_queue_run_in_1,
            )
            .bind(tenant)
            .bind(id)
            .bind(version)
            .bind(target.device)
            .bind(target.registration)
            .bind(target.generation)
            .bind(input.occurrence)
            .bind(input.available)
            .bind(input.deadline)
            .bind(state)
            .bind(fingerprint)
            .bind(now)
            .bind(evidence)
            .bind(origin)
            .bind(invocation)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    crate::enrollment::tasks::wake::run_in(profile, &service.reconcile_messaging, tx, id).await?;
    tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'command_relay')").execute(c).await?;Ok(())})).await?;
    let audit = RequestAudit::new(
        tx.tenant_id().to_string(),
        "enrollment_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.operation(
        id,
        "enrollment_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("enrollment-admission");
    audit.plan(version);
    audit.target(&id.to_string());
    audit.registration(input.target.registration);
    let result: Result<()> = async {
        let run = storage::read_run(profile, tx, id).await?;
        let fact = Fact::business(
            &audit,
            &format!("enrollment:{id}:accept"),
            202,
            "success",
            None,
        )?
        .with_activity(&crate::enrollment::tasks::activity::run(
            &run,
            ActivityPhase::Accepted,
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
        Frequency::OncePerVersion => format!("version:{}", target.registration),
        Frequency::OncePerEntry => format!("entry:{source}:{entry}:{}", target.registration),
        Frequency::EveryTrigger => format!("{event}:{}", target.registration),
    }
}
pub async fn occurrence_available_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &Target,
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
                        .enrollment_tasks_admission_occurrence_available_in_1,
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
        rss_mdm_install_support::StorageProfile::Mdm => "mdm.registration.enrollment.v1",
        rss_mdm_install_support::StorageProfile::Da => "da.registration.enrollment.v1",
    })
    .expect("fixed Enrollment domain")
}
fn dispatch(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: rss_request_context::TenantId,
    version: Uuid,
    input: &RunInput<'_>,
) -> Result<rss_transactional_messaging::outbox::PendingMessage<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_transactional_messaging::{message::*, outbox::PendingMessage};
    use sha2::{Digest, Sha256};
    let payload = checked_input(serde_json::to_vec(
        &serde_json::json!({"version":1,"policyVersion":version,"taskId":input.id,"device":input.target.device,"registrationId":input.target.registration,"generation":input.target.generation}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("enrollment.{}", input.id)))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(input.now))?,
                messaging_domain(profile),
                checked_input(MessageRoute::parse("agent.enrollment"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.registration.enrollment-dispatch"))?,
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
