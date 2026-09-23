use super::{schedule::Trigger, state::RunState, storage as db};
use crate::Error;
use crate::commands::{Commands, Result, invalid, messaging_domain};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_transactional_messaging::{
    message::*,
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProduceOutcome {
    Produced,
    Duplicate,
    SkippedByPolicy,
    CapacityBlocked,
}
impl ProduceOutcome {
    fn merge(self, next: Self) -> Self {
        use ProduceOutcome::*;
        match (self, next) {
            (CapacityBlocked, _) | (_, CapacityBlocked) => CapacityBlocked,
            (Produced, _) | (_, Produced) => Produced,
            (Duplicate, _) | (_, Duplicate) => Duplicate,
            _ => SkippedByPolicy,
        }
    }
}

pub(super) async fn produce(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    plan: &db::Plan,
    coordinate: i64,
    trigger: &str,
    now: i64,
    only: Option<&str>,
) -> Result<ProduceOutcome> {
    let mut outcome = ProduceOutcome::SkippedByPolicy;
    for device in &plan.frozen.input.devices {
        if only.is_some_and(|value| value != device) {
            continue;
        }
        if !db::valid(tx, plan, device, now).await? {
            continue;
        }
        let identity = invalid(serde_json::to_vec(&(
            tx.tenant_id().to_string(),
            plan.id,
            1,
            device,
        )))?;
        let Some(occurrence) = plan
            .frozen
            .input
            .schedule
            .occurrence(coordinate, &identity)?
        else {
            outcome = outcome.merge(ProduceOutcome::SkippedByPolicy);
            continue;
        };
        if trigger == "timer"
            && matches!(
                plan.frozen.input.schedule.misfire,
                super::schedule::Misfire::Skip
            )
            && occurrence.available_at < now.saturating_sub(30)
        {
            outcome = outcome.merge(ProduceOutcome::SkippedByPolicy);
            continue;
        }
        let target = match db::registration(tx, device).await {
            Ok(target) => target,
            Err(crate::commands::Fault::Request(Error::Conflict)) => {
                outcome = outcome.merge(ProduceOutcome::SkippedByPolicy);
                continue;
            }
            Err(e) => return Err(e),
        };
        let key = if trigger.starts_with("registration:") {
            trigger.to_owned()
        } else {
            format!("{trigger}:{coordinate}")
        };
        let tenant = tx.tenant_id().to_string();
        let device_key = device.clone();
        let plan_key = plan.id.to_string();
        let occurrence_key = key.clone();
        let (duplicate, active)=tx.with_connection(move|c|Box::pin(async move{sqlx::query_as::<_,(bool,i64)>("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND device=$3 AND occurrence=$4), (SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$3 AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$5)").bind(tenant).bind(plan_key).bind(device_key).bind(occurrence_key).bind(now).fetch_one(c).await})).await?;
        if duplicate {
            outcome = outcome.merge(ProduceOutcome::Duplicate);
            continue;
        }
        if active >= 128 {
            outcome = outcome.merge(ProduceOutcome::CapacityBlocked);
            continue;
        }
        let deadline = occurrence
            .available_at
            .checked_add(i64::from(plan.frozen.input.run_lifetime_seconds))
            .ok_or(Error::Malformed)?
            .min(plan.frozen.input.schedule.until)
            .min(occurrence.window_end.unwrap_or(i64::MAX));
        if deadline <= now || deadline <= occurrence.available_at {
            outcome = outcome.merge(ProduceOutcome::SkippedByPolicy);
            continue;
        }
        let id = Uuid::new_v4();
        let message = dispatch(tx.tenant_id(), plan.id, id, &target, now)?;
        let digest = message.fingerprint().as_bytes().to_vec();
        if service
            .outbox
            .append(tx, message)
            .await
            .map_err(rss_transactional_messaging_postgres::PgError::from)?
            != AppendOutcome::Inserted
        {
            return Err(Error::Conflict.into());
        }
        let tenant = tx.tenant_id().to_string();
        let plan_id = plan.id.to_string();
        let state = invalid(serde_json::to_value(RunState::new(deadline, now)?))?;
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,plan,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,$8,$9,$10,$11,$12)").bind(tenant).bind(id.to_string()).bind(plan_id).bind(target.device).bind(target.registration.to_string()).bind(target.generation).bind(key).bind(occurrence.available_at).bind(deadline).bind(state).bind(digest).bind(now).execute(c).await?;Ok(())})).await?;
        let audit = crate::audit::Audit::new(tx.tenant_id().to_string(), "command_accept");
        audit.operation(id, "command_accept");
        audit.target(device);
        let result = crate::commands::storage::audit(tx, &audit, 202).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| crate::audit::FailureReason::Transaction),
        );
        result?;
        outcome = outcome.merge(ProduceOutcome::Produced);
    }
    Ok(outcome)
}
fn dispatch(
    tenant: rss_request_context::TenantId,
    plan: Uuid,
    id: Uuid,
    target: &super::model::Target,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = invalid(serde_json::to_vec(
        &json!({"version":2,"planId":plan,"taskId":id,"device":target.device,"registrationId":target.registration,"generation":target.generation}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        invalid(MessageId::parse(&format!("action.{id}")))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                invalid(Timepoint::try_from(now))?,
                messaging_domain(),
                invalid(MessageRoute::parse("agent.task"))?,
                ContractIdentity::new(
                    invalid(ContractId::parse("mdm.action-dispatch"))?,
                    ContractVersion::from_static_major(2),
                    invalid(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v2.json"))
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}
pub(super) async fn tick(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    plan: &db::Plan,
    now: i64,
) -> Result<()> {
    if !plan.active || plan.reviewer.is_none() {
        return Ok(());
    }
    // Select the shared coordinate without device jitter; each insertion applies its own jitter.
    let mut schedule = plan.frozen.input.schedule.clone();
    schedule.jitter_seconds = 0;
    schedule.window = None;
    schedule.misfire = super::schedule::Misfire::CoalesceOne;
    let mut capacity_blocked = false;
    if let Some(occurrence) = schedule.due(plan.scan_at, now, b"schedule")? {
        capacity_blocked = matches!(
            produce(service, tx, plan, occurrence.coordinate, "timer", now, None).await?,
            ProduceOutcome::CapacityBlocked
        );
    }
    if matches!(schedule.trigger, Trigger::Registration) {
        for device in &plan.frozen.input.devices {
            match db::registration(tx, device).await {
                Ok(target) => {
                    // Registration identity is stable across worker restarts. Production's device set
                    // is narrowed without changing the approved plan or target authorization bases.
                    capacity_blocked |= matches!(
                        event(service, tx, plan, &target, "registration", now).await?,
                        ProduceOutcome::CapacityBlocked
                    );
                }
                Err(crate::commands::Fault::Request(Error::Conflict)) => (),
                Err(error) => return Err(error),
            }
        }
    }
    if capacity_blocked {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let id = plan.id.to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_plans SET scan_at=greatest(scan_at,$3) WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).bind(now).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn event(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    plan: &db::Plan,
    target: &super::model::Target,
    kind: &str,
    now: i64,
) -> Result<ProduceOutcome> {
    if let Trigger::CheckIn { minimum_seconds } = plan.frozen.input.schedule.trigger {
        let tenant = tx.tenant_id().to_string();
        let plan_id = plan.id.to_string();
        let device = target.device.clone();
        let last=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Option<i64>>("SELECT max(created_at) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid AND device=$3").bind(tenant).bind(plan_id).bind(device).fetch_one(c).await})).await?;
        if last.is_some_and(|last| now.saturating_sub(last) < i64::from(minimum_seconds)) {
            return Ok(ProduceOutcome::SkippedByPolicy);
        }
    }
    let key = if kind == "registration" {
        format!("registration:{}", target.registration)
    } else {
        "checkin".to_owned()
    };
    produce(service, tx, plan, now, &key, now, Some(&target.device)).await
}
