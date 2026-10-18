//! Software-specific admission and task material; shared Run owns delivery and recovery.
use super::{
    production::{RunInput, queue_run_in},
    storage as db,
};
use crate::Target;
use crate::{Error, ExecutionService, Result};
use rss_mdm_policy::schedule::Trigger;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub async fn accept_for_device(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    now: i64,
) -> Result<()> {
    if policy.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall {
        return Ok(());
    }
    let Some(slot) = slot_in(service, tx, policy, target, None, now).await? else {
        return Ok(());
    };
    let id = Uuid::new_v4();
    queue_run_in(
        service,
        tx,
        RunInput {
            triggered_at: None,
            source: db::Source::Policy { version: policy.id },
            target,
            id,
            occurrence: slot.occurrence,
            available: slot.available,
            deadline: slot.deadline,
            now,
        },
    )
    .await?;
    persist_effect_in(tx, id, &slot.effect).await?;
    crate::sources::storage::wake_execution_in(tx, policy.owner).await?;
    Ok(())
}

pub struct Slot {
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub effect: serde_json::Value,
}
pub async fn slot_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    request: Option<Uuid>,
    now: i64,
) -> Result<Option<Slot>> {
    let Some(binding) =
        crate::channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
            .await?
    else {
        return Ok(None);
    };
    if !policy
        .assignment
        .supported_in(&service.admission(), tx, &binding)
        .await?
    {
        return Ok(None);
    }
    let Some((stage, _entry)) = policy
        .assignment
        .entry_in(&service.source, tx, &target.device, now)
        .await?
    else {
        return Ok(None);
    };
    let Some((platform, architecture)) =
        db::agent_profile_in(service, tx, target.registration).await?
    else {
        return Ok(None);
    };
    if policy
        .assignment
        .admitted_in(&service.admission(), tx, platform, architecture)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let steps = policy
        .assignment
        .prepared_in(
            &service.admission(),
            tx,
            platform,
            architecture,
            &binding.execution_context,
        )
        .await?
        .ok_or(Error::Forbidden)?;
    let effect = effect_key(policy, target, &steps)?;
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let version = policy.id;
    let stage_scope = policy.assignment.stages()[stage].scope;
    let prefix = format!("software:stage:{stage_scope}:%");
    let key = effect.clone();
    let (pending, last, satisfied, failures, attempts): (bool, Option<i64>, bool, i64, i64) = tx.with_connection(move |c| Box::pin(async move {
        // Unresolved effects conflict across intent, version, digest and registration generations.
        // Only the latest precisely ordered completion can satisfy the requested effect;
        // a later removal, replacement or known failure invalidates earlier success.
        sqlx::query_as(r#"
            WITH effects AS (
                SELECT r.* FROM mdm_commands.action_runs r
                WHERE r.tenant_id=$1::uuid AND r.device=$3
                  AND r.software_effect->'resource'=$2::jsonb->'resource'
                  AND r.software_effect->'target'=$2::jsonb->'target'
            )
            SELECT coalesce(bool_or(state->>'execution' IN ('unknown','waiting_reboot')
                       OR ((state->>'execution'='running'
                            OR (state->>'execution'='not_started' AND deadline>$5))
                           AND state->>'cancellation'<>'confirmed')),false),
                   max(created_at) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND occurrence LIKE $6),
                   coalesce((SELECT software_effect=$2 AND result->>'effect'='verified'
                             FROM effects
                             WHERE software_effect->'generation'=$2::jsonb->'generation'
                               AND result->>'effect' IN ('verified','failed')
                               AND jsonb_typeof(result->'effectObservedAt')='number'
                             ORDER BY (result->>'effectObservedAt')::bigint DESC LIMIT 1),false),
                   count(*) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND result->>'effect'='failed'),
                   count(*) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND occurrence LIKE $6)
            FROM effects
        "#)
            .bind(tenant).bind(key).bind(device).bind(version).bind(now).bind(prefix).fetch_one(c).await
    })).await?;
    if pending || satisfied || failures >= 3 {
        return Ok(None);
    }
    let schedule = &policy.assignment.frozen.schedule;
    let coordinate = match &schedule.trigger {
        Trigger::Manual if request.is_some() => now,
        Trigger::Manual => return Ok(None),
        Trigger::CheckIn { minimum_seconds } => {
            let delay = i64::from(*minimum_seconds).saturating_mul(1_i64 << failures.clamp(0, 3));
            if last.is_some_and(|at| now.saturating_sub(at) < delay) {
                return Ok(None);
            }
            now
        }
        Trigger::Registration => now,
        Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. } => {
            let Some(due) = schedule.due(-1, now, target.device.as_bytes())? else {
                return Ok(None);
            };
            due.coordinate
        }
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(None);
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(policy.assignment.frozen.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX));
    if deadline <= available {
        return Ok(None);
    }
    let occurrence = match request {
        Some(request) => format!("software:stage:{stage_scope}:self-service:{request}"),
        None => format!(
            "software:stage:{stage_scope}:desired:{}:{attempts}",
            target.registration
        ),
    };
    let tenant = tx.tenant_id().to_string();
    let version = policy.id;
    let device = target.device.clone();
    let key = occurrence.clone();
    let (exists, active): (bool, i64) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4), (SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$3 AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$5)")
            .bind(tenant).bind(version).bind(device).bind(key).bind(now).fetch_one(c).await
    })).await?;
    if exists || active >= 128 {
        return Ok(None);
    }
    Ok(Some(Slot {
        occurrence,
        available,
        deadline,
        effect,
    }))
}
fn effect_key(
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    steps: &[rss_mdm_agent_wire::runtime::SoftwareTaskStep],
) -> Result<serde_json::Value> {
    let root = steps.last().ok_or(Error::Malformed)?;
    // Installation effects survive logout; Start still binds the complete OS session target.
    let effect_target = match &root.target {
        rss_mdm_agent_wire::runtime::SoftwareExecutionTarget::Device => {
            serde_json::json!({"kind":"device"})
        }
        rss_mdm_agent_wire::runtime::SoftwareExecutionTarget::User { identity, .. } => {
            serde_json::json!({"kind":"user", "identity":identity})
        }
    };
    Ok(
        serde_json::json!({"generation":target.generation,"resource":policy.assignment.frozen.resource,"version":policy.assignment.frozen.version,"digest":policy.assignment.frozen.resource_digest,"intent":if policy.assignment.intent()==rss_mdm_policy::SoftwareIntent::ExplicitUninstall {"uninstall"} else {"install"},"target":effect_target}),
    )
}
pub async fn persist_effect_in(
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    effect: &serde_json::Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let effect = effect.clone();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.action_runs SET software_effect=$3 WHERE tenant_id=$1::uuid AND id=$2 AND software_effect IS NULL").bind(tenant).bind(run).bind(effect).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}
