//! Software-specific admission and task material; shared Run owns delivery and recovery.
use super::{
    model::Target,
    production::{RunInput, queue_run_in},
    storage as db,
};
use crate::{
    Error,
    execution::{ExecutionService, Result},
};
use rss_mdm_policy::{SoftwareIntent, schedule::Trigger};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub(super) async fn accept_for_device(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &crate::planning::policies::software::SoftwareExecutionPolicy,
    target: &Target,
    request: Uuid,
    now: i64,
) -> Result<()> {
    let Some((stage, _entry)) = policy.entry_in(tx, &target.device, now).await? else {
        return Ok(());
    };
    let Some((platform, architecture)) = db::agent_profile_in(tx, target.registration).await?
    else {
        return Ok(());
    };
    if policy
        .admitted_in(service, tx, platform, architecture)
        .await?
        .is_none()
    {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let resource = policy.frozen.resource.clone();
    let device = target.device.clone();
    let version = policy.id;
    let (pending, last): (bool, Option<i64>) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT coalesce(bool_or(r.state->>'execution' IN ('unknown','waiting_reboot') OR ((r.state->>'execution'='running' OR (r.state->>'execution'='not_started' AND r.deadline>$5)) AND r.state->>'cancellation'<>'confirmed')),false),max(r.created_at) FILTER(WHERE r.policy_version=$4::uuid) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) JOIN mdm_policy.policies p ON (p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE r.tenant_id=$1::uuid AND p.definition->'resource'->>'id'=$2 AND r.device=$3")
            .bind(tenant).bind(resource).bind(device).bind(version).bind(now).fetch_one(c).await
    })).await?;
    if pending {
        return Ok(());
    }
    let schedule = &policy.frozen.schedule;
    let (coordinate, event) = match &schedule.trigger {
        Trigger::Manual => return Ok(()),
        Trigger::CheckIn { minimum_seconds } => {
            if last.is_some_and(|at| now.saturating_sub(at) < i64::from(*minimum_seconds)) {
                return Ok(());
            }
            (now, format!("checkin:{request}"))
        }
        Trigger::Registration => (now, format!("registration:{}", target.registration)),
        Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. } => {
            let Some(due) = schedule.due(-1, now, target.device.as_bytes())? else {
                return Ok(());
            };
            (due.coordinate, format!("timer:{}", due.coordinate))
        }
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(());
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(policy.frozen.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX));
    if deadline <= available {
        return Ok(());
    }
    let recurrence = if matches!(policy.intent(), SoftwareIntent::ExplicitUninstall) {
        format!("version:{}", target.registration)
    } else {
        format!("{event}:{}", target.registration)
    };
    let stage_scope = policy.stages()?[stage].scope;
    let occurrence = format!("software:stage:{stage_scope}:{recurrence}");
    let tenant = tx.tenant_id().to_string();
    let version = policy.id;
    let device = target.device.clone();
    let key = occurrence.clone();
    let (exists, active): (bool, i64) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4), (SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$3 AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$5)")
            .bind(tenant).bind(version).bind(device).bind(key).bind(now).fetch_one(c).await
    })).await?;
    if exists || active >= 128 {
        return Ok(());
    }
    queue_run_in(
        service,
        tx,
        RunInput {
            source: db::Source::Policy { version: policy.id },
            target,
            id: Uuid::new_v4(),
            occurrence,
            available,
            deadline,
            now,
        },
    )
    .await?;
    crate::planning::policies::storage::wake_execution_in(tx, policy.owner).await?;
    Ok(())
}
