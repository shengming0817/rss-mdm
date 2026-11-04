//! Read-only explanation over the same frozen input, trigger and deduplication rules as admission.
use crate::{Result, Target, admission, policy::ScriptPolicy};
use rss_mdm_policy::{
    Frequency,
    pages::{CurrentRecord, TaskAdmission, TaskAdmissionState as S},
    schedule::Trigger,
};

#[expect(
    clippy::too_many_arguments,
    reason = "explicit owner facts in the caller's read-only snapshot"
)]
pub async fn state_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: &ScriptPolicy,
    source: &rss_mdm_scope_service::channels::ChannelTargets,
    store: std::sync::Arc<dyn crate::agent_facts::Store>,
    target: &Target,
    now: i64,
    capacity: bool,
) -> Result<(TaskAdmission, CurrentRecord)> {
    let waiting = |state| (TaskAdmission::new(state, None), CurrentRecord::Unknown);
    let entry = match policy
        .entry_on(c, tenant, source, &target.device, now)
        .await?
    {
        Ok(entry) => entry,
        Err(reason) => return Ok((reason, CurrentRecord::Unknown)),
    };
    if policy.frozen.parameters.has_input() {
        return Ok(waiting(S::InputRequired));
    }
    match crate::eligibility::require_on(c, tenant, store, target, &policy.frozen).await? {
        crate::eligibility::Eligibility::Unknown => return Ok(waiting(S::ChannelUnknown)),
        crate::eligibility::Eligibility::Ineligible => {
            return Ok(waiting(S::UnsupportedCapability));
        }
        crate::eligibility::Eligibility::Eligible => {}
    }
    let pending = crate::storage::pending_on(
        c,
        tenant,
        policy.owner,
        policy.id,
        target,
        &policy.frozen.resource.id,
        now,
    )
    .await?;
    if pending.unknown.is_some() {
        return Ok(waiting(S::EffectUnknown));
    }
    if pending.active.is_some() {
        return Ok(waiting(S::ExecutionPending));
    }
    let explicit = admission::explicit_on(c, tenant, policy.id, &target.device, now, true).await?;
    let schedule = &policy.frozen.input.schedule;
    // A fixed frequency has a real identity even if the next check-in/event does not yet exist.
    if explicit.is_none() && !matches!(policy.frequency, Frequency::EveryTrigger) {
        let key = admission::policy_occurrence(
            policy.frequency,
            target,
            &policy.entry_source(),
            entry,
            "",
        );
        if let Some(task_id) =
            admission::occurrence_on(c, tenant, policy.id, &target.device, &key).await?
        {
            return Ok((
                TaskAdmission::new(S::FrequencyConsumed, None),
                CurrentRecord::Present { task_id },
            ));
        }
    }
    if let Some(candidate) =
        admission::candidate(policy, target, None, now, pending.last, explicit, entry)?
    {
        if let Some(task_id) =
            admission::occurrence_on(c, tenant, policy.id, &target.device, &candidate.occurrence)
                .await?
        {
            let next = schedule
                .next_after(now, target.device.as_bytes())?
                .map(|o| o.available_at);
            return Ok((
                TaskAdmission::new(S::FrequencyConsumed, None).not_before(next),
                CurrentRecord::Present { task_id },
            ));
        }
        let state = if !capacity {
            S::CapacityBusy
        } else if candidate.available > now {
            waiting_time_reason(schedule, now, target.device.as_bytes())?
        } else {
            S::WaitingCheckIn
        };
        // Event-trigger jitter is anchored at the actual event, not at this GET.
        let known_time = explicit.is_some()
            || matches!(
                schedule.trigger,
                Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. }
            );
        return Ok((
            TaskAdmission::new(state, None).not_before(
                (known_time && candidate.available > now && capacity)
                    .then_some(candidate.available),
            ),
            CurrentRecord::Absent,
        ));
    }
    let (state, next) = match &schedule.trigger {
        Trigger::Manual => (S::WaitingTrigger, None),
        Trigger::CheckIn { minimum_seconds } => {
            let next = pending
                .last
                .and_then(|v| v.checked_add(i64::from(*minimum_seconds)))
                .filter(|at| *at > now);
            (
                if next.is_some() {
                    S::IntervalNotElapsed
                } else {
                    S::WaitingCheckIn
                },
                next,
            )
        }
        Trigger::Registration => (S::WaitingCheckIn, None),
        _ => {
            let next = schedule
                .next_after(now, target.device.as_bytes())?
                .map(|o| o.available_at);
            (
                if next.is_some() {
                    S::Scheduled
                } else {
                    S::WaitingTrigger
                },
                next,
            )
        }
    };
    Ok((
        TaskAdmission::new(state, None).not_before(next),
        CurrentRecord::Unknown,
    ))
}

// Ask the production window calculator about now with jitter disabled. Merely configuring
// a window does not make an otherwise open window the cause of a jitter delay.
fn waiting_time_reason(
    schedule: &rss_mdm_policy::schedule::Schedule,
    now: i64,
    identity: &[u8],
) -> Result<S> {
    let mut window = schedule.clone();
    window.jitter_seconds = 0;
    Ok(
        if window.window.is_some()
            && window
                .occurrence(now, identity)?
                .is_none_or(|slot| slot.available_at > now)
        {
            S::OutsideWindow
        } else {
            S::Scheduled
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_open_window_does_not_turn_jitter_into_an_outside_window_reason() {
        let mut schedule:rss_mdm_policy::schedule::Schedule=serde_json::from_value(serde_json::json!({
            "trigger":{"kind":"interval","anchor":0,"seconds":60},"notBefore":0,"until":null,
            "jitterSeconds":60,"window":{"zone":"UTC","weekdays":[1,2,3,4,5,6,7],"startMinute":0,"endMinute":1440}
        })).unwrap();
        let now = (0..60)
            .find(|at| {
                schedule
                    .occurrence(*at, b"device")
                    .unwrap()
                    .unwrap()
                    .available_at
                    > *at
            })
            .unwrap();
        assert_eq!(
            waiting_time_reason(&schedule, now, b"device").unwrap(),
            S::Scheduled
        );
        schedule.window.as_mut().unwrap().start_minute = 60;
        assert_eq!(
            waiting_time_reason(&schedule, now, b"device").unwrap(),
            S::OutsideWindow
        );
    }
}
