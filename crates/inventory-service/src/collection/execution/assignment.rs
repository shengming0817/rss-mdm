//! Read-only collection qualification; no task, trigger or report is created here.
use super::{admission, frozen::Published, model::Target, policy::CollectionPolicy, storage};
use crate::transaction::Result;
use rss_mdm_policy::{
    pages::{CurrentRecord, TaskAdmission, TaskAdmissionState as S},
    schedule::Trigger,
};
impl super::inputs::Inputs {
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit owner facts in the caller's read-only snapshot"
    )]
    pub async fn assignment_state_on(
        &self,
        c: &mut sqlx::PgConnection,
        policy: &CollectionPolicy,
        scope: super::participants::Admission,
        store: std::sync::Arc<dyn super::agent_facts::Store>,
        target: &Target,
        now: i64,
        capacity: bool,
    ) -> Result<(TaskAdmission, CurrentRecord)> {
        let waiting = |state| (TaskAdmission::new(state, None), CurrentRecord::Unknown);
        let entry = match policy
            .entry_on(c, self.tenant, scope, &target.device, now)
            .await?
        {
            Ok(entry) => entry,
            Err(reason) => return Ok((reason, CurrentRecord::Unknown)),
        };
        let eligible = match &policy.frozen {
            Published::AgentCollection { action, .. } => {
                if !super::policy::agent_source_on(c, self.tenant, target).await? {
                    return Ok(waiting(S::ReportSourceUnavailable));
                }
                let assessment = super::eligibility::assessment_on(
                    c,
                    self.tenant,
                    store,
                    target,
                    action.input.platform,
                    action.input.architecture,
                    &action.definition,
                )
                .await?;
                match assessment {
                    super::eligibility::Assessment::Unknown => {
                        return Ok(waiting(S::ChannelUnknown));
                    }
                    super::eligibility::Assessment::Eligible => true,
                    super::eligibility::Assessment::Unsupported => false,
                }
            }
            Published::NativeCollection { action, .. } => {
                self.native
                    .eligible_on(c, self.tenant, target, &action.definition)
                    .await?
            }
        };
        if !eligible {
            return Ok(waiting(S::UnsupportedCapability));
        }
        let (pending, last) =
            storage::pending_on(c, self.tenant, policy.owner, policy.id, target, now).await?;
        if pending.is_some() {
            return Ok(waiting(S::ExecutionPending));
        }
        let explicit =
            admission::explicit_on(c, self.tenant, policy.id, &target.device, now, true).await?;
        let started = storage::last_started_on(c, self.tenant, policy.id, target).await?;
        let schedule = &policy.frozen.input().schedule;
        if let Some(observed) = interval_without_trigger(
            schedule,
            started,
            explicit.is_some(),
            now,
            policy.frozen.channel(),
            capacity,
        )? {
            return Ok(observed);
        }
        if let Some(candidate) =
            admission::candidate(policy, target, None, now, last, started, explicit, entry)?
        {
            if let Some(task_id) = admission::occurrence_on(
                c,
                self.tenant,
                policy.id,
                &target.device,
                &candidate.occurrence,
            )
            .await?
            {
                return Ok((
                    TaskAdmission::new(S::FrequencyConsumed, None),
                    CurrentRecord::Present { task_id },
                ));
            }
            let state = if !capacity {
                S::CapacityBusy
            } else if candidate.available > now {
                S::Scheduled
            } else if policy.frozen.channel() == rss_mdm_inventory::Channel::Agent {
                S::WaitingCheckIn
            } else {
                S::Eligible
            };
            return Ok((
                TaskAdmission::new(state, None).not_before(
                    (candidate.available > now && capacity).then_some(candidate.available),
                ),
                CurrentRecord::Absent,
            ));
        }
        let next = schedule
            .next_after(now, target.device.as_bytes())?
            .map(|o| o.available_at);
        Ok((
            TaskAdmission::new(S::Scheduled, None).not_before(next),
            CurrentRecord::Unknown,
        ))
    }
}

/// A rolling interval acquires its timer coordinate at a future execution observation.
/// A GET cannot mint that identity or bind jitter to its own clock. The last actual
/// start still proves the minimum interval, independently of any future observation.
fn interval_without_trigger(
    schedule: &rss_mdm_policy::schedule::Schedule,
    started: Option<i64>,
    explicit: bool,
    now: i64,
    channel: rss_mdm_inventory::Channel,
    capacity: bool,
) -> Result<Option<(TaskAdmission, CurrentRecord)>> {
    let (Some(started), Trigger::Interval { seconds, .. }) = (started, &schedule.trigger) else {
        return Ok(None);
    };
    if explicit {
        return Ok(None);
    }
    let lower = started
        .checked_add(i64::from(*seconds))
        .ok_or(crate::Error::Malformed)?;
    let state = if now < lower {
        S::IntervalNotElapsed
    } else if !capacity {
        S::CapacityBusy
    } else if channel == rss_mdm_inventory::Channel::Agent {
        S::WaitingCheckIn
    } else {
        S::Eligible
    };
    Ok(Some((
        TaskAdmission::new(state, None).not_before((now < lower).then_some(lower)),
        CurrentRecord::Unknown,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_inventory::Channel;
    fn schedule() -> rss_mdm_policy::schedule::Schedule {
        serde_json::from_value(serde_json::json!({"trigger":{"kind":"interval","anchor":0,"seconds":60},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":60,"window":null})).unwrap()
    }
    #[test]
    fn a_get_does_not_bind_the_next_observation_identity_or_jitter() {
        let schedule = schedule();
        assert_eq!(
            schedule
                .collection_due(Some(0), 100, b"device")
                .unwrap()
                .unwrap()
                .available_at,
            131
        );
        assert_eq!(
            schedule
                .collection_due(Some(0), 101, b"device")
                .unwrap()
                .unwrap()
                .available_at,
            122
        );
        for (channel, capacity, expected) in [
            (Channel::Agent, true, S::WaitingCheckIn),
            (Channel::Mdm, true, S::Eligible),
            (Channel::Agent, false, S::CapacityBusy),
        ] {
            for now in [100, 101] {
                let (admission, record) =
                    interval_without_trigger(&schedule, Some(0), false, now, channel, capacity)
                        .unwrap()
                        .unwrap();
                assert_eq!(admission.state(), expected);
                assert_eq!(record, CurrentRecord::Unknown);
                assert_eq!(admission.next_allowed_start_at, None);
            }
        }
    }
    #[test]
    fn real_interval_bounds_and_durable_trigger_identities_remain_distinct() {
        let schedule = schedule();
        let (admission, record) =
            interval_without_trigger(&schedule, Some(0), false, 50, Channel::Agent, true)
                .unwrap()
                .unwrap();
        assert_eq!(admission.state(), S::IntervalNotElapsed);
        assert_eq!(admission.next_allowed_start_at, Some(60));
        assert_eq!(record, CurrentRecord::Unknown);
        assert!(
            interval_without_trigger(&schedule, None, false, 100, Channel::Agent, true)
                .unwrap()
                .is_none()
        );
        assert!(
            interval_without_trigger(&schedule, Some(0), true, 100, Channel::Agent, true)
                .unwrap()
                .is_none()
        );
    }
}
