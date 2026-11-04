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
        source: &dyn super::participants::TargetAdmission,
        store: std::sync::Arc<dyn super::agent_facts::Store>,
        target: &Target,
        now: i64,
        capacity: bool,
    ) -> Result<(TaskAdmission, CurrentRecord)> {
        let waiting = |state| (TaskAdmission::new(state, None), CurrentRecord::Unknown);
        let entry = match policy
            .entry_on(c, self.tenant, source, &target.device, now)
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
        // Existing Collection validation permits only interval/every_trigger/coalesce_one.
        // Actual starts, including custom events, reset the interval; the authored anchor does not.
        let next = match (started, &schedule.trigger) {
            (Some(at), Trigger::Interval { seconds, .. }) => {
                at.checked_add(i64::from(*seconds)).filter(|at| *at > now)
            }
            _ => schedule
                .next_after(now, target.device.as_bytes())?
                .map(|o| o.available_at),
        };
        Ok((
            TaskAdmission::new(
                if started.is_some() {
                    S::IntervalNotElapsed
                } else {
                    S::Scheduled
                },
                None,
            )
            .not_before(next),
            CurrentRecord::Unknown,
        ))
    }
}
