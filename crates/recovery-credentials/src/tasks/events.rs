use super::*;
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_audit_integration::activity::ActivityOrigin;
impl crate::tasks::Transactions {
    pub async fn accept_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: Uuid,
        target: &crate::tasks::Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
    ) -> crate::tasks::transaction::Result<Decision> {
        if !self.accepts_new_work() {
            return Ok(Decision::Rejected {
                reason: "device_access_disabled".into(),
            });
        }
        let profile = self.profile();

        self.validate_in(tx)?;
        crate::tasks::storage::lock_device(profile, tx, &target.device).await?;
        let now = crate::tasks::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        let plan = crate::tasks::policy::read_in(&self.policy_reader, tx, version).await?;
        if !plan.active {
            return Ok(Decision::Rejected {
                reason: "policy_disabled".into(),
            });
        }
        if plan
            .entry_in(&self.source, tx, &target.device, now)
            .await?
            .is_none()
        {
            return Ok(Decision::Rejected {
                reason: "scope_not_eligible".into(),
            });
        }
        crate::tasks::actions::production::accept_for_device(
            profile,
            self,
            tx,
            &plan,
            target,
            crate::tasks::actions::production::AdmissionTrigger::Custom {
                origin: cause.1,
                request: cause.0,
                at: now,
                deadline,
            },
            now,
            cause.0,
        )
        .await?;
        let tenant = tx.tenant_id();
        let id = cause.0;
        let exists = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        !crate::tasks::storage::owned_ids_on(profile, c, tenant, &[id])
                            .await?
                            .is_empty(),
                    )
                })
            })
            .await?;
        Ok(if exists {
            Decision::Accepted {
                operations: vec![Operation::Run { id: cause.0 }],
            }
        } else {
            Decision::Rejected {
                reason: "execution_not_eligible".into(),
            }
        })
    }
}

impl crate::tasks::Transactions {
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &crate::tasks::Target,
        id: Uuid,
    ) -> crate::tasks::Result<bool> {
        let profile = self.profile();
        self.validate_in(tx)?;
        let run = crate::tasks::storage::load_run(profile, tx, id).await?;
        Ok(run.target.device == target.device
            && run.target.device == target.device
            && run.state.execution == rss_mdm_task_state::Execution::Running
            && run.state.started_at.is_some())
    }
}
