use super::*;
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_audit_integration::activity::ActivityOrigin;
impl Transactions {
    pub async fn accept_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &rss_mdm_policy::Policy,
        target: &Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
        audit: &RequestAudit,
    ) -> Result<Decision> {
        self.validate_in(tx)?;
        storage::lock_device(tx, &target.device).await?;
        let now = storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        if !policy.state.is_enabled() {
            return Ok(Decision::Rejected {
                reason: "policy_disabled".into(),
            });
        }
        let source = self.source.clone();
        let tenant = tx.tenant_id();
        let scope = policy.definition.scope;
        let device = target.device.clone();
        let eligible = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(source
                        .admission_on(
                            c,
                            tenant,
                            scope,
                            crate::participants::scope::Channel::Agent,
                            &device,
                        )
                        .await)
                })
            })
            .await??;
        if !matches!(
            eligible,
            crate::participants::scope::ScopeAdmission::Eligible { .. }
        ) {
            return Ok(Decision::Rejected {
                reason: "scope_not_eligible".into(),
            });
        }
        let prepared =
            admission::prepare_target_reconciliation_in(self, tx, target, Some(policy.id)).await?;
        let outcome = admission::reconcile_in(self, tx, prepared, now, cause.1, audit).await?;
        Ok(if !outcome.operations.is_empty() {
            Decision::Accepted {
                operations: outcome
                    .operations
                    .into_iter()
                    .map(|id| Operation::Run { id })
                    .collect(),
            }
        } else if outcome.blocked {
            Decision::Rejected {
                reason: "access_not_eligible".into(),
            }
        } else {
            Decision::NoChange {
                reason: "account_bindings_current".into(),
            }
        })
    }
}
impl crate::device_access::execution::Transactions {
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &crate::device_access::execution::Target,
        id: Uuid,
    ) -> crate::device_access::execution::Result<bool> {
        self.validate_in(tx)?;
        let run = crate::device_access::execution::storage::load_run(tx, id).await?;
        Ok(run.target.device == target.device
            && run.target.registration == target.registration
            && run.target.generation == target.generation
            && run.state.execution == rss_mdm_task_state::Execution::Running
            && run.state.started_at.is_some())
    }
}
