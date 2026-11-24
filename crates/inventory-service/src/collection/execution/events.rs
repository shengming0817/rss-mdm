//! Policy event participation stays in the initiating Policy transaction.
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_audit_integration::activity::ActivityOrigin;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
impl super::Transactions {
    pub async fn accept_event_in(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        version: Uuid,
        target: &super::model::Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
    ) -> crate::transaction::Result<Decision> {
        self.validate_in(tx)?;
        if tx.tenant_id() != binding.tenant() || tx.expected_epoch() != binding.epoch() {
            return Err(crate::Error::Forbidden.into());
        }
        super::storage::lock_device(tx, &target.device).await?;
        let now = super::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        let plan = super::policy::read_in(self, tx, version).await?;
        if plan.policy.version != version {
            return Ok(Decision::Rejected {
                reason: "policy_changed".into(),
            });
        }
        if !plan.active {
            return Ok(Decision::Rejected {
                reason: "policy_disabled".into(),
            });
        }
        if plan
            .entry_in(self, tx, &target.device, now)
            .await?
            .is_none()
        {
            return Ok(Decision::Rejected {
                reason: "scope_not_eligible".into(),
            });
        }
        super::admission::accept_for_device(
            binding,
            self,
            tx,
            &plan,
            target,
            super::admission::TriggerInput::Custom {
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
                    Ok(!super::storage::owned_ids_on(c, tenant, &[id])
                        .await?
                        .is_empty())
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

impl super::Transactions {
    pub async fn event_parent_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> crate::transaction::Result<bool> {
        self.validate_in(tx)?;
        let run = super::storage::load_run(tx, id).await?;
        Ok(run.target.device == device
            && run.state.execution == rss_mdm_task_state::Execution::Running
            && run.state.started_at.is_some())
    }
}
pub enum EventProgress {
    Agent(rss_mdm_task_state::RunState),
    Native(super::model::NativeProgress),
}
impl super::Transactions {
    pub async fn event_progress_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> crate::transaction::Result<EventProgress> {
        self.validate_in(tx)?;
        Ok(if super::storage::channel_in(tx, id).await? == "agent" {
            EventProgress::Agent(super::storage::read_run(tx, id).await?.state)
        } else {
            EventProgress::Native(super::storage::native_progress_in(tx, id).await?)
        })
    }
}
