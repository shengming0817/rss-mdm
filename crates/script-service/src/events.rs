//! Policy event participation stays in the initiating Policy transaction.
use rss_mdm_agent_wire::runtime::{
    PolicyEventDecision as Decision, PolicyEventOperation as Operation,
};
use rss_mdm_audit_integration::activity::ActivityOrigin;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
impl crate::Transactions {
    pub async fn accept_event_in(
        &self,
        tx: &mut PgTransaction<'_>,
        version: Uuid,
        target: &crate::Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
    ) -> crate::transaction::Result<Decision> {
        self.validate_in(tx)?;
        crate::storage::lock_device(tx, &target.device).await?;
        let now = crate::storage::now(tx).await?;
        if now >= deadline {
            return Ok(Decision::Expired);
        }
        let plan = crate::policy::read_in(self, tx, version).await?;
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
        crate::admission::accept_for_device(
            self,
            tx,
            &plan,
            target,
            crate::admission::TriggerInput::Custom {
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
                    Ok(!crate::storage::owned_ids_on(c, tenant, &[id])
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
