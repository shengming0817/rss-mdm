//! Owner task status projected from the shared exact-identity observations.
use rss_mdm_recovery_observation::{Attempt, Observations, Scan};
pub struct WorkerStatus {
    pub task: Option<rss_runtime::TaskState>,
    pub observed: bool,
    pub failed: bool,
    pub recovery: rss_mdm_recovery_observation::Phase,
    pub discovery: Option<Scan>,
    pub scan: Option<Scan>,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub latest_failure: Option<Attempt>,
}
pub(crate) fn status(state: &Observations, task: Option<rss_runtime::TaskState>) -> WorkerStatus {
    let snapshot = state.snapshot();
    WorkerStatus {
        task,
        recovery: snapshot.recovery,
        observed: snapshot.observed(),
        failed: snapshot.failed(),
        discovery: snapshot.discovery,
        scan: snapshot.scan,
        unresolved_attempts: snapshot.unresolved_attempts,
        truncated: snapshot.truncated,
        latest_failure: snapshot.latest_failure,
    }
}

impl crate::Compliance {
    /// Read the retained owner outcome without discovering or waking business work.
    pub async fn input_failed(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        budget: std::time::Duration,
    ) -> std::result::Result<bool, crate::Error> {
        let failed = self
            .runtime
            .local_tx_with_context(
                execution,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget),
                self,
                |_, tx| {
                    Box::pin(async move {
                        let tenant = tx.tenant_id();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                rss_mdm_compliance_postgres::tasks::input_failed(c, tenant).await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(crate::Error::Unavailable(crate::Failure::ComplianceStorage)),
                |_| Err(crate::Error::Unavailable(crate::Failure::ComplianceStorage)),
                |_| Err(crate::Error::RollbackFailed),
                |_| Err(crate::Error::CommitUnknown),
                |_| Err(crate::Error::Conflict),
            )?;
        if !failed {
            let scope = rss_reconcile::Scope::new(execution.tenant(), "mdm.compliance")
                .expect("constant domain");
            let target =
                rss_reconcile::Target::new(scope, "inputs").expect("constant input target");
            self.worker_health
                .lock()
                .expect("worker observation")
                .settled(&target, rss_reconcile::Completion::Converged);
        }
        Ok(failed)
    }
}
