//! Scope worker observations. App only combines the reported facts.
use crate::*;
impl Scopes {
    pub async fn queue_health(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        budget: std::time::Duration,
    ) -> std::result::Result<[u64; 5], Error> {
        self.runtime
            .local_tx_with_context(
                execution,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget),
                &self.store,
                |store, tx| {
                    Box::pin(async move {
                        store.queue_counts_in(tx).await.map_err(|e| match e {
                            rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                            _ => sqlx::Error::Protocol("Scope health".into()).into(),
                        })
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Storage)),
                |_| Err(Error::Unavailable(Failure::Storage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Conflict),
            )
    }
}
impl Scopes {
    pub fn runner_health(&self) -> rss_mdm_recovery_observation::Snapshot {
        self.runner_health
            .lock()
            .expect("runner observation")
            .snapshot()
    }
    pub(crate) fn record_discovery(
        &self,
        outcome: std::result::Result<(), rss_reconcile::ErrorKind>,
    ) {
        self.runner_health
            .lock()
            .expect("runner observation")
            .discovery(
                crate::tasks::domain(self.profile()),
                outcome,
                self.clock.unix_seconds().ok(),
            );
    }
    pub(crate) fn record_scan(
        &self,
        scope: &rss_reconcile::Scope,
        failure: Option<rss_reconcile::ErrorKind>,
    ) {
        self.runner_health.lock().expect("runner observation").scan(
            scope,
            failure.map_or(Ok(()), Err),
            self.clock.unix_seconds().ok(),
        );
    }
    pub(crate) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        self.runner_health
            .lock()
            .expect("runner observation")
            .observe(&event, self.clock.unix_seconds().ok());
    }
    pub(crate) fn record_settled(
        &self,
        target: &rss_reconcile::Target,
        completion: rss_reconcile::Completion,
    ) {
        self.runner_health
            .lock()
            .expect("runner observation")
            .settled(target, completion);
    }
}

impl crate::Scopes {
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
                |owner, tx| {
                    Box::pin(async move {
                        owner.store.input_failed_in(tx).await.map_err(|e| match e {
                            rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                            _ => sqlx::Error::Protocol("Scope input health".into()).into(),
                        })
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(crate::Error::Unavailable(crate::Failure::Storage)),
                |_| Err(crate::Error::Unavailable(crate::Failure::Storage)),
                |_| Err(crate::Error::RollbackFailed),
                |_| Err(crate::Error::CommitUnknown),
                |_| Err(crate::Error::Conflict),
            )?;
        if !failed {
            let scope =
                rss_reconcile::Scope::new(execution.tenant(), crate::tasks::domain(self.profile()))
                    .expect("constant domain");
            let target =
                rss_reconcile::Target::new(scope, "inputs").expect("constant input target");
            self.record_settled(&target, rss_reconcile::Completion::Converged);
        }
        Ok(failed)
    }
}
