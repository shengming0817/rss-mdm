//! Scope worker observations. App only combines the reported facts.
use crate::*;
impl Scopes {
    pub fn input_observed(&self) -> bool {
        self.input_state.load(std::sync::atomic::Ordering::Acquire) != 0
    }
    pub fn input_failed(&self) -> bool {
        self.input_state.load(std::sync::atomic::Ordering::Acquire) == 2
    }
    pub async fn queue_health(
        &self,
        budget: std::time::Duration,
    ) -> std::result::Result<[u64; 5], Error> {
        self.runtime
            .local_tx_with_context(
                self.tenant,
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
/// Bounded owner observations; target identities never cross the diagnostic boundary.
#[derive(Clone, Copy, Debug)]
pub struct Scan {
    pub failure: Option<rss_reconcile::ErrorKind>,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Attempt {
    pub stage: rss_reconcile::Stage,
    pub failure: rss_reconcile::ErrorKind,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct RunnerHealth {
    pub scan: Option<Scan>,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub latest_failure: Option<Attempt>,
}
#[derive(Default)]
pub(crate) struct RunnerObservation {
    scan: Option<Scan>,
    failures: std::collections::HashMap<rss_reconcile::Target, (u64, Attempt)>,
    sequence: u64,
    truncated: bool,
}
impl Scopes {
    pub fn runner_health(&self) -> RunnerHealth {
        let state = self.runner_health.lock().expect("Scope runner observation");
        RunnerHealth {
            scan: state.scan,
            unresolved_attempts: state.failures.len() as u64,
            truncated: state.truncated,
            latest_failure: state
                .failures
                .values()
                .max_by_key(|(n, _)| n)
                .map(|(_, v)| *v),
        }
    }
    pub(crate) fn record_scan(&self, failure: Option<rss_reconcile::ErrorKind>) {
        self.runner_health
            .lock()
            .expect("Scope runner observation")
            .scan = Some(Scan {
            failure,
            observed_at: self.clock.unix_seconds().ok(),
        });
    }
    pub(crate) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        match event {
            rss_reconcile::Observation::ScanFailed { error, .. } => {
                self.record_scan(Some(error.kind()))
            }
            rss_reconcile::Observation::AttemptFailed {
                target,
                stage,
                error,
            } => {
                let mut state = self.runner_health.lock().expect("Scope runner observation");
                state.sequence = state.sequence.saturating_add(1);
                let sequence = state.sequence;
                if state.failures.contains_key(&target) || state.failures.len() < 1000 {
                    state.failures.insert(
                        target,
                        (
                            sequence,
                            Attempt {
                                stage,
                                failure: error.kind(),
                                observed_at: self.clock.unix_seconds().ok(),
                            },
                        ),
                    );
                } else {
                    // Lost identities cannot be declared recovered by a later unrelated success.
                    state.truncated = true;
                }
            }
        }
    }
    pub(crate) fn record_settled(
        &self,
        target: &rss_reconcile::Target,
        completion: rss_reconcile::Completion,
    ) {
        if matches!(
            completion,
            rss_reconcile::Completion::Converged | rss_reconcile::Completion::Reobserve(_)
        ) {
            self.runner_health
                .lock()
                .expect("Scope runner observation")
                .failures
                .remove(target);
        }
    }
}
