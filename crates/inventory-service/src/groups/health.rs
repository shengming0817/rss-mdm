//! Group reports its own execution and queues; App composes product readiness.
use super::*;
impl Groups {
    pub fn task_state(&self) -> Option<rss_runtime::TaskState> {
        self.task_status.get().map(rss_runtime::TaskStatus::current)
    }
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
        self.runtime.local_tx(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                let row:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks j WHERE tenant_id=$1::uuid AND NOT completed AND cursor IS NULL AND NOT EXISTS(SELECT FROM mdm_group.member_runs r WHERE(r.tenant_id,r.id)=(j.tenant_id,j.id) AND r.processed_count>0) LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks j WHERE tenant_id=$1::uuid AND NOT completed AND (cursor IS NOT NULL OR EXISTS(SELECT FROM mdm_group.member_runs r WHERE(r.tenant_id,r.id)=(j.tenant_id,j.id) AND r.processed_count>0)) LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND completed AND failure IS NULL LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)")
                    .bind(tenant).fetch_one(c).await?;
                Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64])
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|_|Err(Error::Conflict))
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
pub(super) struct RunnerObservation {
    scan: Option<Scan>,
    failures: std::collections::HashMap<rss_reconcile::Target, (u64, Attempt)>,
    sequence: u64,
    truncated: bool,
}
impl Groups {
    pub fn runner_health(&self) -> RunnerHealth {
        let state = self.runner_health.lock().expect("Group runner observation");
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
    pub(super) fn record_scan(&self, failure: Option<rss_reconcile::ErrorKind>) {
        self.runner_health
            .lock()
            .expect("Group runner observation")
            .scan = Some(Scan {
            failure,
            observed_at: self.clock.unix_seconds(),
        });
    }
    pub(super) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        match event {
            rss_reconcile::Observation::Deferred { .. } => {}
            rss_reconcile::Observation::ScanFailed { error, .. } => {
                self.record_scan(Some(error.kind()))
            }
            rss_reconcile::Observation::AttemptFailed {
                target,
                stage,
                error,
            } => {
                let mut state = self.runner_health.lock().expect("Group runner observation");
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
                                observed_at: self.clock.unix_seconds(),
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
    pub(super) fn record_settled(
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
                .expect("Group runner observation")
                .failures
                .remove(target);
        }
    }
}
