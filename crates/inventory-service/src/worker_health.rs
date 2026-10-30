//! Bounded observations only; execution and task state stay with each business owner.
use rss_reconcile::{Completion, ErrorKind, Observation, Stage, Target};
#[derive(Default)]
pub(crate) struct ObservationState {
    scan: Option<WorkerScan>,
    failed: std::collections::HashMap<Target, (u64, WorkerAttempt)>,
    sequence: u64,
    truncated: bool,
}
impl ObservationState {
    pub(crate) fn scan(&mut self, failure: Option<ErrorKind>, observed_at: Option<i64>) {
        self.scan = Some(WorkerScan {
            failure,
            observed_at,
        });
    }
    pub(crate) fn failure(&mut self, event: Observation, observed_at: Option<i64>) {
        match event {
            Observation::Deferred { .. } => {}
            Observation::ScanFailed { error, .. } => self.scan(Some(error.kind()), observed_at),
            Observation::AttemptFailed {
                target,
                stage,
                error,
            } => {
                self.sequence = self.sequence.saturating_add(1);
                if self.failed.len() < 1000 || self.failed.contains_key(&target) {
                    self.failed.insert(
                        target,
                        (
                            self.sequence,
                            WorkerAttempt {
                                stage,
                                failure: error.kind(),
                                observed_at,
                            },
                        ),
                    );
                } else {
                    self.truncated = true;
                }
            }
        }
    }
    pub(crate) fn settled(&mut self, target: &Target, completion: Completion) {
        if matches!(completion, Completion::Converged | Completion::Reobserve(_)) {
            self.failed.remove(target);
        }
    }
    pub(crate) fn status(&self, task: Option<rss_runtime::TaskState>) -> WorkerStatus {
        WorkerStatus {
            task,
            observed: self.scan.is_some(),
            failed: self.scan.is_some_and(|s| s.failure.is_some())
                || !self.failed.is_empty()
                || self.truncated,
            scan: self.scan,
            unresolved_attempts: self.failed.len() as u64,
            truncated: self.truncated,
            latest_failure: self.failed.values().max_by_key(|(n, _)| n).map(|(_, f)| *f),
        }
    }
}
/// Last durable scheduling scan, without scope identity.
#[derive(Clone, Copy)]
pub struct WorkerScan {
    /// Failure of the most recent scan, if any.
    pub failure: Option<ErrorKind>,
    /// Wall-clock observation when available from the injected clock.
    pub observed_at: Option<i64>,
}
/// Most recent unresolved execution failure, without target identity.
#[derive(Clone, Copy)]
pub struct WorkerAttempt {
    /// Failed RSS execution stage.
    pub stage: Stage,
    /// Closed failure category.
    pub failure: ErrorKind,
    /// Wall-clock observation from the injected clock.
    pub observed_at: Option<i64>,
}
/// Product worker readiness evidence without exposing task identities.
pub struct WorkerStatus {
    /// Actual registered managed-task state.
    pub task: Option<rss_runtime::TaskState>,
    /// Whether this owner has attempted a durable scan.
    pub observed: bool,
    /// Unresolved scan or execution failure.
    pub failed: bool,
    /// Most recent scan observation.
    pub scan: Option<WorkerScan>,
    /// Number of retained unresolved target failures.
    pub unresolved_attempts: u64,
    /// Additional failure identities exceeded the observation budget.
    pub truncated: bool,
    /// Most recent unresolved failure.
    pub latest_failure: Option<WorkerAttempt>,
}
