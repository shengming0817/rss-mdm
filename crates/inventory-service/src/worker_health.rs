//! Bounded observations only; execution and task state stay with each business owner.
use rss_reconcile::{Completion, Observation, Target};
#[derive(Default)]
pub(crate) struct ObservationState {
    scan: Option<bool>,
    failed: std::collections::HashSet<Target>,
    truncated: bool,
}
impl ObservationState {
    pub(crate) fn scan(&mut self, failed: bool) {
        self.scan = Some(failed);
    }
    pub(crate) fn failure(&mut self, event: Observation) {
        match event {
            Observation::ScanFailed { .. } => self.scan = Some(true),
            Observation::AttemptFailed { target, .. } => {
                if self.failed.len() < 1000 || self.failed.contains(&target) {
                    self.failed.insert(target);
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
            failed: self.scan == Some(true) || !self.failed.is_empty() || self.truncated,
        }
    }
}
/// Product worker readiness evidence without exposing task identities.
pub struct WorkerStatus {
    /// Actual registered managed-task state.
    pub task: Option<rss_runtime::TaskState>,
    /// Whether this owner has attempted a durable scan.
    pub observed: bool,
    /// Unresolved scan or execution failure.
    pub failed: bool,
}
