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
