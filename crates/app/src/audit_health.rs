//! Health of the two fixed audit projections, separate from source admission.
use rss_runtime::TaskStatus;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
#[derive(Default)]
pub(crate) struct Readiness {
    pub(crate) phase: std::sync::Mutex<AuditPhase>,
    retrying: AtomicBool,
    pub(crate) task: OnceLock<TaskStatus>,
}
impl Readiness {
    pub(crate) fn progress(&self, claimed: usize, retried: usize) {
        if retried > 0 {
            self.retrying.store(true, Ordering::Release);
        } else if claimed > 0 {
            self.retrying.store(false, Ordering::Release);
        }
        *self.phase.lock().expect("audit health") = if self.retrying.load(Ordering::Acquire) {
            AuditPhase::Retrying
        } else {
            AuditPhase::Healthy
        };
    }
    pub(crate) fn transient_failure(&self) {
        *self.phase.lock().expect("audit health") = AuditPhase::DependencyUnavailable;
    }
    pub(crate) fn health(&self) -> AuditHealth {
        AuditHealth {
            phase: *self.phase.lock().expect("audit health"),
            task: self.task.get().map(TaskStatus::current),
        }
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AuditPhase {
    #[default]
    Initializing,
    Healthy,
    Retrying,
    DependencyUnavailable,
    Stopped,
}
pub(crate) struct AuditHealth {
    pub phase: AuditPhase,
    pub task: Option<rss_runtime::TaskState>,
}
impl AuditHealth {
    pub fn is_ready(&self) -> bool {
        self.phase == AuditPhase::Healthy && self.task == Some(rss_runtime::TaskState::Running)
    }
}
