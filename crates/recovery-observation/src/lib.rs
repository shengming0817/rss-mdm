//! Process-local observations of an exact recovery owner. RSS owns tasks and claims.
//! No business decisions, worker loop, timers, transaction execution or durable state.
use rss_reconcile::{Completion, ErrorKind, Observation, Scope, Target};
use rss_runtime::{TaskState, TaskStatus};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

mod observations;
pub use observations::{Attempt, Observations, Scan, Snapshot};
mod store;
pub use store::ObservedStore;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Unobserved,
    Healthy,
    Failed(ErrorKind),
}
#[derive(Clone, Debug)]
pub struct Health {
    pub task: Option<TaskState>,
    pub stopping: bool,
    pub recovery: Phase,
    pub discovery: Phase,
    pub scan: Phase,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub relay: Option<Phase>,
    pub inputs: Option<Phase>,
}
impl Health {
    pub fn phases(&self) -> impl Iterator<Item = Phase> + '_ {
        std::iter::once(self.recovery)
            .chain(self.relay)
            .chain(self.inputs)
    }
    /// Startup belongs to the managed task; an idle owner need not invent tenant work.
    pub fn is_ready(&self) -> bool {
        self.task == Some(TaskState::Running)
            && !self.stopping
            && self.phases().all(|p| !matches!(p, Phase::Failed(_)))
    }
}
/// A new process starts an observation window. Overflow remains failed until restart;
/// successful work never erases failures for another target or scope.
pub struct Readiness {
    domain: String,
    task: OnceLock<TaskStatus>,
    stopping: AtomicBool,
    rounds: Mutex<Observations>,
    relay_enabled: bool,
    inputs_enabled: bool,
}
impl Readiness {
    pub fn new(domain: &str, relay: bool, inputs: bool) -> Self {
        Self {
            domain: domain.into(),
            task: OnceLock::new(),
            stopping: AtomicBool::new(false),
            rounds: Mutex::new(Observations::default()),
            relay_enabled: relay,
            inputs_enabled: inputs,
        }
    }
    pub fn health(&self) -> Health {
        let snapshot = self.rounds.lock().ok().map(|r| r.snapshot());
        let recovery = snapshot.map_or(Phase::Failed(ErrorKind::Invariant), |s| s.recovery);
        let scan = snapshot.map_or(Phase::Failed(ErrorKind::Invariant), |s| phase_scan(s.scan));
        let relay = self
            .relay_enabled
            .then(|| snapshot.map_or(Phase::Failed(ErrorKind::Invariant), |s| phase_scan(s.relay)));
        let inputs = self.inputs_enabled.then(|| {
            snapshot.map_or(Phase::Failed(ErrorKind::Invariant), |s| {
                phase_scan(s.inputs)
            })
        });
        let unresolved_attempts = snapshot.map_or(0, |s| s.unresolved_attempts);
        let truncated = snapshot.is_none_or(|s| s.truncated);
        Health {
            task: self.task.get().map(TaskStatus::current),
            stopping: self.stopping.load(Ordering::Acquire),
            recovery,
            discovery: snapshot.map_or(Phase::Failed(ErrorKind::Invariant), |s| {
                phase_scan(s.discovery)
            }),
            scan,
            unresolved_attempts,
            truncated,
            relay,
            inputs,
        }
    }
    pub fn bind(&self, task: TaskStatus) {
        if self.task.set(task).is_err() {
            self.stop();
        }
    }
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }
    pub fn relay_round(&self, outcome: Result<(), ErrorKind>) {
        if self.relay_enabled
            && let Ok(mut r) = self.rounds.lock()
        {
            r.relay_round(&self.domain, outcome, None);
        }
    }
    pub fn inputs(&self, target: &Target, outcome: Result<(), ErrorKind>) {
        if self.inputs_enabled
            && self.check(target.scope()).is_ok()
            && let Ok(mut r) = self.rounds.lock()
        {
            r.inputs(target, outcome, None);
        }
    }
    /// Also records runner timeouts that drop a store future before it returns.
    pub fn observe(&self, event: &Observation) {
        let scope = match event {
            Observation::ScanFailed { scope, .. } => scope,
            Observation::AttemptFailed { target, .. } | Observation::Deferred { target } => {
                target.scope()
            }
        };
        if self.check(scope).is_ok()
            && let Ok(mut r) = self.rounds.lock()
        {
            r.observe(event, None);
        }
    }
    fn check(&self, scope: &Scope) -> Result<(), rss_reconcile::Error> {
        if scope.reconciler() == self.domain {
            Ok(())
        } else {
            Err(rss_reconcile::Error::new(ErrorKind::Invariant))
        }
    }
    pub fn discovery(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock() {
            r.discovery(&self.domain, outcome, None);
        }
    }
    pub fn scan_scope(&self, scope: &Scope, outcome: Result<(), ErrorKind>) {
        if self.check(scope).is_ok()
            && let Ok(mut r) = self.rounds.lock()
        {
            r.scan(scope, outcome, None);
        }
    }
    pub fn relay_scope(&self, scope: &Scope, epoch: i64, outcome: Result<(), ErrorKind>) {
        if self.relay_enabled
            && self.check(scope).is_ok()
            && let Ok(mut r) = self.rounds.lock()
        {
            r.relay(scope, epoch, outcome, None);
        }
    }
    fn settled(&self, target: &Target, completion: Completion) {
        if let Ok(mut r) = self.rounds.lock() {
            r.settled(target, completion);
        }
    }
}
fn phase_scan(scan: Option<Scan>) -> Phase {
    match scan {
        None => Phase::Unobserved,
        Some(Scan { failure: None, .. }) => Phase::Healthy,
        Some(Scan {
            failure: Some(kind),
            ..
        }) => Phase::Failed(kind),
    }
}
