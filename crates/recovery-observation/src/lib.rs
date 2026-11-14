//! Process-local observations of an exact recovery owner. RSS owns tasks and claims.
//! No business decisions, worker loop, timers, transaction execution or durable state.
use rss_reconcile::{Completion, ErrorKind, Observation, Scope, Target};
use rss_runtime::{TaskState, TaskStatus};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

mod store;
pub use store::ObservedStore;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Initializing,
    Healthy,
    Failed(ErrorKind),
}
#[derive(Clone, Debug)]
pub struct Health {
    pub task: Option<TaskState>,
    pub stopping: bool,
    pub recovery: Phase,
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
    pub fn is_ready(&self) -> bool {
        self.task == Some(TaskState::Running)
            && !self.stopping
            && self.phases().all(|p| p == Phase::Healthy)
    }
}
struct Rounds {
    scan: Phase,
    relay: Option<Phase>,
    inputs: Option<Phase>,
    failures: BTreeMap<String, ErrorKind>,
    overflow: bool,
}
impl Rounds {
    fn record(&mut self, key: String, outcome: Result<(), ErrorKind>) {
        match outcome {
            Ok(()) => {
                self.failures.remove(&key);
            }
            Err(error) if self.failures.len() < 1000 || self.failures.contains_key(&key) => {
                self.failures.insert(key, error);
            }
            Err(_) => self.overflow = true,
        }
    }
}
/// A new process starts an observation window. Overflow remains failed until restart;
/// successful work never erases failures for another target or scope.
pub struct Readiness {
    domain: String,
    task: OnceLock<TaskStatus>,
    stopping: AtomicBool,
    rounds: Mutex<Rounds>,
}
impl Readiness {
    pub fn new(domain: &str, relay: bool, inputs: bool) -> Self {
        Self {
            domain: domain.into(),
            task: OnceLock::new(),
            stopping: AtomicBool::new(false),
            rounds: Mutex::new(Rounds {
                scan: Phase::Initializing,
                relay: relay.then_some(Phase::Initializing),
                inputs: inputs.then_some(Phase::Initializing),
                failures: BTreeMap::new(),
                overflow: false,
            }),
        }
    }
    pub fn health(&self) -> Health {
        let (recovery, relay, inputs, scan, unresolved_attempts, truncated) =
            match self.rounds.lock() {
                Ok(r) => (
                    if r.overflow {
                        Phase::Failed(ErrorKind::Invariant)
                    } else {
                        r.failures
                            .values()
                            .next()
                            .copied()
                            .map_or(r.scan, Phase::Failed)
                    },
                    r.relay,
                    r.inputs,
                    r.scan,
                    r.failures.len() as u64,
                    r.overflow,
                ),
                Err(_) => (
                    Phase::Failed(ErrorKind::Invariant),
                    None,
                    None,
                    Phase::Failed(ErrorKind::Invariant),
                    0,
                    true,
                ),
            };
        Health {
            task: self.task.get().map(TaskStatus::current),
            stopping: self.stopping.load(Ordering::Acquire),
            recovery,
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
    pub fn relay(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock()
            && r.relay.is_some()
        {
            r.relay = Some(phase(outcome));
        }
    }
    pub fn inputs(&self, scope: &Scope, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock()
            && r.inputs.is_some()
        {
            r.inputs = Some(phase(outcome));
            r.record(format!("{}:inputs", scope.tenant()), outcome);
        }
    }
    /// Runner timeouts may drop the store future before it can return an observation.
    pub fn observe(&self, event: &Observation) {
        match event {
            Observation::ScanFailed { scope, error } if scope.reconciler() == self.domain => {
                self.scan_scope(scope, Err(error.kind()));
            }
            Observation::AttemptFailed { target, error, .. }
                if target.scope().reconciler() == self.domain =>
            {
                if let Ok(mut r) = self.rounds.lock() {
                    r.record(
                        format!("{}:{}", target.scope().tenant(), target.entity()),
                        Err(error.kind()),
                    );
                }
            }
            _ => {}
        }
    }
    fn check(&self, scope: &Scope) -> Result<(), rss_reconcile::Error> {
        if scope.reconciler() == self.domain {
            Ok(())
        } else {
            Err(rss_reconcile::Error::new(ErrorKind::Invariant))
        }
    }
    pub fn scan(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock() {
            r.scan = phase(outcome);
        }
    }
    pub fn scan_scope(&self, scope: &Scope, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock() {
            r.scan = phase(outcome);
            r.record(format!("scope:{}:scan", scope.tenant()), outcome);
        }
    }
    pub fn relay_scope(&self, scope: &Scope, epoch: i64, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock()
            && r.relay.is_some()
        {
            r.relay = Some(phase(outcome));
            r.record(format!("scope:{}:relay:{epoch}", scope.tenant()), outcome);
        }
    }
    fn settled(&self, target: &Target, completion: Completion) {
        if matches!(completion, Completion::Converged | Completion::Reobserve(_))
            && let Ok(mut r) = self.rounds.lock()
        {
            r.failures
                .remove(&format!("{}:{}", target.scope().tenant(), target.entity()));
        }
    }
}
fn phase(outcome: Result<(), ErrorKind>) -> Phase {
    match outcome {
        Ok(()) => Phase::Healthy,
        Err(kind) => Phase::Failed(kind),
    }
}
