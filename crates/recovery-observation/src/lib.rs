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
/// A new process starts an observation window. Overflow remains failed until restart;
/// successful work never erases failures for another target or scope.
pub struct Readiness {
    scope: Scope,
    task: OnceLock<TaskStatus>,
    stopping: AtomicBool,
    rounds: Mutex<Rounds>,
}
impl Readiness {
    pub fn new(scope: Scope, relay: bool, inputs: bool) -> Self {
        Self {
            scope,
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
    pub fn inputs(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock()
            && r.inputs.is_some()
        {
            r.inputs = Some(phase(outcome));
            if outcome.is_ok() {
                // Input owners confirm durable progress/failure before recording success.
                // Another instance may have recovered this fixed target since our attempt.
                r.failures.remove("inputs");
            }
        }
    }
    /// Runner timeouts may drop the store future before it can return an observation.
    pub fn observe(&self, event: &Observation) {
        match event {
            Observation::ScanFailed { scope, error } if scope == &self.scope => {
                self.scan(Err(error.kind()))
            }
            Observation::AttemptFailed { target, error, .. } if target.scope() == &self.scope => {
                if let Ok(mut r) = self.rounds.lock() {
                    if r.failures.len() < 1000 || r.failures.contains_key(target.entity()) {
                        r.failures.insert(target.entity().to_owned(), error.kind());
                    } else {
                        r.overflow = true;
                    }
                }
            }
            _ => {}
        }
    }
    fn check(&self, scope: &Scope) -> Result<(), rss_reconcile::Error> {
        if scope == &self.scope {
            Ok(())
        } else {
            Err(rss_reconcile::Error::new(ErrorKind::Invariant))
        }
    }
    fn scan(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut r) = self.rounds.lock() {
            r.scan = phase(outcome);
        }
    }
    fn settled(&self, target: &Target, completion: Completion) {
        if matches!(completion, Completion::Converged | Completion::Reobserve(_))
            && let Ok(mut r) = self.rounds.lock()
        {
            r.failures.remove(target.entity());
        }
    }
}
fn phase(outcome: Result<(), ErrorKind>) -> Phase {
    match outcome {
        Ok(()) => Phase::Healthy,
        Err(kind) => Phase::Failed(kind),
    }
}
