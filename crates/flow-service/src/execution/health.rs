//! Execution owner observations; RSS remains the task and durable claim authority.
//! ref: rss crates/runtime/src/resource.rs, crates/reconcile/src/ports.rs
use rss_reconcile::ErrorKind;
use rss_runtime::{TaskState, TaskStatus};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Initializing,
    Healthy,
    Failed(ErrorKind),
}
#[derive(Clone, Copy, Debug)]
pub struct Health {
    pub task: Option<TaskState>,
    pub stopping: bool,
    pub recovery: Phase,
    pub relay: Phase,
}
impl Health {
    pub fn is_ready(&self) -> bool {
        self.task == Some(TaskState::Running)
            && !self.stopping
            && self.recovery == Phase::Healthy
            && self.relay == Phase::Healthy
    }
}
#[derive(Default)]
pub struct Readiness {
    task: OnceLock<TaskStatus>,
    stopping: AtomicBool,
    rounds: Mutex<(Phase, Phase)>,
}
impl Readiness {
    pub fn health(&self) -> Health {
        let (recovery, relay) = self.rounds.lock().map(|s| *s).unwrap_or((
            Phase::Failed(ErrorKind::Invariant),
            Phase::Failed(ErrorKind::Invariant),
        ));
        Health {
            task: self.task.get().map(TaskStatus::current),
            stopping: self.stopping.load(Ordering::Acquire),
            recovery,
            relay,
        }
    }
    pub(crate) fn bind(&self, task: TaskStatus) {
        if self.task.set(task).is_err() {
            self.stop();
        }
    }
    pub(crate) fn scan(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut rounds) = self.rounds.lock() {
            rounds.0 = phase(outcome);
        }
    }
    pub(crate) fn relay(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut rounds) = self.rounds.lock() {
            rounds.1 = phase(outcome);
        }
    }
    pub(crate) fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }
}
fn phase(outcome: Result<(), ErrorKind>) -> Phase {
    match outcome {
        Ok(()) => Phase::Healthy,
        Err(kind) => Phase::Failed(kind),
    }
}

// Transparent observations of real claim results, including confirmed empty scans.
pub(super) struct ObservedStore<'a>(pub &'a super::ExecutionService);
impl rss_reconcile::DurableStore for ObservedStore<'_> {
    type Claim = rss_reconcile_postgres::PgClaim;
    async fn wake<T: rss_reconcile::Timer>(
        &self,
        target: &rss_reconcile::Target,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.wake(target, control).await
    }
    async fn claim_due<T: rss_reconcile::Timer>(
        &self,
        scope: &rss_reconcile::Scope,
        limit: usize,
        lease: std::time::Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<Vec<Self::Claim>, rss_reconcile::Error> {
        let result = self
            .0
            .reconcile
            .claim_due(scope, limit, lease, control)
            .await;
        if result.is_ok() {
            self.0.readiness.scan(Ok(()));
        }
        result
    }
    async fn renew<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        lease: std::time::Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.renew(claim, lease, control).await
    }
    async fn release<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        self.0.reconcile.release(claim, control).await
    }
    fn finish<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = Result<(), rss_reconcile::Error>> + Send {
        self.0.reconcile.finish(claim, completion, control)
    }
}
