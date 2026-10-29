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
    pub inputs: Phase,
}
impl Health {
    pub fn is_ready(&self) -> bool {
        self.task == Some(TaskState::Running)
            && !self.stopping
            && self.recovery == Phase::Healthy
            && self.relay == Phase::Healthy
            && self.inputs == Phase::Healthy
    }
}
#[derive(Default)]
pub struct Readiness {
    task: OnceLock<TaskStatus>,
    stopping: AtomicBool,
    rounds: Mutex<(Phase, Phase)>,
    inputs: Mutex<Phase>,
    attempts: Mutex<std::collections::BTreeMap<String, ErrorKind>>,
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
            recovery: self
                .attempts
                .lock()
                .ok()
                .and_then(|s| s.values().next().copied())
                .map_or(recovery, Phase::Failed),
            relay,
            inputs: self
                .inputs
                .lock()
                .map(|p| *p)
                .unwrap_or(Phase::Failed(ErrorKind::Invariant)),
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
    pub(crate) fn inputs(&self, outcome: Result<(), ErrorKind>) {
        if let Ok(mut value) = self.inputs.lock() {
            *value = phase(outcome);
        }
    }
    pub(crate) fn failed_attempt(&self, target: &rss_reconcile::Target, kind: ErrorKind) {
        if let Ok(mut attempts) = self.attempts.lock() {
            if attempts.len() < 1000 || attempts.contains_key(target.entity()) {
                attempts.insert(target.entity().to_owned(), kind);
            } else {
                attempts.insert("!truncated".into(), ErrorKind::Invariant);
            }
        }
    }
    fn settled(&self, target: &rss_reconcile::Target) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.remove(target.entity());
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
    async fn finish<T: rss_reconcile::Timer>(
        &self,
        claim: &Self::Claim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> Result<(), rss_reconcile::Error> {
        use rss_reconcile::Completion;
        let settlement = control.child(std::time::Duration::from_secs(6));
        let input = claim.target() == &crate::source_changes::target(self.0.transactions.tenant);
        if input {
            self.0.settle_inputs(claim, completion, &settlement).await?;
        }
        let scheduled = if let Some(work) =
            crate::actions::scheduled::Work::parse(claim.target().entity())
        {
            if matches!(completion, Completion::Converged | Completion::Reobserve(_)) {
                let delay = crate::transaction::inspect(
                    &self.0.transactions.runtime,
                    self.0.transactions.tenant,
                    (self.0, work),
                    |(service, work), tx| {
                        Box::pin(async move {
                            crate::actions::scheduled::delay_in(service, tx, *work).await
                        })
                    },
                )
                .await
                .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
                delay.map_or(Completion::Converged, Completion::Reobserve)
            } else {
                completion
            }
        } else if let Some(work @ crate::actions::native_recovery::Work::Run(_)) =
            crate::actions::native_recovery::Work::parse(claim.target().entity())
            && completion == Completion::Converged
        {
            let waiting = crate::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                work,
                |work, tx| {
                    Box::pin(
                        async move { crate::actions::native_recovery::active(tx, *work).await },
                    )
                },
            )
            .await
            .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            if waiting {
                Completion::Reobserve(std::time::Duration::from_secs(5))
            } else {
                Completion::Converged
            }
        } else if let Some(policy) = crate::actions::recovery::policy_id(claim.target().entity())
            && matches!(completion, Completion::Reobserve(_))
        {
            let pending = crate::transaction::inspect(
                &self.0.transactions.runtime,
                self.0.transactions.tenant,
                policy,
                |policy, tx| {
                    Box::pin(async move { crate::actions::recovery::backlog_in(tx, *policy).await })
                },
            )
            .await
            .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
            Completion::Reobserve(if pending {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::from_secs(5)
            })
        } else {
            match (input, completion) {
                (true, Completion::Converged) => {
                    Completion::Reobserve(std::time::Duration::from_secs(5))
                }
                (false, Completion::Reobserve(_)) => {
                    let pending = crate::transaction::inspect(
                        &self.0.transactions.runtime,
                        self.0.transactions.tenant,
                        claim.target().entity(),
                        |entity, tx| {
                            Box::pin(async move { crate::recovery::backlog_in(tx, entity).await })
                        },
                    )
                    .await
                    .map_err(|_| rss_reconcile::Error::new(ErrorKind::Transient))?;
                    Completion::Reobserve(if pending {
                        std::time::Duration::from_millis(20)
                    } else {
                        std::time::Duration::from_secs(5)
                    })
                }
                _ => completion,
            }
        };
        let result = self.0.reconcile.finish(claim, scheduled, &settlement).await;
        if result.is_ok() && matches!(completion, Completion::Converged | Completion::Reobserve(_))
        {
            self.0.readiness.settled(claim.target());
        }
        if input {
            let healthy = result.is_ok()
                && matches!(completion, Completion::Converged | Completion::Reobserve(_));
            self.0.readiness.inputs(if healthy {
                Ok(())
            } else {
                Err(result
                    .as_ref()
                    .err()
                    .map_or(ErrorKind::Transient, |e| e.kind()))
            });
        }
        result
    }
}
