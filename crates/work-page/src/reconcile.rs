//! Bounded tenant discovery for the host's RSS reconciliation registrations.
use super::{
    Failure,
    capacity::{Capacity, Slot},
};
use rss_reconcile::{
    Claim, ClaimBatch, Completion, Control, DurableStore, Error, ErrorKind, Observation, Policy,
    ReconcileDiff, ReconcileStep, Reconciler, ResourceSet, Scope, Target, Timer,
};
use std::{
    future::Future,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RECOVERY: Duration = Duration::from_secs(5);

pub async fn run<P, B>(
    budget: &Arc<Capacity>,
    policy: Policy,
    stop: &CancellationToken,
    notify: &Notify,
    page: impl Fn(Option<Uuid>) -> P,
    batch: impl Fn(Uuid, Vec<Slot>, CancellationToken) -> B + Send + Sync + 'static,
) -> Result<(), Error>
where
    P: Future<Output = Result<Vec<Uuid>, ErrorKind>>,
    B: Future<Output = Result<rss_reconcile::Report, Error>> + Send + 'static,
{
    let limit = NonZeroUsize::new(policy.concurrency())
        .expect("validated policy")
        .min(budget.limit());
    let batch = Arc::new(batch);
    let claim_limit = policy.claim_batch_size().min(limit.get());
    super::run_fallible(
        limit,
        RECOVERY,
        stop,
        notify,
        (std::convert::identity, |after| {
            let future = page(after);
            async move {
                future.await.map_err(|kind| match kind {
                    ErrorKind::Transient | ErrorKind::Deadline => Failure::Retry,
                    _ => Failure::Fatal(Error::new(kind)),
                })
            }
        }),
        |tenant, admission| {
            let budget = budget.clone();
            let batch = batch.clone();
            async move {
                let slots = budget.acquire(tenant, claim_limit, &admission).await;
                if slots.is_empty() {
                    return Ok(RECOVERY);
                }
                let report = batch(tenant, slots, admission)
                    .await
                    .map_err(|error| match error.kind() {
                        ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown => {
                            Failure::Retry
                        }
                        _ => Failure::Fatal(error),
                    })?;
                let worked = [
                    report.converged,
                    report.reobserve,
                    report.deferred,
                    report.retried,
                    report.suspended,
                    report.fenced,
                    report.execution_failed,
                ]
                .into_iter()
                .any(|n| n > 0);
                Ok(if worked { Duration::ZERO } else { RECOVERY })
            }
        },
        |_| {},
    )
    .await
}

/// RSS owns claims, attempts, renewal and settlement. Move the capacity slot
/// with that exact claim so unrelated completions can refill the budget.
pub async fn batch<S: DurableStore, R: Reconciler<S::Claim>>(
    (store, reconciler): (&S, &R),
    slots: Vec<Slot>,
    scope: &Scope,
    policy: Policy,
    stop: &CancellationToken,
    observe: impl FnMut(Observation) + Send,
) -> Result<rss_reconcile::Report, Error> {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic execution clock boundary"
    )]
    let timer = BatchTimer(tokio::time::Instant::now());
    let force = CancellationToken::new();
    let control = Control::new(&timer, Duration::MAX, &force);
    let store = Admitted {
        store,
        slots: Mutex::new(slots),
    };
    rss_reconcile::run_batch(
        &store,
        &Delegate(reconciler),
        scope,
        policy,
        &control,
        stop,
        observe,
    )
    .await
}

struct Admitted<'a, S> {
    store: &'a S,
    slots: Mutex<Vec<Slot>>,
}
struct Leased<C> {
    claim: C,
    _slot: Slot,
}
impl<C: Claim> Claim for Leased<C> {
    fn target(&self) -> &Target {
        self.claim.target()
    }
    fn failures(&self) -> u32 {
        self.claim.failures()
    }
}
impl<S: DurableStore> DurableStore for Admitted<'_, S> {
    type Claim = Leased<S::Claim>;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.bind_resources(target, resources, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<ClaimBatch<Self::Claim>, Error> {
        let mut slots = std::mem::take(&mut *self.slots.lock().expect("one claim round"));
        slots.truncate(limit);
        if slots.is_empty() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        let batch = self
            .store
            .claim_due(scope, slots.len(), scan_budget, lease, control)
            .await?;
        if batch.claims.len() > slots.len() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        Ok(ClaimBatch {
            claims: batch
                .claims
                .into_iter()
                .zip(slots)
                .map(|(claim, _slot)| Leased { claim, _slot })
                .collect(),
            more: batch.more,
        })
    }
    async fn renew<T: Timer>(
        &self,
        claim: &Self::Claim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.renew(&claim.claim, lease, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &Self::Claim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.finish(&claim.claim, completion, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &Self::Claim,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.release(&claim.claim, control).await
    }
}
struct Delegate<'a, R>(&'a R);
impl<C: Claim, R: Reconciler<C>> Reconciler<Leased<C>> for Delegate<'_, R> {
    type State = R::State;
    async fn observe<T: Timer>(
        &self,
        c: &Leased<C>,
        control: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<Self::State>>, Error> {
        self.0.observe(&c.claim, control).await
    }
    async fn apply<T: Timer>(
        &self,
        c: &Leased<C>,
        diff: ReconcileDiff<Self::State>,
        control: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        self.0.apply(&c.claim, diff, control).await
    }
}

struct BatchTimer(tokio::time::Instant);
impl Timer for BatchTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic execution clock boundary"
    )]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }
}
