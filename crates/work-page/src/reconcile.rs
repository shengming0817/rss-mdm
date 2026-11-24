//! Bounded tenant discovery for the host's RSS reconciliation registrations.
use super::{
    Failure,
    capacity::{Capacity, Slot},
};
use futures::{StreamExt, stream::FuturesUnordered};
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
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RECOVERY: Duration = Duration::from_secs(5);

/// A grant belongs to one RSS claim round. The store can announce more durable
/// work as soon as it knows the result, before a slow claim finishes.
pub struct Grant {
    slots: Vec<Slot>,
    refill: Arc<Notify>,
    scan: OwnedSemaphorePermit,
}

pub async fn run<P, B>(
    budget: &Arc<Capacity>,
    policy: Policy,
    stop: &CancellationToken,
    notify: &Notify,
    page: impl Fn(Option<Uuid>) -> P,
    batch: impl Fn(Uuid, Grant, CancellationToken) -> B + Send + Sync + 'static,
) -> Result<(), Error>
where
    P: Future<Output = Result<Vec<Uuid>, ErrorKind>>,
    B: Future<Output = Result<Duration, Error>> + Send + 'static,
{
    let limit = NonZeroUsize::new(policy.concurrency())
        .expect("validated policy")
        .min(budget.limit());
    let window = budget.window(limit);
    let active = Arc::new(Mutex::new(
        std::collections::BTreeMap::<Uuid, Arc<Notify>>::new(),
    ));
    let registration_stop = stop.child_token();
    let batch = Arc::new(batch);
    let claim_limit = policy.claim_batch_size().min(limit.get());
    // One additional discovered tenant may wait for the next physical slot.
    super::run_fallible(
        limit.saturating_add(1),
        RECOVERY,
        &registration_stop,
        notify,
        (std::convert::identity, |after| {
            let future = page(after);
            let active = &active;
            async move {
                let rows = future.await.map_err(|kind| match kind {
                    ErrorKind::Transient | ErrorKind::Deadline => Failure::Retry,
                    _ => Failure::Fatal(Error::new(kind)),
                })?;
                // The durable page can announce new work while an earlier batch
                // still owns a slow claim. Coalesce those hints per active tenant.
                let running = active.lock().expect("active tenants");
                for tenant in &rows {
                    if let Some(refill) = running.get(tenant) { refill.notify_one(); }
                }
                Ok(rows)
            }
        }),
        |tenant, admission| {
            let budget = budget.clone();
            let batch = batch.clone();
            let registration_stop = registration_stop.clone();
            let active = active.clone();
            let admission = admission.child_token();
            let refill = Arc::new(Notify::new());
            active.lock().expect("active tenants").insert(tenant,refill.clone());
            let first = budget.acquire_within(tenant, claim_limit, window, &admission);
            async move {
                // Only one unclaimed round per tenant may be queued or inside claim_due.
                let scan = Arc::new(Semaphore::new(1));
                let attempt = |slots, permit| {
                    let (stop, batch, refill) = (admission.clone(), batch.clone(), refill.clone());
                    async move {
                        let slots: Vec<Slot> = slots.await;
                        if slots.is_empty() { return Ok(RECOVERY); }
                        batch(tenant, Grant { slots, refill, scan: permit }, stop).await
                    }
                };
                let mut attempts = FuturesUnordered::from_iter([attempt(first, scan.clone().try_acquire_owned().expect("initial scan"))]);
                let mut delay = RECOVERY;
                let mut failure = None;
                while !attempts.is_empty() {
                    tokio::select! {
                        biased;
                        result = attempts.next() => match result.expect("owned claim round") {
                            Ok(next) => delay = delay.min(next),
                            Err(error) => {
                                admission.cancel();
                                let classified = match error.kind() {
                                    ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown => Failure::Retry,
                                    _ => {
                                        registration_stop.cancel();
                                        Failure::Fatal(error)
                                    }
                                };
                                if !matches!(failure, Some(Failure::Fatal(_))) { failure = Some(classified); }
                            }
                        },
                        permit = async {
                            let permit = scan.clone().acquire_owned().await.expect("live scan gate");
                            refill.notified().await;
                            permit
                        }, if !admission.is_cancelled() => {
                            attempts.push(attempt(budget.acquire_within(tenant,claim_limit,window,&admission), permit));
                        }
                    }
                }
                active.lock().expect("active tenants").remove(&tenant);
                failure.map_or(Ok(delay), Err)
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
    grant: Grant,
    scope: &Scope,
    policy: Policy,
    stop: &CancellationToken,
    observe: impl FnMut(Observation) + Send,
) -> Result<Duration, Error> {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic execution clock boundary"
    )]
    let timer = BatchTimer(tokio::time::Instant::now());
    let force = CancellationToken::new();
    let control = Control::new(&timer, Duration::MAX, &force);
    let store = Admitted {
        store,
        round: Mutex::new(Some((grant.slots, grant.scan))),
        refill: grant.refill,
        next_scan: Mutex::new(None),
    };
    let report = rss_reconcile::run_batch(
        &store,
        &Delegate(reconciler),
        scope,
        policy,
        &control,
        stop,
        observe,
    )
    .await?;
    // A committed settlement owns the next useful scan. An immediate empty
    // scan would otherwise discard a short reobserve deadline until recovery.
    let next = store.next_scan.into_inner().expect("batch scan hint");
    Ok(next.map_or_else(
        || {
            if report.converged > 0 {
                Duration::ZERO
            } else {
                RECOVERY
            }
        },
        |due| due.saturating_sub(timer.now()),
    ))
}

struct Admitted<'a, S> {
    store: &'a S,
    round: Mutex<Option<(Vec<Slot>, OwnedSemaphorePermit)>>,
    refill: Arc<Notify>,
    next_scan: Mutex<Option<Duration>>,
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
        let (mut slots, _scan) = self
            .round
            .lock()
            .expect("claim round")
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
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
        if batch.more {
            self.refill.notify_one();
            *self.next_scan.lock().expect("batch scan hint") = Some(Duration::ZERO);
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
        let delay = match &completion {
            Completion::Reobserve(after)
            | Completion::Deferred(after)
            | Completion::Retry { after, .. } => Some(*after),
            _ => None,
        };
        self.store.finish(&claim.claim, completion, control).await?;
        if let Some(due) = delay.and_then(|after| control.elapsed().checked_add(after)) {
            let mut next = self.next_scan.lock().expect("batch scan hint");
            *next = Some(next.map_or(due, |previous| previous.min(due)));
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn rediscovery_refills_a_slow_tenant_and_a_fatal_refill_stops_admission() {
        let policy = Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 8,
            claim_batch_size: 8,
            scan_budget: 64,
            lease_ttl: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(6),
            scan_interval: Duration::from_millis(20),
            idle_scan_interval: RECOVERY,
            initial_backoff: RECOVERY,
            max_backoff: RECOVERY,
            max_attempts: 3,
        })
        .unwrap();
        let a = Uuid::from_u128(1);
        let budget = Capacity::new(NonZeroUsize::new(8).unwrap());
        let stop = CancellationToken::new();
        let notify = Notify::new();
        let (tx, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let rounds = Arc::new(AtomicUsize::new(0));
        let release = CancellationToken::new();
        let worker = run(
            &budget,
            policy,
            &stop,
            &notify,
            |after| std::future::ready(Ok(if after.is_none() { vec![a] } else { Vec::new() })),
            {
                let release = release.clone();
                move |_, mut grant, stop| {
                    let round = rounds.fetch_add(1, Ordering::SeqCst);
                    let (release, tx) = (release.clone(), tx.clone());
                    async move {
                        drop(grant.scan);
                        match round {
                            0 => {
                                grant.slots.truncate(1);
                                tx.send((round, grant.slots.len())).unwrap();
                                stop.cancelled().await;
                                tx.send((round, 0)).unwrap();
                                release.cancelled().await;
                                Ok(RECOVERY)
                            }
                            1 => {
                                tx.send((round, grant.slots.len())).unwrap();
                                Err(Error::new(ErrorKind::Invariant))
                            }
                            _ => panic!("claimed after fatal refill"),
                        }
                    }
                }
            },
        );
        let proof = async {
            assert_eq!(observed.recv().await, Some((0, 1)));
            notify.notify_one();
            assert_eq!(observed.recv().await, Some((1, 7)));
            assert_eq!(observed.recv().await, Some((0, 0)));
            release.cancel();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(worker, proof)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Invariant);
    }
}
