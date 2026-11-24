//! Bounded tenant discovery for the host's RSS reconciliation registrations.
use super::{
    Failure,
    capacity::{Capacity, Slot},
};
use rss_reconcile::{
    Claim, ClaimBatch, Completion, Control, DurableStore, Error, ErrorKind, Observation, Policy,
    ReconcileDiff, ReconcileStep, Reconciler, ResourceSet, Scope, Target, Timer,
};
use std::collections::{BTreeMap, BTreeSet};
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

/// Execution permits for a single bounded RSS claim round.
pub struct Grant {
    slots: Vec<Slot>,
    round: Arc<Round>,
}

#[derive(Default)]
struct Positions {
    active: BTreeSet<usize>,
    claiming: Option<usize>,
}
struct Round {
    tenant: Uuid,
    position: usize,
    running: Arc<Mutex<BTreeMap<Uuid, Positions>>>,
    rescan: Arc<Notify>,
}
impl Round {
    fn claimed(&self, more: bool) {
        let mut running = self.running.lock().expect("active claim rounds");
        let positions = running.get_mut(&self.tenant).expect("active tenant");
        if positions.claiming == Some(self.position) {
            positions.claiming = None;
        }
        if more {
            self.rescan.notify_one();
        }
    }
}
impl Drop for Round {
    fn drop(&mut self) {
        let mut running = self.running.lock().expect("active claim rounds");
        let positions = running.get_mut(&self.tenant).expect("active tenant");
        positions.active.remove(&self.position);
        if positions.claiming == Some(self.position) {
            positions.claiming = None;
        }
        if positions.active.is_empty() {
            running.remove(&self.tenant);
        }
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "retry deadlines shared across a tenant's claim rounds"
)]
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
    let width = policy.claim_batch_size().min(limit.get());
    let running = Arc::new(Mutex::new(BTreeMap::<Uuid, Positions>::new()));
    let retry_at = Arc::new(Mutex::new(BTreeMap::<Uuid, tokio::time::Instant>::new()));
    let rescan = Arc::new(Notify::new());
    let batch = Arc::new(batch);
    // Each local position owns exactly one RSS round. A hot tenant must re-enter the
    // same ready queue as newly discovered peers before it can reserve another batch.
    super::run_pages(
        limit.saturating_add(1),
        RECOVERY,
        stop,
        || async {
            tokio::select! {
                ()=notify.notified()=>true,
                ()=rescan.notified()=>false,
            }
        },
        (
            |&(tenant, position): &(Uuid, usize)| {
                super::Work::independent(tenant, (tenant, position))
            },
            |after: Option<(Uuid, usize)>| {
                let page = page(after.map(|(tenant, _)| tenant));
                let running = &running;
                let retry_at = &retry_at;
                async move {
                    let tenants = page.await.map_err(|kind| match kind {
                        ErrorKind::Transient | ErrorKind::Deadline => Failure::Retry,
                        _ => Failure::Fatal(Error::new(kind)),
                    })?;
                    let after = tenants.last().map(|t| (*t, 0));
                    let active = running.lock().expect("active claim rounds");
                    let now = tokio::time::Instant::now();
                    let mut retries = retry_at.lock().expect("scope retry deadlines");
                    retries.retain(|_, due| *due > now);
                    let next = retries.values().min().copied();
                    let rows = tenants
                        .into_iter()
                        .filter_map(|tenant| {
                            if retries.contains_key(&tenant) {
                                return None;
                            }
                            let Some(positions) = active.get(&tenant) else {
                                return Some((tenant, 0));
                            };
                            if positions.claiming.is_some() || positions.active.len() >= limit.get()
                            {
                                return None;
                            }
                            (0..=positions.active.len())
                                .find(|p| !positions.active.contains(p))
                                .map(|p| (tenant, p))
                        })
                        .collect();
                    Ok(super::Page { rows, after, next })
                }
            },
        ),
        |(tenant, position), admission| {
            let mut active = running.lock().expect("active claim rounds");
            let positions = active.entry(tenant).or_default();
            positions.active.insert(position);
            positions.claiming = Some(position);
            drop(active);
            let round = Arc::new(Round {
                tenant,
                position,
                running: running.clone(),
                rescan: rescan.clone(),
            });
            let requested = budget.acquire_within(tenant, width, window, &admission);
            let batch = batch.clone();
            let retry_at = retry_at.clone();
            async move {
                if let Some(due) = retry_at.lock().expect("scope retry deadlines").get(&tenant)
                    && *due > tokio::time::Instant::now()
                {
                    return Ok(due.saturating_duration_since(tokio::time::Instant::now()));
                }
                let slots = requested.await;
                if slots.is_empty() {
                    return Ok(RECOVERY);
                }
                let result = batch(
                    tenant,
                    Grant {
                        slots,
                        round: round.clone(),
                    },
                    admission,
                )
                .await;
                drop(round);
                result.map_err(|error| match error.kind() {
                    ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown => {
                        retry_at
                            .lock()
                            .expect("scope retry deadlines")
                            .insert(tenant, tokio::time::Instant::now() + RECOVERY);
                        Failure::Retry
                    }
                    _ => Failure::Fatal(error),
                })
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
        slots: Mutex::new(grant.slots),
        round: grant.round,
        stop: stop.clone(),
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
    slots: Mutex<Vec<Slot>>,
    round: Arc<Round>,
    stop: CancellationToken,
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
        let mut slots = std::mem::take(&mut *self.slots.lock().expect("claim round"));
        slots.truncate(limit);
        if slots.is_empty() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        let query = self
            .store
            .claim_due(scope, slots.len(), scan_budget, lease, control);
        let (result, slots) =
            super::scheduler::with_execution_slots(slots, self.stop.clone(), query).await;
        let batch = result?;
        self.round.claimed(batch.more);
        if batch.claims.len() > slots.len() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        if batch.more {
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

    fn test_policy(width: usize) -> Policy {
        Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: width,
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
        .unwrap()
    }

    #[tokio::test]
    async fn rediscovery_refills_a_slow_tenant_and_a_fatal_refill_stops_admission() {
        let policy = test_policy(8);
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
                        grant.round.claimed(false);
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
    #[tokio::test]
    async fn hot_scopes_yield_registration_positions_to_later_pages() {
        let limit = NonZeroUsize::MIN;
        let host = Capacity::new(limit);
        let stop = CancellationToken::new();
        let notify = Notify::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let worker = run(
            &host,
            test_policy(1),
            &stop,
            &notify,
            |after: Option<Uuid>| {
                let after = after.map_or(0, |t| t.as_u128());
                std::future::ready(Ok((1..=35)
                    .filter(|id| *id > after)
                    .take(32)
                    .map(Uuid::from_u128)
                    .collect()))
            },
            move |tenant, grant, _| {
                let tx = tx.clone();
                async move {
                    let hot = matches!(tenant.as_u128(), 1 | 2 | 35);
                    grant.round.claimed(hot);
                    if hot {
                        let (release, wait) = tokio::sync::oneshot::channel();
                        tx.send((tenant.as_u128(), release)).unwrap();
                        let _ = wait.await;
                    }
                    Ok(if hot { Duration::ZERO } else { RECOVERY })
                }
            },
        );
        let proof = async {
            let mut served = BTreeSet::new();
            for _ in 0..12 {
                let (tenant, release) = rx.recv().await.unwrap();
                served.insert(tenant);
                if served.len() == 3 {
                    stop.cancel();
                    drop(release);
                    return;
                }
                release.send(()).unwrap();
            }
            panic!("late hot scope starved: {served:?}");
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(worker, proof)
        })
        .await
        .unwrap();
        result.unwrap();
    }
}
