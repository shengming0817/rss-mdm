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
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RECOVERY: Duration = Duration::from_secs(5);

/// Execution permits for a single bounded RSS claim round.
pub struct Grant {
    slots: Vec<Slot>,
    round: Arc<Round>,
}

// One registration owns one reconciler domain. Positions execute claims, while
// the tenant retains all acknowledged wake times across position reuse.
#[derive(Default)]
struct Tenant {
    active: BTreeSet<usize>,
    discovered: bool,
    claiming: Option<usize>,
    // An entity belongs to exactly one scope in this registration.
    deadlines: BTreeSet<(Instant, Arc<str>)>,
    by_entity: BTreeMap<Arc<str>, Instant>,
    in_flight: BTreeMap<Arc<str>, usize>,
    sweep_start: Option<Instant>,
    previous_sweep: Option<Instant>,
    immediate: bool,
    recovery: Option<Instant>,
    retry: Option<Instant>,
}
impl Tenant {
    fn next(&self, now: Instant) -> Instant {
        if let Some(retry) = self.retry.filter(|at| *at > now) {
            return retry;
        }
        if self.immediate {
            return now;
        }
        self.recovery
            .into_iter()
            .chain(self.deadlines.first().map(|(at, _)| *at))
            .min()
            .unwrap_or(now)
    }
}
struct Round {
    tenant: Uuid,
    position: usize,
    running: Arc<Mutex<BTreeMap<Uuid, Tenant>>>,
    rescan: Arc<Notify>,
}
#[allow(
    clippy::disallowed_methods,
    reason = "monotonic tenant claim deadlines"
)]
impl Round {
    fn claimed(&self, more: bool) {
        let mut running = self.running.lock().expect("active claim rounds");
        let tenant = running.get_mut(&self.tenant).expect("active tenant");
        tenant.claiming = None;
        let now = Instant::now();
        tenant.recovery = Some(now + RECOVERY);
        tenant.immediate |= more;
        // A page scanned before this claim finished may have slept with the
        // previous earliest deadline (or none, while an immediate scan was pending).
        if tenant.next(now) <= now || !tenant.deadlines.is_empty() {
            self.rescan.notify_one();
        }
    }
    fn request_scan(&self) {
        let mut running = self.running.lock().expect("active claim rounds");
        running
            .get_mut(&self.tenant)
            .expect("active tenant")
            .immediate = true;
        self.rescan.notify_one();
    }
}
impl Drop for Round {
    #[allow(
        clippy::disallowed_methods,
        reason = "reconsider due work when a position drains"
    )]
    fn drop(&mut self) {
        let mut running = self.running.lock().expect("active claim rounds");
        let tenant = running.get_mut(&self.tenant).expect("active tenant");
        tenant.active.remove(&self.position);
        tenant.in_flight.retain(|_, owner| *owner != self.position);
        if tenant.claiming == Some(self.position) {
            tenant.claiming = None;
        }
        let now = Instant::now();
        if tenant.next(now) <= now {
            self.rescan.notify_one();
        }
    }
}

// Only the provider knows when the physical claim started and which completion
// reached storage after the domain's settlement wrapper. Scope these callbacks
// to the owning batch, including during RSS's concurrent attempt polling.
tokio::task_local! { static CURRENT: (Scope, Arc<Round>); }

pub(crate) fn scanned<'a>(
    scope: &Scope,
    started: Instant,
    more: bool,
    claims: impl Iterator<Item = &'a Target>,
) {
    let _ = CURRENT.try_with(|(owner, round)| {
        if owner == scope {
            let mut running = round.running.lock().expect("active claim rounds");
            let tenant = running.get_mut(&round.tenant).expect("active tenant");
            // Physical claims are serialized per scope until Round::claimed. Older
            // positions may still be waiting for their finish acknowledgement.
            for target in claims {
                let entity = target.entity();
                if let Some((key, at)) = tenant.by_entity.remove_entry(entity) {
                    tenant.deadlines.remove(&(at, key));
                }
                tenant.in_flight.insert(Arc::from(entity), round.position);
            }
            // A tail page cannot cover a ticket behind its cursor or beyond its
            // high-water mark. Only retire through the start of the whole sweep.
            let start = *tenant.sweep_start.get_or_insert(started);
            if more {
                return;
            }
            tenant.sweep_start = None;
            // Even a nonempty terminal page may resume a peer's cursor or skip
            // a locked row. Give each due hint one fresh pass through the fair
            // queue. Persistent contention is handled by normal idle recovery.
            let through = tenant.previous_sweep.replace(start);
            while tenant
                .deadlines
                .first()
                .is_some_and(|(at, _)| through.is_some_and(|end| *at <= end))
            {
                let (_, entity) = tenant.deadlines.pop_first().expect("present deadline");
                tenant.by_entity.remove(&entity);
            }
        }
    });
}

#[allow(
    clippy::disallowed_methods,
    reason = "monotonic acknowledged settlement deadline"
)]
pub(crate) fn settled(target: &Target, completion: Option<Completion>) {
    let _ = CURRENT.try_with(|(owner, round)| {
        if owner != target.scope() {
            return;
        }
        let mut running = round.running.lock().expect("active claim rounds");
        let tenant = running.get_mut(&round.tenant).expect("active tenant");
        if tenant.in_flight.get(target.entity()) != Some(&round.position) {
            return;
        }
        let (entity, _) = tenant
            .in_flight
            .remove_entry(target.entity())
            .expect("owned claim");
        let Some(
            Completion::Reobserve(after)
            | Completion::Deferred(after)
            | Completion::Retry { after, .. },
        ) = completion
        else {
            return;
        };
        let now = Instant::now();
        if let Some(at) = now.checked_add(after) {
            let previous = tenant.next(now);
            tenant.deadlines.insert((at, entity.clone()));
            tenant.by_entity.insert(entity, at);
            if at < previous {
                round.rescan.notify_one();
            }
        }
    });
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
    B: Future<Output = Result<(), Error>> + Send + 'static,
{
    let limit = NonZeroUsize::new(policy.concurrency())
        .expect("validated policy")
        .min(budget.limit());
    let window = budget.window(limit);
    let width = policy.claim_batch_size().min(limit.get());
    let running = Arc::new(Mutex::new(BTreeMap::<Uuid, Tenant>::new()));
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
                ()=notify.notified()=>{
                    for tenant in running.lock().expect("active claim rounds").values_mut() {
                        tenant.immediate = true;
                    }
                },
                ()=rescan.notified()=>{},
            }
            false
        },
        (
            |&(tenant, position): &(Uuid, usize)| {
                super::Work::independent(tenant, (tenant, position))
            },
            |after: Option<(Uuid, usize)>| {
                let page = page(after.map(|(tenant, _)| tenant));
                let running = &running;
                async move {
                    let tenants = page.await.map_err(|kind| match kind {
                        ErrorKind::Transient | ErrorKind::Deadline => Failure::Retry,
                        _ => Failure::Fatal(Error::new(kind)),
                    })?;
                    let after = tenants.last().map(|t| (*t, 0));
                    let now = Instant::now();
                    let mut active = running.lock().expect("active claim rounds");
                    if after.is_none() {
                        // Only retire absent scopes. A discovered tenant can still
                        // be waiting in the fair queue after every deadline elapsed.
                        active.retain(|_, tenant| {
                            std::mem::take(&mut tenant.discovered)
                                || !tenant.active.is_empty()
                                || tenant.deadlines.last().is_some_and(|(at, _)| *at > now)
                                || tenant.retry.is_some_and(|at| at > now)
                        });
                    }
                    let mut next = None;
                    let rows = tenants
                        .into_iter()
                        .filter_map(|id| {
                            let Some(tenant) = active.get_mut(&id) else {
                                return Some((id, 0));
                            };
                            tenant.discovered = true;
                            let at = tenant.next(now);
                            if at > now {
                                next = Some(next.map_or(at, |old: Instant| old.min(at)));
                                return None;
                            }
                            if tenant.claiming.is_some() || tenant.active.len() >= limit.get() {
                                return None;
                            }
                            (0..=tenant.active.len())
                                .find(|position| !tenant.active.contains(position))
                                .map(|position| (id, position))
                        })
                        .collect();
                    Ok(super::Page { rows, after, next })
                }
            },
        ),
        |(tenant, position), admission| {
            let mut active = running.lock().expect("active claim rounds");
            let state = active.entry(tenant).or_default();
            let now = Instant::now();
            // Admission may retain a candidate while another position scans or backs off.
            let round = (state.next(now) <= now
                && state.claiming.is_none()
                && !state.active.contains(&position))
            .then(|| {
                state.discovered = true;
                state.active.insert(position);
                state.claiming = Some(position);
                state.immediate = false;
                Arc::new(Round {
                    tenant,
                    position,
                    running: running.clone(),
                    rescan: rescan.clone(),
                })
            });
            drop(active);
            let requested = round.map(|round| {
                (
                    round,
                    budget.acquire_within(tenant, width, window, &admission),
                )
            });
            let batch = batch.clone();
            async move {
                let Some((round, requested)) = requested else {
                    return Ok(None);
                };
                let slots = requested.await;
                if slots.is_empty() {
                    return Ok(None);
                }
                if round.running.lock().expect("active claim rounds")[&tenant]
                    .retry
                    .is_some_and(|at| at > Instant::now())
                {
                    return Ok(None);
                }
                match batch(
                    tenant,
                    Grant {
                        slots,
                        round: round.clone(),
                    },
                    admission,
                )
                .await
                {
                    Ok(()) => Ok(None),
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown
                        ) =>
                    {
                        let mut running = round.running.lock().expect("active claim rounds");
                        let state = running.get_mut(&tenant).expect("active tenant");
                        state.retry = Some(Instant::now() + RECOVERY);
                        state.immediate = true;
                        round.rescan.notify_one();
                        Ok(None)
                    }
                    Err(error) => Err(Failure::Fatal(error)),
                }
            }
        },
        |_| {},
    )
    .await
}

/// RSS owns claims, attempts, renewal and settlement. Move the capacity slot
/// with that exact claim so unrelated completions can refill the budget.
///
/// For timed wakes, the store must forward physical claims and final settlements
/// to [Scheduler](super::scheduler::Scheduler), including any domain-adjusted completion.
/// Other stores receive notifications, pagination and the five-second recovery scan;
/// their delayed completions do not publish a local deadline.
pub async fn batch<S: DurableStore, R: Reconciler<S::Claim>>(
    (store, reconciler): (&S, &R),
    grant: Grant,
    scope: &Scope,
    policy: Policy,
    stop: &CancellationToken,
    observe: impl FnMut(Observation) + Send,
) -> Result<(), Error> {
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
    };
    let delegate = Delegate(reconciler);
    let execution =
        rss_reconcile::run_batch(&store, &delegate, scope, policy, &control, stop, observe);
    let report = CURRENT
        .scope((scope.clone(), store.round.clone()), execution)
        .await?;
    // A confirmed deferral releases the same resource hold as convergence. Give other
    // due tickets a chance before this target reaches its own reobservation deadline.
    if report.converged > 0 || report.deferred > 0 {
        store.round.request_scan();
    }
    Ok(())
}

struct Admitted<'a, S> {
    store: &'a S,
    slots: Mutex<Vec<Slot>>,
    round: Arc<Round>,
    stop: CancellationToken,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    mod deadlines;

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
                                Ok(())
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
                    // Model a real claim holding execution capacity until settlement.
                    drop(grant);
                    Ok(())
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
