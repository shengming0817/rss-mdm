//! Execution slots shared by all production registrations using one physical budget.
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct Capacity {
    limit: NonZeroUsize,
    per_tenant: NonZeroUsize,
    state: Mutex<State>,
    changed: watch::Sender<()>,
}
#[derive(Default)]
struct State {
    active: usize,
    last: Option<Uuid>,
    tenants: BTreeMap<Uuid, usize>,
    windows: BTreeMap<u64, usize>,
    next_window: u64,
    waiting: VecDeque<Waiter>,
}

struct Waiter {
    id: Arc<()>,
    tenant: Uuid,
    window: Option<Window>,
    database: Option<Arc<Capacity>>,
}

/// A narrower registration participates in the same atomic grant as the host.
#[derive(Clone, Copy)]
pub(crate) struct Window {
    id: u64,
    limit: usize,
}

impl State {
    fn record(&mut self, tenant: Uuid, window: Option<Window>, count: usize) {
        self.active += count;
        self.last = Some(tenant);
        *self.tenants.entry(tenant).or_default() += count;
        if let Some(w) = window {
            *self.windows.entry(w.id).or_default() += count;
        }
    }
    fn available(&self, tenant: Uuid, window: Option<Window>, per_tenant: usize) -> usize {
        let tenant_free = per_tenant - self.tenants.get(&tenant).copied().unwrap_or(0);
        window.map_or(tenant_free, |w| {
            tenant_free.min(w.limit - self.windows.get(&w.id).copied().unwrap_or(0))
        })
    }
}

impl Capacity {
    pub fn new(limit: NonZeroUsize) -> Arc<Self> {
        Self::with_tenant_limit(limit, limit)
    }
    pub(crate) fn with_tenant_limit(limit: NonZeroUsize, per_tenant: NonZeroUsize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            per_tenant,
            state: Mutex::default(),
            changed: watch::channel(()).0,
        })
    }
    pub fn limit(&self) -> NonZeroUsize {
        self.limit
    }

    pub(crate) fn window(&self, limit: NonZeroUsize) -> Option<Window> {
        if limit >= self.limit {
            return None;
        }
        let mut state = self.state.lock().expect("capacity state");
        state.next_window += 1;
        Some(Window {
            id: state.next_window,
            limit: limit.get(),
        })
    }

    /// Prefer tenants with fewer executing items, keeping FIFO order for ties.
    /// At equal usage give another waiting tenant a turn before repeating the last grant.
    pub fn acquire(
        self: &Arc<Self>,
        tenant: Uuid,
        width: usize,
        stop: &CancellationToken,
    ) -> impl Future<Output = Vec<Slot>> + Send + use<> {
        self.acquire_within(tenant, width, None, stop)
    }

    pub(crate) fn acquire_within(
        self: &Arc<Self>,
        tenant: Uuid,
        width: usize,
        window: Option<Window>,
        stop: &CancellationToken,
    ) -> impl Future<Output = Vec<Slot>> + Send + use<> {
        let requested = self.request(tenant, width, window, None, stop);
        async move { requested.await.0 }
    }

    // The only nested lock order is execution -> physical database. Ordinary
    // database operations never depend on execution slots. A waiting claim is
    // eligible in the execution queue only while its database can admit it.
    pub(crate) fn request(
        self: &Arc<Self>,
        tenant: Uuid,
        width: usize,
        window: Option<Window>,
        database: Option<Arc<Capacity>>,
        stop: &CancellationToken,
    ) -> impl Future<Output = (Vec<Slot>, Option<Slot>)> + Send + use<> {
        let mut changed = self.changed.subscribe();
        let mut db_changed = database.as_ref().map(|db| db.changed.subscribe());
        let stop = stop.clone();
        let ticket = Ticket {
            capacity: self.clone(),
            id: Arc::new(()),
        };
        if width > 0 && !stop.is_cancelled() {
            self.state
                .lock()
                .expect("capacity state")
                .waiting
                .push_back(Waiter {
                    id: ticket.id.clone(),
                    tenant,
                    window,
                    database: database.clone(),
                });
        }
        async move {
            while width > 0 && !stop.is_cancelled() {
                if let Some(grant) =
                    ticket
                        .capacity
                        .grant(&ticket.id, tenant, width, window, database.as_ref())
                {
                    return grant;
                }
                tokio::select! {
                    ()=stop.cancelled()=>break,
                    result=changed.changed()=>result.expect("live capacity"),
                    _=async { db_changed.as_mut().expect("coupled claim").changed().await.expect("live database") }, if db_changed.is_some()=>{
                        ticket.capacity.changed.send_replace(());
                    }
                }
            }
            (Vec::new(), None)
        }
    }

    fn grant(
        self: &Arc<Self>,
        id: &Arc<()>,
        tenant: Uuid,
        width: usize,
        window: Option<Window>,
        database: Option<&Arc<Capacity>>,
    ) -> Option<(Vec<Slot>, Option<Slot>)> {
        let mut state = self.state.lock().expect("capacity state");
        let free = self.limit.get() - state.active;
        if free == 0 {
            return None;
        }
        let mut contenders = std::collections::BTreeSet::new();
        let next = state
            .waiting
            .iter()
            .filter(|w| {
                state.available(w.tenant, w.window, self.per_tenant.get()) > 0
                    && w.database.as_ref().is_none_or(|db| {
                        db.connection_available(
                            w.tenant,
                            &db.state.lock().expect("database capacity"),
                        )
                    })
            })
            .inspect(|w| {
                contenders.insert(w.tenant);
            })
            .min_by_key(|w| {
                (
                    state.tenants.get(&w.tenant).copied().unwrap_or(0),
                    Some(w.tenant) == state.last,
                )
            })?;
        if !Arc::ptr_eq(&next.id, id) {
            return None;
        }
        let connection = match database {
            Some(db) => Some(db.try_connection(tenant)?),
            None => None,
        };
        let count = width
            .min(free.div_ceil(contenders.len()))
            .min(state.available(tenant, window, self.per_tenant.get()));
        state.record(tenant, window, count);
        Some((
            (0..count)
                .map(|_| Slot {
                    capacity: self.clone(),
                    tenant,
                    window,
                })
                .collect(),
            connection,
        ))
    }

    fn connection_available(&self, tenant: Uuid, state: &State) -> bool {
        state.active < self.limit.get()
            && state.available(tenant, None, self.per_tenant.get()) > 0
            && !state
                .waiting
                .iter()
                .any(|w| state.available(w.tenant, w.window, self.per_tenant.get()) > 0)
    }

    pub(crate) fn try_connection(self: &Arc<Self>, tenant: Uuid) -> Option<Slot> {
        let mut state = self.state.lock().expect("database capacity");
        if !self.connection_available(tenant, &state) {
            return None;
        }
        state.record(tenant, None, 1);
        Some(Slot {
            capacity: self.clone(),
            tenant,
            window: None,
        })
    }
}

struct Ticket {
    capacity: Arc<Capacity>,
    id: Arc<()>,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.capacity
            .state
            .lock()
            .expect("capacity state")
            .waiting
            .retain(|waiter| !Arc::ptr_eq(&waiter.id, &self.id));
        self.capacity.changed.send_replace(());
    }
}

pub struct Slot {
    capacity: Arc<Capacity>,
    tenant: Uuid,
    window: Option<Window>,
}
impl Slot {
    pub(crate) fn origin(&self) -> (Arc<Capacity>, Uuid, Option<Window>) {
        (self.capacity.clone(), self.tenant, self.window)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.capacity.state.lock().expect("capacity state");
        state.active -= 1;
        if let Some(w) = self.window {
            let n = state.windows.get_mut(&w.id).expect("admitted registration");
            *n -= 1;
            if *n == 0 {
                state.windows.remove(&w.id);
            }
        }
        let count = state
            .tenants
            .get_mut(&self.tenant)
            .expect("admitted tenant");
        *count -= 1;
        if *count == 0 {
            state.tenants.remove(&self.tenant);
        }
        self.capacity.changed.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_discovered_peer_wins_the_next_released_slot() {
        for limit in [1, 2, 8] {
            let budget = Capacity::new(NonZeroUsize::new(limit).unwrap());
            let stop = CancellationToken::new();
            let tenant = Uuid::from_u128(1);
            let mut slots = budget.acquire(tenant, 8, &stop).await;
            assert_eq!(slots.len(), limit);
            let mut hot = Box::pin(budget.acquire(tenant, 1, &stop));
            let mut peer = Box::pin(budget.acquire(Uuid::from_u128(2), 8, &stop));
            assert!(futures::poll!(&mut hot).is_pending());
            assert!(futures::poll!(&mut peer).is_pending());
            drop(slots.pop().unwrap());
            assert!(futures::poll!(&mut hot).is_pending());
            let peer = peer.await;
            assert_eq!(peer.len(), 1);
            stop.cancel();
            assert!(hot.await.is_empty());
        }
    }
    #[tokio::test]
    async fn a_host_waiter_does_not_reserve_a_narrow_registration() {
        let host = Capacity::new(NonZeroUsize::new(8).unwrap());
        let narrow = host.window(NonZeroUsize::MIN);
        let stop = CancellationToken::new();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut held = host.acquire(a, 8, &stop).await;
        let mut hot = Box::pin(host.acquire_within(a, 1, narrow, &stop));
        let peer = host.acquire_within(b, 1, narrow, &stop);
        assert!(futures::poll!(&mut hot).is_pending());
        drop(held.pop().unwrap());
        let peer = peer.await;
        assert_eq!(peer.len(), 1);
        drop(held.pop().unwrap());
        assert!(futures::poll!(&mut hot).is_pending());
        drop(peer);
        assert_eq!(hot.await.len(), 1);
    }
    #[tokio::test]
    async fn blocked_database_tickets_take_neither_budget_and_wake_after_release() {
        let host = Capacity::new(NonZeroUsize::new(8).unwrap());
        let db = Capacity::with_tenant_limit(NonZeroUsize::new(2).unwrap(), NonZeroUsize::MIN);
        let stop = CancellationToken::new();
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let settlement = db.acquire(a, 1, &stop).await;
        let mut hot = Box::pin(host.request(a, 8, None, Some(db.clone()), &stop));
        assert!(futures::poll!(&mut hot).is_pending());
        let (slots, connection) = host.request(b, 8, None, Some(db.clone()), &stop).await;
        assert_eq!(slots.len(), 8);
        assert!(connection.is_some());
        drop(settlement);
        assert!(futures::poll!(&mut hot).is_pending());
        drop((slots, connection));
        assert_eq!(hot.await.0.len(), 8);
    }

    #[tokio::test]
    async fn capacity_one_serializes_all_registrations() {
        let budget = Capacity::new(NonZeroUsize::MIN);
        let stop = CancellationToken::new();
        let held = budget.acquire(Uuid::from_u128(1), 8, &stop).await;
        let mut peer = Box::pin(budget.acquire(Uuid::from_u128(2), 8, &stop));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut peer)
                .await
                .is_err()
        );
        drop(held);
        assert_eq!(peer.await.len(), 1);
    }
}
