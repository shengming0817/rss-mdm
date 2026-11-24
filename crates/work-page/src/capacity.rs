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
    waiting: VecDeque<(Arc<()>, Uuid, Option<Window>)>,
}

/// A narrower registration participates in the same atomic grant as the host.
#[derive(Clone, Copy)]
pub(crate) struct Window {
    id: u64,
    limit: usize,
}

impl State {
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
        let mut changed = self.changed.subscribe();
        let stop = stop.clone();
        let ticket = Ticket {
            capacity: self.clone(),
            id: Arc::new(()),
        };
        let tenant_limit = self.per_tenant.get();
        if width > 0 && !stop.is_cancelled() {
            self.state
                .lock()
                .expect("capacity state")
                .waiting
                .push_back((ticket.id.clone(), tenant, window));
        }
        async move {
            if width == 0 {
                return Vec::new();
            }
            let capacity = &ticket.capacity;
            loop {
                {
                    let mut state = capacity.state.lock().expect("capacity state");
                    if stop.is_cancelled() {
                        return Vec::new();
                    }
                    let free = (capacity.limit.get() - state.active).min(state.available(
                        tenant,
                        window,
                        tenant_limit,
                    ));
                    let mut eligible = state
                        .waiting
                        .iter()
                        .filter(|(_, t, w)| state.available(*t, *w, tenant_limit) > 0);
                    if free > 0
                        && eligible
                            .clone()
                            .min_by_key(|(_, t, _)| {
                                (
                                    state.tenants.get(t).copied().unwrap_or(0),
                                    Some(*t) == state.last,
                                )
                            })
                            .is_some_and(|(id, _, _)| Arc::ptr_eq(id, &ticket.id))
                    {
                        let contenders = eligible
                            .by_ref()
                            .map(|(_, tenant, _)| *tenant)
                            .collect::<std::collections::BTreeSet<_>>()
                            .len();
                        let fair_share = (capacity.limit.get() - state.active).div_ceil(contenders);
                        let count = width.min(free).min(fair_share);
                        state.last = Some(tenant);
                        state.active += count;
                        if let Some(w) = window {
                            *state.windows.entry(w.id).or_default() += count;
                        }
                        *state.tenants.entry(tenant).or_default() += count;
                        return (0..count)
                            .map(|_| Slot {
                                capacity: capacity.clone(),
                                tenant,
                                window,
                            })
                            .collect();
                    }
                }
                tokio::select! {
                    () = stop.cancelled() => return Vec::new(),
                    result = changed.changed() => result.expect("live capacity"),
                }
            }
        }
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
            .retain(|(id, _, _)| !Arc::ptr_eq(id, &self.id));
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
