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
    state: Mutex<State>,
    changed: watch::Sender<()>,
}
#[derive(Default)]
struct State {
    active: usize,
    tenants: BTreeMap<Uuid, usize>,
    waiting: VecDeque<(Arc<()>, Uuid)>,
}

impl Capacity {
    pub fn new(limit: NonZeroUsize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::default(),
            changed: watch::channel(()).0,
        })
    }
    pub fn limit(&self) -> NonZeroUsize {
        self.limit
    }

    /// Prefer tenants with fewer executing items, keeping FIFO order for ties.
    /// One tenant cannot occupy the last slot of a multi-slot budget.
    pub async fn acquire(
        self: &Arc<Self>,
        tenant: Uuid,
        width: usize,
        stop: &CancellationToken,
    ) -> Vec<Slot> {
        if width == 0 {
            return Vec::new();
        }
        let mut changed = self.changed.subscribe();
        let ticket = Ticket {
            capacity: self,
            id: Arc::new(()),
        };
        let tenant_limit = self.limit.get().saturating_sub(1).max(1);
        self.state
            .lock()
            .expect("capacity state")
            .waiting
            .push_back((ticket.id.clone(), tenant));
        loop {
            {
                let mut state = self.state.lock().expect("capacity state");
                if stop.is_cancelled() {
                    return Vec::new();
                }
                let used = state.tenants.get(&tenant).copied().unwrap_or(0);
                let free = (self.limit.get() - state.active).min(tenant_limit - used);
                if free > 0
                    && state
                        .waiting
                        .iter()
                        .min_by_key(|(_, key)| state.tenants.get(key).copied().unwrap_or(0))
                        .is_some_and(|(id, _)| Arc::ptr_eq(id, &ticket.id))
                {
                    // Divide spare capacity among current contenders. An idle tenant
                    // merely listed on a discovery page has no claim on the budget.
                    let contenders = state
                        .waiting
                        .iter()
                        .map(|(_, key)| *key)
                        .filter(|key| state.tenants.get(key).copied().unwrap_or(0) < tenant_limit)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    let fair_share = (self.limit.get() - state.active).div_ceil(contenders);
                    let count = width.min(free).min(fair_share);
                    state.active += count;
                    *state.tenants.entry(tenant).or_default() += count;
                    return (0..count)
                        .map(|_| Slot {
                            capacity: self.clone(),
                            tenant,
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

struct Ticket<'a> {
    capacity: &'a Capacity,
    id: Arc<()>,
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        self.capacity
            .state
            .lock()
            .expect("capacity state")
            .waiting
            .retain(|(id, _)| !Arc::ptr_eq(id, &self.id));
        self.capacity.changed.send_replace(());
    }
}

pub struct Slot {
    capacity: Arc<Capacity>,
    tenant: Uuid,
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.capacity.state.lock().expect("capacity state");
        state.active -= 1;
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
    async fn a_late_tenant_can_work_while_all_hot_tenant_slots_are_held() {
        let budget = Capacity::new(NonZeroUsize::new(8).unwrap());
        let stop = CancellationToken::new();
        let tenant = Uuid::from_u128(1);
        let slots = budget.acquire(tenant, 8, &stop).await;
        assert_eq!(slots.len(), 7);
        let mut hot = Box::pin(budget.acquire(tenant, 1, &stop));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut hot)
                .await
                .is_err()
        );
        for peer in 2..=20 {
            let slots = budget.acquire(Uuid::from_u128(peer), 8, &stop).await;
            assert_eq!(slots.len(), 1);
        }
        stop.cancel();
        assert!(hot.await.is_empty());
        drop(slots);
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
