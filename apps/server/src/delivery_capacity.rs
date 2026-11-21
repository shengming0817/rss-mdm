//! Process-local admission for independently settled outbox heads.
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Binding {
    owner: &'static str,
    tenant: Uuid,
}

pub(crate) struct Capacity {
    total: usize,
    owner: usize,
    tenant: usize,
    binding: usize,
    state: Mutex<State>,
    changed: watch::Sender<()>,
}
#[derive(Default)]
struct State {
    active: Vec<Binding>,
    waiting: VecDeque<(Arc<()>, Binding)>,
}

pub(crate) const PROJECTION_SLOTS: usize = 3;
pub(crate) const PROJECTION_CONNECTIONS: u32 = PROJECTION_SLOTS as u32 + 1;

impl Capacity {
    fn new(total: usize, owner: usize, tenant: usize, binding: usize) -> Arc<Self> {
        Arc::new(Self {
            total,
            owner,
            tenant,
            binding,
            state: Mutex::default(),
            changed: watch::channel(()).0,
        })
    }
    pub(crate) fn projection() -> Arc<Self> {
        Self::new(PROJECTION_SLOTS, PROJECTION_SLOTS, 2, 2)
    }
    pub(crate) fn command_limits(parallelism: NonZeroUsize) -> (usize, usize) {
        let total = parallelism.get().min(4);
        (total, total.min(3))
    }
    pub(crate) fn commands(parallelism: NonZeroUsize) -> Arc<Self> {
        let (total, owner) = Self::command_limits(parallelism);
        let binding = total.saturating_sub(1).clamp(1, 2);
        Self::new(total, owner, total.min(3), binding)
    }
    pub(crate) fn total(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.total).expect("positive execution capacity")
    }
    pub(crate) fn batches_per_binding(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.binding).expect("positive binding capacity")
    }
    fn available(&self, state: &State, key: Binding) -> usize {
        let used = &state.active;
        (self.total - used.len())
            .min(self.owner - used.iter().filter(|v| v.owner == key.owner).count())
            .min(self.tenant - used.iter().filter(|v| v.tenant == key.tenant).count())
            .min(self.binding - used.iter().filter(|v| **v == key).count())
    }
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        owner: &'static str,
        tenant: Uuid,
        stop: &CancellationToken,
    ) -> Option<Vec<Slot>> {
        let key = Binding { owner, tenant };
        let mut changed = self.changed.subscribe();
        let ticket = Arc::new(());
        self.state
            .lock()
            .expect("admission state")
            .waiting
            .push_back((ticket.clone(), key));
        loop {
            {
                let mut state = self.state.lock().expect("admission state");
                if stop.is_cancelled() {
                    state.waiting.retain(|(id, _)| !Arc::ptr_eq(id, &ticket));
                    self.changed.send_replace(());
                    return None;
                }
                // Skip saturated owners/tenants without giving a hot binding priority
                // over an older admissible waiter.
                let next = state
                    .waiting
                    .iter()
                    .position(|(_, k)| self.available(&state, *k) > 0);
                if let Some(index) = next
                    && Arc::ptr_eq(&ticket, &state.waiting[index].0)
                {
                    state.waiting.remove(index);
                    let count = self.available(&state, key);
                    state.active.extend(std::iter::repeat_n(key, count));
                    self.changed.send_replace(());
                    return Some(
                        (0..count)
                            .map(|_| Slot {
                                budget: self.clone(),
                                key,
                            })
                            .collect(),
                    );
                }
            }
            tokio::select! {
                () = stop.cancelled() => {},
                value = changed.changed() => value.expect("live admission budget"),
            }
        }
    }
}
pub(crate) struct Slot {
    budget: Arc<Capacity>,
    key: Binding,
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().expect("admission state");
        let index = state
            .active
            .iter()
            .position(|key| *key == self.key)
            .expect("owned slot");
        state.active.swap_remove(index);
        self.budget.changed.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn command_limits_reserve_capacity_for_other_owners_and_tenants() {
        let stop = CancellationToken::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        for (parallelism, total, binding) in
            [(1, 1, 1), (2, 2, 1), (3, 3, 2), (4, 4, 2), (16, 4, 2)]
        {
            let capacity = Capacity::commands(NonZeroUsize::new(parallelism).unwrap());
            assert_eq!(capacity.total().get(), total);
            let held = capacity.acquire("script", a, &stop).await.unwrap();
            assert_eq!(held.len(), binding);
            let waiting = capacity.acquire("script", a, &stop);
            tokio::pin!(waiting);
            assert!(futures::poll!(&mut waiting).is_pending());
            if binding < total {
                let peer = capacity.acquire("inventory", a, &stop).await.unwrap();
                assert_eq!(peer.len(), (total - binding).min(3 - binding));
                if total == 4 {
                    let late = capacity.acquire("script", b, &stop).await.unwrap();
                    assert_eq!(late.len(), 1);
                }
            }
            drop(held);
            assert_eq!(waiting.await.unwrap().len(), binding);
        }
    }
    #[tokio::test]
    async fn projection_refills_one_returned_slot_and_cancels_queued_claims() {
        let stop = CancellationToken::new();
        let capacity = Capacity::projection();
        let tenant = Uuid::from_u128(1);
        let mut held = capacity.acquire("groups", tenant, &stop).await.unwrap();
        let pending = capacity.acquire("groups", tenant, &stop);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
        drop(held.pop());
        let refill = pending.await.unwrap();
        assert_eq!(refill.len(), 1);
        let cancelled = capacity.acquire("groups", tenant, &stop);
        tokio::pin!(cancelled);
        assert!(futures::poll!(&mut cancelled).is_pending());
        let peer = capacity
            .acquire("groups", Uuid::from_u128(2), &stop)
            .await
            .unwrap();
        assert_eq!(peer.len(), 1);
        assert_eq!(
            PROJECTION_CONNECTIONS as usize,
            held.len() + refill.len() + peer.len() + 1
        );
        stop.cancel();
        assert!(cancelled.await.is_none());
    }
}
