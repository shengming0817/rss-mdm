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
            total, owner, tenant, binding,
            state: Mutex::default(),
            changed: watch::channel(()).0,
        })
    }
    pub(crate) fn projection() -> Arc<Self> {
        Self::new(PROJECTION_SLOTS, PROJECTION_SLOTS, 2, 2)
    }
    pub(crate) fn commands(parallelism: NonZeroUsize) -> Arc<Self> {
        let total = parallelism.get().min(4);
        let binding = total.saturating_sub(1).clamp(1, 2);
        Self::new(total, total.min(3), total.min(3), binding)
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
    pub(crate) async fn acquire(self: &Arc<Self>, owner: &'static str, tenant: Uuid, stop: &CancellationToken) -> Option<Vec<Slot>> {
        let key = Binding { owner, tenant };
        let mut changed = self.changed.subscribe();
        let ticket = Arc::new(());
        self.state.lock().expect("admission state").waiting.push_back((ticket.clone(), key));
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
                let next = state.waiting.iter().position(|(_, k)| self.available(&state, *k) > 0);
                if let Some(index) = next && Arc::ptr_eq(&ticket, &state.waiting[index].0) {
                    state.waiting.remove(index);
                    let count = self.available(&state, key);
                    state.active.extend(std::iter::repeat_n(key, count));
                    self.changed.send_replace(());
                    return Some((0..count).map(|_| Slot { budget: self.clone(), key }).collect());
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
        let index = state.active.iter().position(|key| *key == self.key).expect("owned slot");
        state.active.swap_remove(index);
        self.budget.changed.send_replace(());
    }
}
