//! A discovery page and one successor per saturated host, resource or object.
use std::collections::{BTreeMap, BTreeSet};

pub struct Work<T, R, O> {
    pub(crate) tenant: T,
    pub(crate) resource: R,
    pub(crate) resource_limit: usize,
    pub(crate) object: O,
}

impl<T, O> Work<T, (), O> {
    pub fn independent(tenant: T, object: O) -> Self {
        Self {
            tenant,
            resource: (),
            resource_limit: usize::MAX,
            object,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Block<R, O> {
    Host,
    Resource(R),
    Object(O),
}

pub(crate) struct Admission<K, T, R, O> {
    limit: usize,
    pending: BTreeMap<K, (u64, u64)>,
    active: BTreeSet<K>,
    tenants: BTreeMap<T, usize>,
    resources: BTreeMap<R, usize>,
    shares: BTreeMap<(T, R), usize>,
    objects: BTreeSet<O>,
    last: Option<(K, T, R)>,
}

fn decrement<G: Ord>(counts: &mut BTreeMap<G, usize>, group: &G) {
    let used = counts.get_mut(group).expect("active group");
    *used -= 1;
    if *used == 0 {
        counts.remove(group);
    }
}

impl<K: Clone + Ord, T: Clone + Ord, R: Clone + Ord, O: Ord> Admission<K, T, R, O> {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            pending: BTreeMap::new(),
            active: BTreeSet::new(),
            tenants: BTreeMap::new(),
            resources: BTreeMap::new(),
            shares: BTreeMap::new(),
            objects: BTreeSet::new(),
            last: None,
        }
    }

    pub(crate) fn active(&self, key: &K) -> bool {
        self.active.contains(key)
    }

    pub(crate) fn discover(&mut self, key: K, round: u64) {
        if !self.active(&key) {
            self.pending.entry(key).or_insert((round, round)).1 = round;
        }
    }

    pub(crate) fn finish_scan(&mut self, round: u64) {
        self.pending.retain(|_, (_, seen)| *seen == round);
    }

    fn block(&self, work: Work<T, R, O>) -> Option<Block<R, O>> {
        if self.objects.contains(&work.object) {
            Some(Block::Object(work.object))
        } else if self.resources.get(&work.resource).copied().unwrap_or(0) >= work.resource_limit {
            Some(Block::Resource(work.resource))
        } else if self.active.len() >= self.limit {
            Some(Block::Host)
        } else {
            None
        }
    }

    // Least occupied tenant, then source / tenant share of that source. At equal usage
    // rotate past the most recently served lane and preserve earlier discovery rounds.
    fn priority(
        &self,
        key: &K,
        turn: u64,
        work: Work<T, R, O>,
    ) -> (usize, usize, usize, bool, bool, u64, bool) {
        let last = self.last.as_ref();
        let same_tenant = last.is_some_and(|(_, t, _)| t == &work.tenant);
        let same_resource = last.is_some_and(|(_, _, r)| r == &work.resource);
        (
            self.tenants.get(&work.tenant).copied().unwrap_or(0),
            self.resources.get(&work.resource).copied().unwrap_or(0),
            self.shares
                .get(&(work.tenant, work.resource))
                .copied()
                .unwrap_or(0),
            same_tenant,
            same_resource,
            turn,
            last.is_some_and(|(k, _, _)| key <= k),
        )
    }

    pub(crate) fn take(&mut self, binding: &impl Fn(&K) -> Work<T, R, O>) -> Option<K> {
        if self.active.len() == self.limit {
            return None;
        }
        let key = self
            .pending
            .iter()
            .filter(|(key, _)| self.block(binding(key)).is_none())
            .min_by_key(|(key, (turn, _))| self.priority(key, *turn, binding(key)))
            .map(|(key, _)| key.clone())?;
        self.pending.remove(&key);
        let work = binding(&key);
        self.active.insert(key.clone());
        self.objects.insert(work.object);
        *self.tenants.entry(work.tenant.clone()).or_default() += 1;
        *self.resources.entry(work.resource.clone()).or_default() += 1;
        *self
            .shares
            .entry((work.tenant.clone(), work.resource.clone()))
            .or_default() += 1;
        self.last = Some((key.clone(), work.tenant, work.resource));
        Some(key)
    }

    // The durable cursor traverses the rest even when every slot is held. Never
    // allocate a waiter or spawn a task per durable row in a hot tenant's backlog.
    pub(crate) fn retain_successors(&mut self, binding: &impl Fn(&K) -> Work<T, R, O>) -> bool {
        let mut successors = BTreeMap::new();
        for (key, waiting) in std::mem::take(&mut self.pending) {
            let block = self
                .block(binding(&key))
                .expect("admitted every eligible candidate");
            let priority = self.priority(&key, waiting.0, binding(&key));
            let candidate = (priority, key, waiting);
            let best = successors.entry(block).or_insert_with(|| candidate.clone());
            if candidate < *best {
                *best = candidate;
            }
        }
        self.pending
            .extend(successors.into_values().map(|(_, key, turn)| (key, turn)));
        !self.pending.is_empty()
    }

    pub(crate) fn finish(&mut self, key: &K, work: Work<T, R, O>) {
        self.active.remove(key);
        self.objects.remove(&work.object);
        decrement(&mut self.tenants, &work.tenant);
        decrement(&mut self.resources, &work.resource);
        decrement(&mut self.shares, &(work.tenant, work.resource));
    }
}
