//! Bounded ready candidates, distinguished by the active tenants and resources a release may affect.
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

    fn available(&self, work: Work<T, R, O>) -> bool {
        !self.objects.contains(&work.object)
            && self.resources.get(&work.resource).copied().unwrap_or(0) < work.resource_limit
    }

    // Least occupied tenant, then source / tenant share of that source. At equal usage
    // rotate past the most recently served lane and preserve earlier discovery rounds.
    fn priority(
        &self,
        key: &K,
        turn: u64,
        work: Work<T, R, O>,
    ) -> (usize, usize, usize, u64, bool, bool, bool) {
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
            turn,
            same_tenant,
            same_resource,
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
            .filter(|(key, _)| self.available(binding(key)))
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

    // Completing any active job may change its tenant's share, its resource's
    // share, and the availability of its object. Keep those alternatives apart
    // until the actual completion. Among currently idle peers keep up to one
    // host-width of distinct lanes in waiting order, independently of backlog size.
    pub(crate) fn retain_successors(&mut self, binding: &impl Fn(&K) -> Work<T, R, O>) -> bool {
        let mut classes = BTreeMap::new();
        for (key, waiting) in std::mem::take(&mut self.pending) {
            let work = binding(&key);
            let class = (
                self.tenants
                    .contains_key(&work.tenant)
                    .then(|| work.tenant.clone()),
                self.resources
                    .contains_key(&work.resource)
                    .then(|| work.resource.clone()),
                self.objects.contains(&work.object).then_some(work.object),
            );
            let lane = (work.tenant, work.resource);
            let priority = self.priority(&key, waiting.0, binding(&key));
            let candidate = (priority, key, waiting);
            let lanes = classes.entry(class).or_insert_with(BTreeMap::new);
            lanes
                .entry(lane)
                .and_modify(|old| {
                    if candidate < *old {
                        *old = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
        for lanes in classes.into_values() {
            let mut successors: Vec<_> = lanes.into_values().collect();
            successors.sort_unstable();
            self.pending.extend(
                successors
                    .into_iter()
                    .take(self.limit)
                    .map(|(_, key, waiting)| (key, waiting)),
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_changes_which_waiting_tenant_has_the_smaller_share() {
        let binding = |key: &u8| Work::independent(*key % 2, *key);
        let mut admission = Admission::new(2);
        for key in 0..2 {
            admission.discover(key, 0);
            assert_eq!(admission.take(&binding), Some(key));
        }
        for key in 2..64 {
            admission.discover(key, 1);
        }
        admission.retain_successors(&binding);
        assert_eq!(admission.pending.len(), 2);
        admission.finish(&1, binding(&1));
        assert_eq!(admission.take(&binding), Some(3));
    }
}
