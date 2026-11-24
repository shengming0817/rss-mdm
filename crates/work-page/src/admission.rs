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
            let turn = self.pending.remove(&key).map_or(round, |(turn, _)| turn);
            self.pending.insert(key, (turn, round));
        }
    }

    pub(crate) fn finish_scan(&mut self, round: u64) {
        self.pending.retain(|_, (_, seen)| *seen == round);
    }

    fn available(&self, work: Work<T, R, O>) -> bool {
        !self.objects.contains(&work.object)
            && self.resources.get(&work.resource).copied().unwrap_or(0) < work.resource_limit
    }

    // The cyclic lane cursor survives page compaction. An old candidate from A
    // cannot repeatedly displace C after B has just received the last grant.
    fn priority(&self, key: &K, turn: u64, work: Work<T, R, O>) -> impl Ord + use<K, T, R, O> {
        let lane = (work.tenant, work.resource);
        let usage = (
            self.tenants.get(&lane.0).copied().unwrap_or(0),
            self.resources.get(&lane.1).copied().unwrap_or(0),
            self.shares.get(&lane).copied().unwrap_or(0),
        );
        let wrapped = self
            .last
            .as_ref()
            .is_some_and(|(_, t, r)| (&lane.0, &lane.1) <= (t, r));
        let key_wrapped = self.last.as_ref().is_some_and(|(last, _, _)| key <= last);
        (usage, wrapped, lane, turn, key_wrapped)
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
            let width = self.limit.min(work.resource_limit);
            let lane = (work.tenant, work.resource);
            let priority = self.priority(&key, waiting.0, binding(&key));
            let candidates = classes.entry(class).or_insert_with(BTreeMap::new);
            let objects = candidates.entry(lane).or_insert_with(BTreeMap::new);
            let candidate = (priority, key, waiting, width);
            // Different durable keys can still conflict on the same object.
            let object = binding(&candidate.1).object;
            match objects.entry(object) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if candidate < *entry.get() {
                        entry.insert(candidate);
                    }
                }
            }
        }
        for lanes in classes.into_values() {
            let mut lanes: Vec<_> = lanes
                .into_values()
                .map(|objects| {
                    let mut ranked: Vec<_> = objects.into_values().collect();
                    ranked.sort_unstable();
                    ranked.truncate(ranked[0].3);
                    ranked
                })
                .collect();
            lanes.sort_unstable_by(|a, b| a[0].cmp(&b[0]));
            for candidates in lanes.into_iter().take(self.limit) {
                self.pending.extend(
                    candidates
                        .into_iter()
                        .map(|(_, key, waiting, _)| (key, waiting)),
                );
            }
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
        assert_eq!(admission.pending.len(), 4);
        admission.finish(&1, binding(&1));
        assert_eq!(admission.take(&binding), Some(3));
    }
    #[test]
    fn every_continuously_ready_lane_gets_a_turn_at_width_one() {
        for separate_tenants in [true, false] {
            let binding = |key: &u8| Work {
                tenant: if separate_tenants { *key / 4 } else { 0 },
                resource: if separate_tenants { 0 } else { *key / 4 },
                resource_limit: 1,
                object: *key,
            };
            let mut admission = Admission::new(1);
            let mut served = BTreeSet::new();
            admission.discover(0, 0);
            let mut running = admission.take(&binding).unwrap();
            for round in 1..=12 {
                for key in 0..12 {
                    admission.discover(key, round);
                }
                admission.retain_successors(&binding);
                admission.finish(&running, binding(&running));
                running = admission.take(&binding).unwrap();
                served.insert(running / 4);
            }
            assert_eq!(served, BTreeSet::from([0, 1, 2]));
        }
    }

    #[test]
    fn known_independent_objects_refill_multiple_releases_during_page_io() {
        let binding = |key: &u8| Work {
            tenant: 0,
            resource: 0,
            resource_limit: 8,
            object: *key,
        };
        let mut admission = Admission::new(8);
        for key in 0..32 {
            admission.discover(key, 0);
        }
        let active: Vec<_> = (0..8).map(|_| admission.take(&binding).unwrap()).collect();
        admission.retain_successors(&binding);
        for key in active {
            admission.finish(&key, binding(&key));
        }
        for _ in 0..8 {
            assert!(admission.take(&binding).is_some());
        }
        assert!(admission.take(&binding).is_none());
    }
}
