//! Exact identities survive unrelated successes. No execution or retry policy lives here.
//! ref: kube-rs kube-runtime/src/controller/mod.rs@f2774b13d66910a8a0fe456cc8e6e52414eb1d0e
use crate::{Phase, RelayMessage};
use rss_reconcile::{Completion, ErrorKind, Observation, Scope, Stage, Target};
use rss_transactional_messaging::message::{MessageFingerprint, MessageId, MessagingDomain};
use std::collections::HashMap;

const FAILURE_LIMIT: usize = 1000;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Discovery(String),
    Scan(Scope),
    Attempt(Target),
    RelayRound(String),
    StoppedRelay(String),
    DeadLetters(Scope, i64),
    RelayClaim(Scope, i64),
    RelayMessage(Scope, i64, MessagingDomain, MessageId),
    Inputs(Scope),
}
impl Key {
    fn phase(&self) -> Option<usize> {
        match self {
            Self::Discovery(_) => Some(0),
            Self::Scan(_) => Some(1),
            Self::RelayRound(_)
            | Self::StoppedRelay(_)
            | Self::DeadLetters(..)
            | Self::RelayClaim(..)
            | Self::RelayMessage(..) => Some(2),
            Self::Inputs(_) => Some(3),
            Self::Attempt(_) => None,
        }
    }
}

/// A phase summary prefers an unresolved failure over unrelated later successes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scan {
    pub failure: Option<ErrorKind>,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Attempt {
    pub stage: Stage,
    pub failure: ErrorKind,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Copy)]
enum Evidence {
    Phase,
    Attempt(Stage),
    Message(Option<MessageFingerprint>),
    ConflictingFingerprints,
}

impl Evidence {
    fn reported(self, kind: ErrorKind, previous: Option<&Failure>) -> (Self, ErrorKind) {
        let (Self::Message(incoming), Some(previous)) = (self, previous) else {
            return (self, kind);
        };
        let evidence = match (previous.evidence, incoming) {
            (Self::ConflictingFingerprints, _) => Self::ConflictingFingerprints,
            (Self::Message(Some(known)), Some(reported)) if reported != known => {
                Self::ConflictingFingerprints
            }
            (Self::Message(Some(_)), None) => previous.evidence,
            _ => self,
        };
        let kind = if matches!(kind, ErrorKind::CommitUnknown | ErrorKind::RollbackFailed) {
            kind
        } else if matches!(
            previous.kind,
            ErrorKind::CommitUnknown | ErrorKind::RollbackFailed
        ) {
            previous.kind
        } else if matches!(evidence, Self::ConflictingFingerprints) {
            ErrorKind::Invariant
        } else {
            kind
        };
        (evidence, kind)
    }
}
#[derive(Clone, Copy)]
struct Failure {
    sequence: u128,
    check_order: u128,
    kind: ErrorKind,
    evidence: Evidence,
    observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub discovery: Option<Scan>,
    pub scan: Option<Scan>,
    pub relay: Option<Scan>,
    pub inputs: Option<Scan>,
    pub recovery: Phase,
    pub recovery_phase: Phase,
    pub blocks_readiness: bool,
    /// Only target execution failures; phase failures are represented by their summaries.
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub latest_failure: Option<Attempt>,
}
impl Snapshot {
    pub fn observed(&self) -> bool {
        self.discovery.is_some() || self.scan.is_some() || self.latest_failure.is_some()
    }
    pub fn failed(&self) -> bool {
        matches!(self.recovery, Phase::Failed(_))
    }
}

/// Independently bound owner health and partition diagnostics.
#[derive(Default)]
pub struct Observations {
    failures: HashMap<Key, Failure>,
    relay_failures: HashMap<Key, Failure>,
    relay_summaries: HashMap<Key, Failure>,
    relay_truncated: bool,
    latest: [Option<Scan>; 4],
    sequence: u128,
    truncated: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RelayWork {
    Idle,
    Readback,
    Claim,
}

/// Correlates a successful ordered discovery page with failures observed before its query.
pub struct RelayPage<'a> {
    observations: &'a std::sync::Mutex<Observations>,
    sequence: u128,
    domain: &'a str,
}
impl<'a> RelayPage<'a> {
    pub fn begin(observations: &'a std::sync::Mutex<Observations>, domain: &'a str) -> Self {
        let sequence = observations.lock().expect("relay observations").sequence;
        Self {
            observations,
            sequence,
            domain,
        }
    }
    /// The catalog returns every current tenant in this page, including idle rows.
    /// Historical claim epochs remain diagnostic evidence and cannot admit a new claim.
    pub fn bindings(
        self,
        rows: Vec<(uuid::Uuid, i64, bool, bool)>,
    ) -> Vec<(uuid::Uuid, i64, RelayWork)> {
        let mut state = self.observations.lock().expect("relay observations");
        rows.into_iter()
            .map(|(tenant, epoch, claimable, quarantine)| {
                let id = rss_request_context::TenantId::parse(&tenant.to_string())
                    .expect("database tenant");
                let scope = Scope::new(id, self.domain).expect("registered owner domain");
                let key = Key::DeadLetters(scope.clone(), epoch);
                if state
                    .relay_summaries
                    .get(&key)
                    .is_none_or(|failure| failure.sequence <= self.sequence)
                {
                    state.dead_letters(scope.clone(), epoch, quarantine, None);
                }
                state.relay_summaries.retain(|key, failure| {
                    let older_binding = matches!(
                        key,
                        Key::DeadLetters(other, old) | Key::RelayClaim(other, old)
                            if other == &scope && *old < epoch
                    );
                    failure.sequence > self.sequence || !older_binding
                });
                if !claimable {
                    let claim = Key::RelayClaim(scope.clone(), epoch);
                    if state
                        .relay_summaries
                        .get(&claim)
                        .is_some_and(|f| f.sequence <= self.sequence)
                    {
                        state.relay_summaries.remove(&claim);
                    }
                }
                let work = if claimable {
                    RelayWork::Claim
                } else if state.relay_failures.iter().any(|(key, failure)| {
                    matches!(
                        (key, failure.evidence),
                        (Key::RelayMessage(owner, original_epoch, _, _), Evidence::Message(_))
                            if owner == &scope && *original_epoch <= epoch
                    )
                }) {
                    RelayWork::Readback
                } else {
                    RelayWork::Idle
                };
                (tenant, epoch, work)
            })
            .collect()
    }
}
impl Observations {
    // One check per admitted batch. Rotate across outstanding messages even
    // when a long-lived failure or a failed read remains unresolved.
    pub(crate) fn next_relay_check(
        &mut self,
        scope: &Scope,
        epoch: i64,
    ) -> Option<(i64, RelayMessage, u128)> {
        let (original_epoch, domain, id, fingerprint, failure) = self
            .relay_failures
            .iter_mut()
            .filter_map(|(key, failure)| match (key, failure.evidence) {
                (Key::RelayMessage(owner, at, domain, id), Evidence::Message(fingerprint))
                    if owner == scope && *at <= epoch =>
                {
                    Some((*at, domain, id, fingerprint, failure))
                }
                _ => None,
            })
            .min_by_key(|(_, _, _, _, failure)| failure.check_order)?;
        self.sequence = self.sequence.saturating_add(1);
        failure.check_order = self.sequence;
        Some((
            original_epoch,
            RelayMessage {
                domain: domain.clone(),
                id: id.clone(),
                fingerprint,
            },
            failure.sequence,
        ))
    }

    pub(crate) fn identify_header(
        &mut self,
        scope: Scope,
        epoch: i64,
        message: RelayMessage,
        sequence: u128,
        fingerprint: MessageFingerprint,
    ) {
        let key = Key::RelayMessage(scope, epoch, message.domain, message.id);
        if let Some(failure) = self.relay_failures.get_mut(&key)
            && failure.sequence == sequence
            && matches!(failure.evidence, Evidence::Message(None))
        {
            self.sequence = self.sequence.saturating_add(1);
            failure.evidence = Evidence::Message(Some(fingerprint));
            failure.sequence = self.sequence;
        }
    }

    pub(crate) fn confirm_terminal(
        &mut self,
        scope: Scope,
        epoch: i64,
        message: RelayMessage,
        sequence: u128,
    ) -> bool {
        let Some(digest) = message.fingerprint else {
            return false;
        };
        let key = Key::RelayMessage(scope, epoch, message.domain, message.id);
        if let Some(failure) = self.relay_failures.get(&key)
            && failure.sequence == sequence
            && matches!(failure.evidence, Evidence::Message(Some(expected)) if expected==digest)
        {
            self.record(key, Ok(()), Evidence::Phase, None);
            return true;
        }
        false
    }

    fn record(
        &mut self,
        key: Key,
        outcome: Result<(), ErrorKind>,
        evidence: Evidence,
        at: Option<i64>,
    ) {
        self.sequence = self.sequence.saturating_add(1);
        if let Some(index) = key.phase() {
            self.latest[index] = Some(Scan {
                failure: outcome.err(),
                observed_at: at,
            });
        }
        let (failures, truncated) = match key {
            Key::RelayMessage(..) => (&mut self.relay_failures, &mut self.relay_truncated),
            Key::DeadLetters(..) | Key::RelayClaim(..) => {
                (&mut self.relay_summaries, &mut self.relay_truncated)
            }
            _ => (&mut self.failures, &mut self.truncated),
        };
        match outcome {
            Ok(()) => {
                failures.remove(&key);
            }
            Err(kind) => {
                // Re-reporting changes the evidence watermark, not the place
                // in the readback queue. New identities join at the tail.
                let previous = failures.get(&key);
                let check_order = match previous {
                    Some(existing) => existing.check_order,
                    None if failures.len() < FAILURE_LIMIT => self.sequence,
                    None => {
                        *truncated = true;
                        return;
                    }
                };
                let (evidence, kind) = evidence.reported(kind, previous);
                failures.insert(
                    key,
                    Failure {
                        sequence: self.sequence,
                        check_order,
                        kind,
                        evidence,
                        observed_at: at,
                    },
                );
            }
        }
    }
    pub fn discovery(&mut self, domain: &str, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::Discovery(domain.into()), outcome, Evidence::Phase, at);
    }
    pub fn scan(&mut self, scope: &Scope, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::Scan(scope.clone()), outcome, Evidence::Phase, at);
    }
    pub fn observe(&mut self, event: &Observation, at: Option<i64>) {
        match event {
            Observation::ScanFailed { scope, error } => self.scan(scope, Err(error.kind()), at),
            Observation::AttemptFailed {
                target,
                stage,
                error,
            } => {
                self.record(
                    Key::Attempt(target.clone()),
                    Err(error.kind()),
                    Evidence::Attempt(*stage),
                    at,
                );
            }
            Observation::Deferred { .. } => {}
        }
    }
    /// Call only after the provider acknowledged this target's completion.
    pub fn settled(&mut self, target: &Target, completion: Completion) {
        if matches!(completion, Completion::Converged | Completion::Reobserve(_)) {
            self.failures.remove(&Key::Attempt(target.clone()));
        }
    }
    /// A whole relay invocation is distinct from every tenant/epoch it attempted.
    pub fn relay_round(&mut self, domain: &str, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::RelayRound(domain.into()), outcome, Evidence::Phase, at);
    }
    pub(crate) fn stop_relay(&mut self, domain: &str, kind: ErrorKind, at: Option<i64>) {
        self.record(
            Key::StoppedRelay(domain.into()),
            Err(kind),
            Evidence::Phase,
            at,
        );
    }
    pub(crate) fn dead_letters(
        &mut self,
        scope: Scope,
        epoch: i64,
        present: bool,
        at: Option<i64>,
    ) {
        self.record(
            Key::DeadLetters(scope, epoch),
            if present {
                Err(ErrorKind::Permanent)
            } else {
                Ok(())
            },
            Evidence::Phase,
            at,
        );
    }
    pub fn relay_claim(
        &mut self,
        scope: &Scope,
        epoch: i64,
        outcome: Result<(), ErrorKind>,
        at: Option<i64>,
    ) {
        let key = Key::RelayClaim(scope.clone(), epoch);
        self.record(key, outcome, Evidence::Phase, at);
    }

    pub fn message_failed(
        &mut self,
        scope: &Scope,
        epoch: i64,
        message: &RelayMessage,
        kind: ErrorKind,
        at: Option<i64>,
    ) {
        self.record(
            Key::RelayMessage(
                scope.clone(),
                epoch,
                message.domain.clone(),
                message.id.clone(),
            ),
            Err(kind),
            Evidence::Message(message.fingerprint),
            at,
        );
    }
    /// The owner supplies the actual durable input target, never a tenant-only alias.
    pub fn inputs(&mut self, target: &Target, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(
            Key::Inputs(target.scope().clone()),
            outcome,
            Evidence::Phase,
            at,
        );
        if outcome.is_ok() {
            self.settled(target, Completion::Converged);
        }
    }
    fn phase(&self, index: usize) -> Option<Scan> {
        self.failures
            .iter()
            .chain(&self.relay_failures)
            .chain(&self.relay_summaries)
            .filter(|(key, _)| key.phase() == Some(index))
            .max_by_key(|(_, failure)| {
                (
                    index == 2
                        && matches!(
                            failure.kind,
                            ErrorKind::CommitUnknown | ErrorKind::RollbackFailed
                        ),
                    failure.sequence,
                )
            })
            .map(|(_, failure)| Scan {
                failure: Some(failure.kind),
                observed_at: failure.observed_at,
            })
            .or(self.latest[index])
    }
    pub fn snapshot(&self) -> Snapshot {
        let attempts = self
            .failures
            .iter()
            .filter(|(key, _)| matches!(key, Key::Attempt(_)));
        let latest_failure = attempts
            .clone()
            .max_by_key(|(_, failure)| failure.sequence)
            .and_then(|(_, failure)| match failure.evidence {
                Evidence::Attempt(stage) => Some(Attempt {
                    stage,
                    failure: failure.kind,
                    observed_at: failure.observed_at,
                }),
                _ => None,
            });
        let recovery = if self.truncated || self.relay_truncated {
            Phase::Failed(ErrorKind::Invariant)
        } else if let Some(failure) = self
            .failures
            .values()
            .chain(self.relay_failures.values())
            .chain(self.relay_summaries.values())
            .max_by_key(|failure| failure.sequence)
        {
            Phase::Failed(failure.kind)
        } else if self.latest.iter().any(Option::is_some) {
            Phase::Healthy
        } else {
            Phase::Unobserved
        };
        let recovery_phase = if self.truncated {
            Phase::Failed(ErrorKind::Invariant)
        } else if let Some((_, failure)) = self
            .failures
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key,
                    Key::RelayRound(_) | Key::StoppedRelay(_) | Key::Inputs(_)
                )
            })
            .max_by_key(|(_, f)| f.sequence)
        {
            Phase::Failed(failure.kind)
        } else if self.latest[0].is_some() || self.latest[1].is_some() {
            Phase::Healthy
        } else {
            Phase::Unobserved
        };
        Snapshot {
            recovery_phase,
            discovery: self.phase(0),
            scan: self.phase(1),
            relay: self.phase(2),
            inputs: self.phase(3),
            recovery,
            blocks_readiness: self.truncated || !self.failures.is_empty(),
            unresolved_attempts: attempts.count() as u64,
            truncated: self.truncated || self.relay_truncated,
            latest_failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_diagnostics_cannot_consume_owner_failure_capacity() {
        let mut state = Observations::default();
        for n in 1..=FAILURE_LIMIT + 1 {
            let tenant =
                rss_request_context::TenantId::parse(&uuid::Uuid::from_u128(n as u128).to_string())
                    .unwrap();
            state.dead_letters(Scope::new(tenant, "script").unwrap(), 1, true, None);
        }
        let tenant = uuid::Uuid::from_u128(100_001);
        let id = rss_request_context::TenantId::parse(&tenant.to_string()).unwrap();
        let scope = Scope::new(id, "script").unwrap();
        let message = RelayMessage {
            domain: MessagingDomain::parse("dispatch").unwrap(),
            id: MessageId::parse("original").unwrap(),
            fingerprint: Some(MessageFingerprint::from_bytes([8; 32])),
        };
        state.message_failed(&scope, 1, &message, ErrorKind::RollbackFailed, None);
        let state = std::sync::Mutex::new(state);
        let bindings = RelayPage::begin(&state, "script").bindings(vec![(tenant, 1, false, false)]);
        assert!(matches!(bindings[0].2, RelayWork::Readback));
        let mut state = state.lock().unwrap();
        let (_, original, revision) = state.next_relay_check(&scope, 1).unwrap();
        assert!(original == message);
        assert!(state.confirm_terminal(scope, 1, original, revision));
        assert!(state.relay_failures.is_empty());
        assert!(!state.relay_summaries.is_empty());
        assert!(state.snapshot().truncated);
        assert!(!state.snapshot().blocks_readiness);
        state.relay_round("script", Err(ErrorKind::StorageContract), None);
        assert!(state.snapshot().blocks_readiness);
        state.relay_round("script", Ok(()), None);
        assert!(!state.snapshot().blocks_readiness);
    }

    #[test]
    fn policy_relay_and_recovery_keep_their_own_failures() {
        let mut state = Observations::default();
        state.relay_round("policy", Err(ErrorKind::StorageContract), None);
        state.discovery("policy", Err(ErrorKind::Transient), None);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.recovery_phase, Phase::Failed(ErrorKind::Transient));
        assert_eq!(
            snapshot.relay.unwrap().failure,
            Some(ErrorKind::StorageContract)
        );
        state.discovery("policy", Ok(()), None);
        assert_eq!(state.snapshot().recovery_phase, Phase::Healthy);
    }

    #[test]
    fn later_failures_share_the_original_message_and_fence_older_reads() {
        let scope = Scope::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            "jobs",
        )
        .unwrap();
        let fingerprint = MessageFingerprint::from_bytes([7; 32]);
        let known = RelayMessage {
            domain: MessagingDomain::parse("dispatch").unwrap(),
            id: MessageId::parse("original").unwrap(),
            fingerprint: Some(fingerprint),
        };
        let partial = RelayMessage {
            fingerprint: None,
            ..known.clone()
        };
        for (first, later, expected) in [
            (
                ErrorKind::Transient,
                ErrorKind::Permanent,
                ErrorKind::Permanent,
            ),
            (
                ErrorKind::CommitUnknown,
                ErrorKind::Transient,
                ErrorKind::CommitUnknown,
            ),
            (
                ErrorKind::RollbackFailed,
                ErrorKind::Deadline,
                ErrorKind::RollbackFailed,
            ),
            (
                ErrorKind::RollbackFailed,
                ErrorKind::CommitUnknown,
                ErrorKind::CommitUnknown,
            ),
        ] {
            use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
            let binding = ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                scope.tenant(),
                Epoch::new(1).unwrap(),
            );
            let state = std::sync::Mutex::new(Observations::default());
            let relay = crate::RelayScope::new(&state, "jobs", binding, None);
            relay.message_failed(&known, first);
            let old_publication = relay.check().unwrap();
            let old_quarantine = relay.check().unwrap();
            relay.message_failed(&partial, later);
            old_publication.published();
            old_quarantine.dead_lettered();
            {
                let state = state.lock().unwrap();
                assert_eq!(
                    state.relay_failures.len(),
                    1,
                    "only the original message is unresolved"
                );
                assert_eq!(state.snapshot().relay.unwrap().failure, Some(expected));
            }
            let current = relay.check().unwrap();
            assert_eq!(current.message().fingerprint, Some(fingerprint));
            current.published();
            assert!(state.lock().unwrap().relay_failures.is_empty());
        }
    }

    #[test]
    fn learning_a_digest_updates_evidence_without_acknowledging_the_message() {
        let scope = Scope::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            "jobs",
        )
        .unwrap();
        let mut state = Observations::default();
        let partial = RelayMessage {
            domain: MessagingDomain::parse("dispatch").unwrap(),
            id: MessageId::parse("original").unwrap(),
            fingerprint: None,
        };
        let first = MessageFingerprint::from_bytes([3; 32]);
        let other = MessageFingerprint::from_bytes([5; 32]);
        state.message_failed(&scope, 1, &partial, ErrorKind::Transient, None);
        let (_, pending, seq) = state.next_relay_check(&scope, 1).unwrap();
        state.confirm_terminal(scope.clone(), 1, pending.clone(), seq);
        state.identify_header(scope.clone(), 1, pending.clone(), seq, first);
        state.identify_header(scope.clone(), 1, pending, seq, other);
        let (_, current, revision) = state.next_relay_check(&scope, 2).unwrap();
        assert!(revision > seq);
        assert_eq!(current.fingerprint, Some(first));
        state.confirm_terminal(scope.clone(), 2, current.clone(), revision);
        state.confirm_terminal(
            scope.clone(),
            1,
            RelayMessage {
                fingerprint: Some(other),
                ..current.clone()
            },
            revision,
        );
        assert_eq!(state.relay_failures.len(), 1);
        state.confirm_terminal(scope, 1, current, revision);
        assert!(state.relay_failures.is_empty());
    }

    #[test]
    fn competing_digests_keep_one_local_failure_and_leave_peer_checks_available() {
        let scope = Scope::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            "jobs",
        )
        .unwrap();
        let mut state = Observations::default();
        let original = RelayMessage {
            domain: MessagingDomain::parse("dispatch").unwrap(),
            id: MessageId::parse("original").unwrap(),
            fingerprint: Some(MessageFingerprint::from_bytes([1; 32])),
        };
        state.message_failed(&scope, 1, &original, ErrorKind::Deadline, None);
        let (_, old, seq) = state.next_relay_check(&scope, 1).unwrap();
        let contradictory = RelayMessage {
            fingerprint: Some(MessageFingerprint::from_bytes([2; 32])),
            ..original.clone()
        };
        state.message_failed(&scope, 1, &contradictory, ErrorKind::Transient, None);
        state.confirm_terminal(scope.clone(), 1, old, seq);
        state.message_failed(&scope, 1, &original, ErrorKind::Transient, None);
        assert_eq!(state.relay_failures.len(), 1);
        assert_eq!(
            state.snapshot().relay.unwrap().failure,
            Some(ErrorKind::Invariant)
        );
        assert!(!state.snapshot().blocks_readiness);
        let peer = RelayMessage {
            id: MessageId::parse("peer").unwrap(),
            ..original.clone()
        };
        state.message_failed(&scope, 1, &peer, ErrorKind::Transient, None);
        let (epoch, check, seq) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(check.id.as_str(), "peer");
        state.confirm_terminal(scope.clone(), epoch, check, seq);
        assert!(state.next_relay_check(&scope, 1).is_none());
        state.message_failed(&scope, 1, &original, ErrorKind::RollbackFailed, None);
        state.message_failed(&scope, 1, &contradictory, ErrorKind::Deadline, None);
        assert_eq!(
            state.snapshot().relay.unwrap().failure,
            Some(ErrorKind::RollbackFailed)
        );
    }

    #[test]
    fn publication_readback_rotates_and_cannot_clear_a_concurrent_failure() {
        let scope = Scope::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            "jobs",
        )
        .unwrap();
        let mut state = Observations::default();
        let message = |id| RelayMessage {
            domain: MessagingDomain::parse("dispatch").unwrap(),
            id: MessageId::parse(id).unwrap(),
            fingerprint: Some(MessageFingerprint::from_bytes([7; 32])),
        };
        for id in ["first", "second"] {
            state.message_failed(&scope, 1, &message(id), ErrorKind::Transient, None);
        }
        let (_, first, seq) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(first.id.as_str(), "first");
        let (_, second, _) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(second.id.as_str(), "second");
        // Both original messages have had a turn. A stream of new failures
        // and repeat reports for the second must leave the first at the head.
        for new_id in ["new-a", "new-b", "new-c"] {
            let new = message(new_id);
            state.message_failed(&scope, 1, &new, ErrorKind::Transient, None);
            state.message_failed(&scope, 1, &second, ErrorKind::Transient, None);
        }
        let (_, oldest, _) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(oldest.id.as_str(), "first");
        let (_, next_original, next) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(next_original.id.as_str(), "second");
        // Later reports must also keep their place relative to new arrivals.
        for new_id in ["new-a", "new-b", "new-c"] {
            state.message_failed(&scope, 1, &first, ErrorKind::Transient, None);
            let (_, checked, watermark) = state.next_relay_check(&scope, 1).unwrap();
            assert_eq!(checked.id.as_str(), new_id);
            state.confirm_terminal(scope.clone(), 1, checked, watermark);
        }
        state.message_failed(&scope, 1, &first, ErrorKind::CommitUnknown, None);
        state.confirm_terminal(scope.clone(), 1, first, seq);
        state.confirm_terminal(scope.clone(), 1, second, next);
        assert_eq!(
            state.snapshot().relay.unwrap().failure,
            Some(ErrorKind::CommitUnknown)
        );
        let (_, remaining, seq) = state.next_relay_check(&scope, 1).unwrap();
        state.confirm_terminal(scope, 1, remaining, seq);
        assert_eq!(state.snapshot().relay.unwrap().failure, None);
    }
}
