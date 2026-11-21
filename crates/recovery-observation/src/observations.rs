//! Exact identities survive unrelated successes. No execution or retry policy lives here.
//! ref: kube-rs kube-runtime/src/controller/mod.rs@f2774b13d66910a8a0fe456cc8e6e52414eb1d0e
use crate::{Phase, RelayMessage};
use rss_reconcile::{Completion, ErrorKind, Observation, Scope, Stage, Target};
use std::collections::HashMap;

const FAILURE_LIMIT: usize = 1000;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Discovery(String),
    Scan(Scope),
    Attempt(Target),
    RelayRound(String),
    Relay(Scope, i64, Option<RelayMessage>),
    Inputs(Scope),
}
impl Key {
    fn phase(&self) -> Option<usize> {
        match self {
            Self::Discovery(_) => Some(0),
            Self::Scan(_) => Some(1),
            Self::RelayRound(_) | Self::Relay(..) => Some(2),
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
struct Failure {
    sequence: u128,
    last_check: u128,
    kind: ErrorKind,
    stage: Option<Stage>,
    observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub discovery: Option<Scan>,
    pub scan: Option<Scan>,
    pub relay: Option<Scan>,
    pub inputs: Option<Scan>,
    pub recovery: Phase,
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

/// One bounded table per owner. Lost failure identities remain unresolved until restart.
#[derive(Default)]
pub struct Observations {
    failures: HashMap<Key, Failure>,
    latest: [Option<Scan>; 4],
    sequence: u128,
    truncated: bool,
}
/// Correlates a successful ordered discovery page with failures observed before its query.
pub struct RelayPage<'a> {
    observations: &'a std::sync::Mutex<Observations>,
    sequence: u128,
    domain: &'a str,
    after: Option<(uuid::Uuid, i64)>,
}
impl<'a> RelayPage<'a> {
    pub fn begin(
        observations: &'a std::sync::Mutex<Observations>,
        domain: &'a str,
        after: Option<(uuid::Uuid, i64)>,
    ) -> Self {
        let sequence = observations.lock().expect("relay observations").sequence;
        Self {
            observations,
            sequence,
            domain,
            after,
        }
    }
    /// Every pending or publishing message keeps its binding discoverable.
    /// Absence in the covered interval proves that another worker may have drained it.
    pub fn confirm(self, rows: &[(uuid::Uuid, i64)]) {
        let mut state = self.observations.lock().expect("relay observations");
        let before = state.failures.len();
        state.failures.retain(|key, failure| {
            let Key::Relay(scope, epoch, _) = key else {
                return true;
            };
            let binding = (uuid::Uuid::from_bytes(scope.tenant().octets()), *epoch);
            scope.reconciler() != self.domain
                || failure.sequence > self.sequence
                || self.after.is_some_and(|after| binding <= after)
                || rows.last().is_some_and(|last| binding > *last)
                || rows.binary_search(&binding).is_ok()
        });
        if state.failures.len() < before {
            state.latest[2] = Some(Scan {
                failure: None,
                observed_at: None,
            });
        }
    }
}
impl Observations {
    // One check per admitted batch. Rotate across outstanding messages even
    // when a long-lived failure or a failed read remains unresolved.
    pub(crate) fn next_relay_check(
        &mut self,
        scope: &Scope,
        epoch: i64,
    ) -> Option<(RelayMessage, u128)> {
        let (message, failure) = self
            .failures
            .iter_mut()
            .filter_map(|(key, failure)| match key {
                Key::Relay(owner, at, Some(message)) if owner == scope && *at == epoch => {
                    Some((message, failure))
                }
                _ => None,
            })
            .min_by_key(|(_, f)| (f.last_check, f.sequence))?;
        self.sequence = self.sequence.saturating_add(1);
        failure.last_check = self.sequence;
        Some((message.clone(), failure.sequence))
    }

    pub(crate) fn confirm_publication(
        &mut self,
        scope: Scope,
        epoch: i64,
        message: RelayMessage,
        sequence: u128,
    ) {
        let key = Key::Relay(scope, epoch, Some(message));
        if self
            .failures
            .get(&key)
            .is_some_and(|f| f.sequence == sequence)
        {
            self.record(key, Ok(()), None, None);
        }
    }

    fn record(
        &mut self,
        key: Key,
        outcome: Result<(), ErrorKind>,
        stage: Option<Stage>,
        at: Option<i64>,
    ) {
        self.sequence = self.sequence.saturating_add(1);
        if let Some(index) = key.phase() {
            self.latest[index] = Some(Scan {
                failure: outcome.err(),
                observed_at: at,
            });
        }
        match outcome {
            Ok(()) => {
                self.failures.remove(&key);
            }
            Err(kind)
                if self.failures.contains_key(&key) || self.failures.len() < FAILURE_LIMIT =>
            {
                self.failures.insert(
                    key,
                    Failure {
                        sequence: self.sequence,
                        last_check: 0,
                        kind,
                        stage,
                        observed_at: at,
                    },
                );
            }
            Err(_) => self.truncated = true,
        }
    }
    pub fn discovery(&mut self, domain: &str, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::Discovery(domain.into()), outcome, None, at);
    }
    pub fn scan(&mut self, scope: &Scope, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::Scan(scope.clone()), outcome, None, at);
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
                    Some(*stage),
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
        self.record(Key::RelayRound(domain.into()), outcome, None, at);
    }
    pub fn relay(
        &mut self,
        scope: &Scope,
        epoch: i64,
        message: Option<&RelayMessage>,
        outcome: Result<(), ErrorKind>,
        at: Option<i64>,
    ) {
        self.record(
            Key::Relay(scope.clone(), epoch, message.cloned()),
            outcome,
            None,
            at,
        );
    }
    /// The owner supplies the actual durable input target, never a tenant-only alias.
    pub fn inputs(&mut self, target: &Target, outcome: Result<(), ErrorKind>, at: Option<i64>) {
        self.record(Key::Inputs(target.scope().clone()), outcome, None, at);
        if outcome.is_ok() {
            self.settled(target, Completion::Converged);
        }
    }
    fn phase(&self, index: usize) -> Option<Scan> {
        self.failures
            .iter()
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
            .and_then(|(_, failure)| {
                failure.stage.map(|stage| Attempt {
                    stage,
                    failure: failure.kind,
                    observed_at: failure.observed_at,
                })
            });
        let recovery = if self.truncated {
            Phase::Failed(ErrorKind::Invariant)
        } else if let Some(failure) = self
            .failures
            .values()
            .max_by_key(|failure| failure.sequence)
        {
            Phase::Failed(failure.kind)
        } else if self.latest.iter().any(Option::is_some) {
            Phase::Healthy
        } else {
            Phase::Unobserved
        };
        Snapshot {
            discovery: self.phase(0),
            scan: self.phase(1),
            relay: self.phase(2),
            inputs: self.phase(3),
            recovery,
            unresolved_attempts: attempts.count() as u64,
            truncated: self.truncated,
            latest_failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::message::{MessageFingerprint, MessageId, MessagingDomain};

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
            fingerprint: MessageFingerprint::from_bytes([7; 32]),
        };
        for id in ["first", "second"] {
            state.relay(
                &scope,
                1,
                Some(&message(id)),
                Err(ErrorKind::Transient),
                None,
            );
        }
        let (first, seq) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(first.id.as_str(), "first");
        let (second, next) = state.next_relay_check(&scope, 1).unwrap();
        assert_eq!(second.id.as_str(), "second");
        state.relay(&scope, 1, Some(&first), Err(ErrorKind::CommitUnknown), None);
        state.confirm_publication(scope.clone(), 1, first, seq);
        state.confirm_publication(scope.clone(), 1, second, next);
        assert_eq!(
            state.snapshot().relay.unwrap().failure,
            Some(ErrorKind::CommitUnknown)
        );
        let (remaining, seq) = state.next_relay_check(&scope, 1).unwrap();
        state.confirm_publication(scope, 1, remaining, seq);
        assert_eq!(state.snapshot().relay.unwrap().failure, None);
    }
}
