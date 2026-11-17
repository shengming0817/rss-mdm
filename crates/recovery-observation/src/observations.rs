//! Exact identities survive unrelated successes. No execution or retry policy lives here.
//! ref: kube-rs kube-runtime/src/controller/mod.rs@f2774b13d66910a8a0fe456cc8e6e52414eb1d0e
use crate::Phase;
use rss_reconcile::{Completion, ErrorKind, Observation, Scope, Stage, Target};
use std::collections::HashMap;

const FAILURE_LIMIT: usize = 1000;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Discovery(String),
    Scan(Scope),
    Attempt(Target),
    RelayRound(String),
    Relay(Scope, i64),
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
impl Observations {
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
        outcome: Result<(), ErrorKind>,
        at: Option<i64>,
    ) {
        self.record(Key::Relay(scope.clone(), epoch), outcome, None, at);
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
            .max_by_key(|(_, failure)| failure.sequence)
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
