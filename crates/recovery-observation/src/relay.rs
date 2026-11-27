//! A second host can publish a failed message while its binding still has other work.
use crate::Observations;
use rss_reconcile::Scope;
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    message::{MessageFingerprint, MessageId, MessagingDomain},
    outbox::PendingMessage,
};
use std::sync::Mutex;

#[derive(Clone, PartialEq, Eq)]
pub struct RelayMessage {
    pub domain: MessagingDomain,
    pub id: MessageId,
    /// RSS can return a claimed ID before it exposes the original envelope to ingress.
    pub fingerprint: Option<MessageFingerprint>,
}
impl<P> From<&PendingMessage<P>> for RelayMessage {
    fn from(message: &PendingMessage<P>) -> Self {
        Self {
            domain: message.envelope().metadata().domain().clone(),
            id: message.message_id().clone(),
            fingerprint: Some(message.fingerprint()),
        }
    }
}

/// Observation for one admitted binding. The caller supplies all durable results.
pub struct RelayScope<'a> {
    state: &'a Mutex<Observations>,
    scope: Scope,
    epoch: i64,
    at: Option<i64>,
}
impl<'a> RelayScope<'a> {
    pub fn new(
        state: &'a Mutex<Observations>,
        domain: &str,
        binding: ExecutionBinding,
        at: Option<i64>,
    ) -> Self {
        Self {
            state,
            scope: Scope::new(binding.tenant(), domain).expect("registered owner domain"),
            epoch: binding.epoch().get(),
            at,
        }
    }
    pub fn check(&self) -> Option<RelayCheck<'a>> {
        let (original_epoch, message, sequence) = self
            .state
            .lock()
            .expect("relay observations")
            .next_relay_check(&self.scope, self.epoch)?;
        Some(RelayCheck {
            state: self.state,
            scope: self.scope.clone(),
            original_epoch,
            read_epoch: self.epoch,
            at: self.at,
            sequence,
            message,
        })
    }
    pub fn owner_failed(&self, kind: rss_reconcile::ErrorKind) {
        self.state.lock().expect("relay observations").relay_round(
            self.scope.reconciler(),
            Err(kind),
            self.at,
        );
    }
    pub fn quarantined(&self) {
        self.state.lock().expect("relay observations").dead_letters(
            self.scope.clone(),
            self.epoch,
            true,
            self.at,
        );
    }
    pub fn claim(&self, outcome: Result<(), rss_reconcile::ErrorKind>) {
        self.state.lock().expect("relay observations").relay_claim(
            &self.scope,
            self.epoch,
            outcome,
            self.at,
        );
    }
    pub fn message_failed(&self, message: &RelayMessage, kind: rss_reconcile::ErrorKind) {
        self.state
            .lock()
            .expect("relay observations")
            .message_failed(&self.scope, self.epoch, message, kind, self.at);
    }
}

/// A readback applies only to the captured revision of this original message.
pub struct RelayCheck<'a> {
    state: &'a Mutex<Observations>,
    scope: Scope,
    original_epoch: i64,
    read_epoch: i64,
    at: Option<i64>,
    sequence: u128,
    message: RelayMessage,
}
impl RelayCheck<'_> {
    pub fn message(&self) -> &RelayMessage {
        &self.message
    }

    /// Learning the original digest does not prove delivery.
    pub fn identify(self, fingerprint: MessageFingerprint) {
        self.state
            .lock()
            .expect("relay observations")
            .identify_header(
                self.scope,
                self.original_epoch,
                self.message,
                self.sequence,
                fingerprint,
            );
    }

    pub fn published(self) {
        self.terminal(false);
    }
    pub fn dead_lettered(self) {
        self.terminal(true);
    }
    fn terminal(self, quarantined: bool) {
        let mut state = self.state.lock().expect("relay observations");
        if state.confirm_terminal(
            self.scope.clone(),
            self.original_epoch,
            self.message,
            self.sequence,
        ) && quarantined
        {
            state.dead_letters(self.scope, self.read_epoch, true, self.at);
        }
    }
}
