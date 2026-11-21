//! A second host can publish a failed message while its binding still has other work.
use crate::Observations;
use rss_reconcile::Scope;
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    message::{MessageFingerprint, MessageId, MessagingDomain},
    outbox::PendingMessage,
};
use std::sync::Mutex;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RelayMessage {
    pub domain: MessagingDomain,
    pub id: MessageId,
    pub fingerprint: MessageFingerprint,
}
impl<P> From<&PendingMessage<P>> for RelayMessage {
    fn from(message: &PendingMessage<P>) -> Self {
        Self {
            domain: message.envelope().metadata().domain().clone(),
            id: message.message_id().clone(),
            fingerprint: message.fingerprint(),
        }
    }
}

/// Captures the failed observation before the caller begins a durable read.
pub struct RelayCheck<'a> {
    state: &'a Mutex<Observations>,
    scope: Scope,
    epoch: i64,
    sequence: u128,
    pub message: RelayMessage,
}
impl<'a> RelayCheck<'a> {
    pub fn begin(
        state: &'a Mutex<Observations>,
        domain: &str,
        binding: ExecutionBinding,
    ) -> Option<Self> {
        let scope = Scope::new(binding.tenant(), domain).expect("registered owner domain");
        let epoch = binding.epoch().get();
        let (message, sequence) = state
            .lock()
            .expect("relay observations")
            .next_relay_check(&scope, epoch)?;
        Some(Self {
            state,
            scope,
            epoch,
            sequence,
            message,
        })
    }

    /// Call only after reading a published receipt for this exact message.
    pub fn published(self) {
        self.state
            .lock()
            .expect("relay observations")
            .confirm_publication(self.scope, self.epoch, self.message, self.sequence);
    }
}
