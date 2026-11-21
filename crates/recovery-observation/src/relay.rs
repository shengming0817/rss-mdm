//! A second host can publish a failed message while its binding still has other work.
use crate::Observations;
use rss_reconcile::Scope;
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    message::{MessageFingerprint, MessageId, MessagingDomain},
    outbox::PendingMessage,
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgOutboxStore, PgRuntime};
use std::{sync::Mutex, time::Duration};

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

impl RelayMessage {
    /// Called inside an admitted slot, before claiming. A failed read is
    /// advisory and preserves the original failure and its retry policy.
    pub async fn verify_one(
        observations: &Mutex<Observations>,
        domain: &str,
        binding: ExecutionBinding,
        runtime: &PgRuntime,
        outbox: &PgOutboxStore<()>,
    ) {
        let scope = Scope::new(binding.tenant(), domain).expect("registered owner domain");
        let epoch = binding.epoch().get();
        let candidate = observations
            .lock()
            .expect("relay observations")
            .next_relay_check(&scope, epoch);
        let Some((message, sequence)) = candidate else {
            return;
        };
        let published = runtime
            .local_tx_with_context(
                binding,
                OperationDeadline::from_remaining(Duration::from_secs(1)),
                (outbox, &message),
                |(store, message), tx| {
                    Box::pin(async move {
                        store
                            .is_published(tx, &message.domain, &message.id, message.fingerprint)
                            .await
                    })
                },
            )
            .await
            .fold(
                |published| published,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
            );
        if published {
            observations
                .lock()
                .expect("relay observations")
                .confirm_publication(scope, epoch, message, sequence);
        }
    }
}
