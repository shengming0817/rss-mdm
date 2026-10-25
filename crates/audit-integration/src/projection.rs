//! MDM's fixed source consumer. RSS owns effect/Inbox/Outbox settlement and recovery identity.
//! ref: RSS transactional-messaging-postgres/src/projection.rs@d0202b30379a067a94ef386e4c071b7f6cc3d47c.
use crate::{
    Error,
    budget::RuntimeTimer,
    source::{DOMAIN, FrozenFact, GROUP},
};
use rss_audit_postgres::PgAudit;
use rss_data_protection::Aead;
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::{
    inbox::ConsumerGroup,
    message::{MessageEnvelope, MessagingDomain},
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
    transaction::{
        EnvelopeValidationFailure, IngressChallenge, IngressValidator, RejectKind,
        TerminalDisposition, VerifiedIngress,
    },
};
use rss_transactional_messaging_postgres::{
    OutboxWakeup, PgConsumerEffect, PgConsumerEffectFailure, PgLocalProjection,
    PgProjectionAttempt, PgProjectionOutcome, PgProjectionRecovery, PgRecoveryCapture, PgRuntime,
    PgTransaction,
};
use std::{
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditProjectionError {
    #[error("invalid audit projection configuration")]
    Configuration,
    #[error("audit projection dependency unavailable")]
    Unavailable,
    #[error("audit projection operation deadline elapsed")]
    Deadline,
    #[error("audit projection requires storage repair")]
    Permanent,
    #[error("audit projection integrity violation")]
    Integrity,
    #[error("audit projection execution authority lost")]
    Fenced,
    #[error("audit source event quarantined")]
    Quarantined,
    #[error("audit projection commit unconfirmed")]
    CommitUnknown,
    #[error("audit projection rollback unconfirmed")]
    RollbackFailed,
}
impl AuditProjectionError {
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::Deadline | Self::CommitUnknown | Self::RollbackFailed
        )
    }
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Unavailable => "unavailable",
            Self::Deadline => "deadline",
            Self::Permanent => "permanent",
            Self::Integrity => "integrity",
            Self::Fenced => "fenced",
            Self::Quarantined => "quarantined",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
        }
    }
    fn pg(error: rss_transactional_messaging_postgres::PgError) -> Self {
        Self::pg_kind(error.kind())
    }
    fn pg_kind(kind: rss_transactional_messaging::error::MessagingErrorKind) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind as Kind;
        match kind {
            Kind::Transient => Self::Unavailable,
            Kind::DeadlineElapsed => Self::Deadline,
            Kind::Permanent => Self::Permanent,
            Kind::Conflict | Kind::Invariant => Self::Integrity,
            Kind::OwnershipLost => Self::Fenced,
        }
    }
}
struct Effect {
    audit: Arc<PgAudit>,
    fatal: Arc<OnceLock<AuditProjectionError>>,
}
impl Effect {
    fn failure(&self, error: Error) -> PgConsumerEffectFailure {
        let error = rss_transactional_messaging_postgres::PgError::from(error);
        let kind = AuditProjectionError::pg_kind(error.kind());
        if !kind.is_retryable() {
            let _ = self.fatal.set(kind);
        }
        PgConsumerEffectFailure::infrastructure(error)
    }
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let frozen = match FrozenFact::decode(message.payload()) {
            Ok(value) => value,
            Err(_) => return Ok(TerminalDisposition::Rejected(RejectKind::Permanent)),
        };
        let identity = frozen.identity().map_err(|error| self.failure(error))?;
        let staged = self
            .audit
            .append_with_in(tx, &identity, |previous, now| {
                let recorded_at = match previous {
                    Some(record) => {
                        rss_audit_core::decode_untrusted(record.prepared().canonical_bytes())
                            .map_err(rss_audit_postgres::Error::from)?
                            .recorded_at()
                    }
                    None => now,
                };
                frozen.prepare(recorded_at)
            })
            .await;
        let staged = match staged {
            Ok(value) => value,
            Err(
                Error::Receipt
                | Error::Fact(_)
                | Error::Audit(
                    rss_audit_postgres::Error::Conflict
                    | rss_audit_postgres::Error::ScopeMismatch
                    | rss_audit_postgres::Error::Protocol(_),
                ),
            ) => return Ok(TerminalDisposition::Rejected(RejectKind::Invariant)),
            Err(error) => return Err(self.failure(error)),
        };
        let recorded_at =
            rss_audit_core::decode_untrusted(staged.record().prepared().canonical_bytes())
                .map_err(|error| self.failure(Error::Audit(error.into())))?
                .recorded_at()
                .unix_seconds();
        match crate::queue::projected(tx, &frozen, recorded_at, staged.inserted()).await {
            Ok(()) => Ok(TerminalDisposition::Succeeded),
            Err(Error::Receipt) => Ok(TerminalDisposition::Rejected(RejectKind::Invariant)),
            Err(error) => Err(self.failure(error)),
        }
    }
}
struct Validator {
    tenants: Vec<TenantId>,
}
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        let message = challenge.message();
        if !self.tenants.contains(&message.metadata().tenant_id()) {
            return Err(EnvelopeValidationFailure::MalformedIdentity);
        }
        let frozen = FrozenFact::decode(message.payload())
            .map_err(|_| EnvelopeValidationFailure::UnsupportedContract)?;
        let expected = frozen
            .message()
            .map_err(|_| EnvelopeValidationFailure::MalformedIdentity)?;
        if message.metadata() != expected.envelope().metadata() {
            return Err(EnvelopeValidationFailure::UnsupportedContract);
        }
        // Controlled replay can use a new transport ID; frozen source identity and every authored fact remain unchanged.
        Ok(challenge.verified())
    }
}
#[derive(Default)]
pub struct AuditProjectionReport {
    pub projected: usize,
    pub deferred: usize,
    pub recoveries: Vec<PgProjectionRecovery>,
    pub failure: Option<AuditProjectionError>,
}
pub struct AuditProjection<K> {
    projection: PgLocalProjection<Effect, K>,
    validator: Validator,
    fatal: Arc<OnceLock<AuditProjectionError>>,
}
impl<K: Aead + Send + Sync> AuditProjection<K> {
    pub async fn new(
        runtime: Arc<PgRuntime>,
        audit: Arc<PgAudit>,
        tenants: Vec<TenantId>,
        protector: Arc<K>,
        delivery: DeliveryBudget,
        deadline: OperationDeadline,
    ) -> Result<Self, AuditProjectionError> {
        if tenants.is_empty() {
            return Err(AuditProjectionError::Configuration);
        }
        let cutoff = Deadline::from_timeout(&RuntimeTimer, deadline.timeout())
            .map_err(|_| AuditProjectionError::Configuration)?;
        runtime
            .local_tx_with_context(tenants[0], remaining(cutoff), &audit, |audit, tx| {
                Box::pin(async move { audit.validate_in(tx).await.map_err(Into::into) })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)
            .map_err(AuditProjectionError::pg)?;
        let capture = PgRecoveryCapture::new(runtime, protector, remaining(cutoff))
            .await
            .map_err(|error| {
                use rss_transactional_messaging_recovery::{Error, StoreFailureKind};
                match error {
                    Error::Deadline | Error::Store(StoreFailureKind::Transient) => {
                        AuditProjectionError::Unavailable
                    }
                    Error::Store(StoreFailureKind::OwnershipLost) => AuditProjectionError::Fenced,
                    Error::Store(StoreFailureKind::Invariant) => AuditProjectionError::Integrity,
                    _ => AuditProjectionError::Permanent,
                }
            })?;
        let fatal = Arc::new(OnceLock::new());
        let projection = PgLocalProjection::new(
            capture,
            ConsumerGroup::parse(GROUP).map_err(|_| AuditProjectionError::Configuration)?,
            MessagingDomain::parse(DOMAIN).map_err(|_| AuditProjectionError::Configuration)?,
            Effect {
                audit,
                fatal: fatal.clone(),
            },
            delivery,
            LeaseRenewalPolicy::from_ttl(delivery.lease_ttl())
                .map_err(|_| AuditProjectionError::Configuration)?,
            remaining(cutoff),
        )
        .await
        .map_err(AuditProjectionError::pg)?;
        if projection
            .has_dead_letters(remaining(cutoff))
            .await
            .map_err(AuditProjectionError::pg)?
        {
            return Err(AuditProjectionError::Quarantined);
        }
        Ok(Self {
            projection,
            validator: Validator { tenants },
            fatal,
        })
    }
    pub async fn next_wakeup(
        &self,
        deadline: OperationDeadline,
    ) -> Result<OutboxWakeup, AuditProjectionError> {
        self.check()?;
        self.projection
            .next_wakeup(deadline)
            .await
            .map_err(AuditProjectionError::pg)
    }
    fn check(&self) -> Result<(), AuditProjectionError> {
        self.fatal.get().copied().map_or(Ok(()), Err)
    }
    fn terminal(&self, disposition: TerminalDisposition) -> Result<(), AuditProjectionError> {
        if disposition != TerminalDisposition::Succeeded {
            let _ = self.fatal.set(AuditProjectionError::Quarantined);
        }
        self.check()
    }
    fn consume(
        &self,
        attempt: PgProjectionAttempt,
        report: &mut AuditProjectionReport,
    ) -> Result<(), AuditProjectionError> {
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        let (outcome, identity) = attempt.into_parts();
        if matches!(
            outcome.status(),
            Status::CommitUnknown | Status::RollbackFailed
        ) {
            report.recoveries.push(identity);
        }
        self.check()?;
        let projected = outcome.fold(
            |value| {
                self.terminal(value.into_parts().1.disposition())?;
                Ok(true)
            },
            |_| Ok(false),
            |_| Ok(false),
            || Err(AuditProjectionError::RollbackFailed),
            || Err(AuditProjectionError::CommitUnknown),
            || Err(AuditProjectionError::Fenced),
        )?;
        if projected {
            report.projected += 1;
        } else {
            report.deferred += 1;
        }
        Ok(())
    }
    /// One real provider claim; the host owns every returned recovery identity.
    /// All sibling results are retained even when another event fails.
    pub async fn project_batch(
        &self,
        limit: NonZeroUsize,
        claim_deadline: OperationDeadline,
        execution_budget: std::time::Duration,
    ) -> Result<AuditProjectionReport, AuditProjectionError> {
        self.check()?;
        let mut report = AuditProjectionReport::default();
        let batch = self
            .projection
            .project_batch(&self.validator, limit, claim_deadline, execution_budget)
            .await
            .map_err(|error| {
                self.fatal
                    .get()
                    .copied()
                    .unwrap_or_else(|| AuditProjectionError::pg(error))
            })?;
        let mut failure = None;
        for item in batch {
            let result = match item.into_outcome() {
                Ok(PgProjectionOutcome::InProgress) => {
                    report.deferred += 1;
                    Ok(())
                }
                Ok(PgProjectionOutcome::Attempt(attempt)) => self.consume(*attempt, &mut report),
                Ok(PgProjectionOutcome::Rejected(_) | PgProjectionOutcome::DeliveryExpired) => {
                    let _ = self.fatal.set(AuditProjectionError::Quarantined);
                    Err(AuditProjectionError::Quarantined)
                }
                Err(error) => Err(AuditProjectionError::pg(error)),
            };
            // Every sibling may carry an uncertain transaction identity. Never short-circuit.
            if let Err(error) = result
                && failure.is_none_or(|previous: AuditProjectionError| previous.is_retryable())
            {
                failure = Some(error);
            }
        }
        report.failure = self.fatal.get().copied().or(failure);
        Ok(report)
    }
    /// `false` is absence of terminal proof, not rollback or permission to execute the effect.
    /// The original durable lease/Inbox decides whether a subsequent claim can execute it.
    pub async fn resolve(
        &self,
        identity: &PgProjectionRecovery,
        deadline: OperationDeadline,
    ) -> Result<bool, AuditProjectionError> {
        match self
            .projection
            .resolve(identity, deadline)
            .await
            .map_err(AuditProjectionError::pg)?
        {
            Some(receipt) => {
                self.terminal(receipt.disposition())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
fn remaining(cutoff: Deadline) -> OperationDeadline {
    OperationDeadline::from_cutoff(cutoff, &RuntimeTimer)
}

#[cfg(feature = "integration")]
impl<K: Aead + Send + Sync> AuditProjection<K> {
    /// Bind fixture uncertainty to the actual effect transaction, never a sibling claim.
    pub fn inject_next_projection_fault(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
        before_acquire: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), AuditProjectionError> {
        self.projection
            .inject_next_projection_fault(fault, before_acquire)
            .map_err(AuditProjectionError::pg)
    }
}
