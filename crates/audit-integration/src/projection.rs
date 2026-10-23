//! MDM's fixed source consumer. RSS owns effect/Inbox/Outbox settlement and recovery identity.
use crate::{
    Error,
    budget::RuntimeTimer,
    source::{DOMAIN, FrozenFact, GROUP},
};
use rss_audit_postgres::PgAudit;
use rss_data_protection::Aead;
use rss_request_context::{Clock, Deadline, TenantId};
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
            Self::Unavailable | Self::CommitUnknown | Self::RollbackFailed
        )
    }
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Unavailable => "unavailable",
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
            Kind::Transient | Kind::DeadlineElapsed => Self::Unavailable,
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
    pub transaction_status: Option<&'static str>,
    pub resolution: Option<&'static str>,
}
pub struct AuditProjection<K> {
    projection: PgLocalProjection<Effect, K>,
    validator: Validator,
    pending: tokio::sync::Mutex<Option<PgProjectionRecovery>>,
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
            pending: tokio::sync::Mutex::new(None),
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
        pending: &mut Option<PgProjectionRecovery>,
        report: &mut AuditProjectionReport,
    ) -> Result<(), AuditProjectionError> {
        use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
        let (outcome, identity) = attempt.into_parts();
        observe("transaction", outcome.status().as_label());
        report.transaction_status = Some(outcome.status().as_label());
        if matches!(
            outcome.status(),
            Status::CommitUnknown | Status::RollbackFailed
        ) {
            *pending = Some(identity);
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
    pub async fn run_once(
        &self,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> Result<AuditProjectionReport, AuditProjectionError> {
        self.check()?;
        let cutoff = Deadline::from_timeout(&RuntimeTimer, deadline.timeout())
            .map_err(|_| AuditProjectionError::Configuration)?;
        let mut pending = tokio::time::timeout(remaining(cutoff).timeout(), self.pending.lock())
            .await
            .map_err(|_| AuditProjectionError::Unavailable)?;
        let mut report = AuditProjectionReport::default();
        if let Some(identity) = pending.as_ref() {
            let result = self.projection.resolve(identity, remaining(cutoff)).await;
            observe(
                "resolve",
                match &result {
                    Ok(Some(_)) => "confirmed",
                    Ok(None) => "unresolved",
                    Err(_) => "failed",
                },
            );
            match result.map_err(AuditProjectionError::pg)? {
                Some(receipt) => {
                    self.terminal(receipt.disposition())?;
                    report.projected += 1;
                    report.resolution = Some("confirmed");
                }
                None => report.resolution = Some("unresolved"),
            }
            *pending = None;
        }
        for _ in 0..limit.get() {
            if cutoff.is_expired(RuntimeTimer.now()) {
                break;
            }
            let outcome = self
                .projection
                .project_one(&self.validator, remaining(cutoff))
                .await
                .map_err(|error| {
                    self.fatal
                        .get()
                        .copied()
                        .unwrap_or_else(|| AuditProjectionError::pg(error))
                })?;
            match outcome {
                PgProjectionOutcome::Empty => break,
                PgProjectionOutcome::InProgress => report.deferred += 1,
                PgProjectionOutcome::Attempt(attempt) => {
                    self.consume(*attempt, &mut pending, &mut report)?
                }
                PgProjectionOutcome::Rejected(_) | PgProjectionOutcome::DeliveryExpired => {
                    let _ = self.fatal.set(AuditProjectionError::Quarantined);
                    return Err(AuditProjectionError::Quarantined);
                }
            }
        }
        Ok(report)
    }
}
fn remaining(cutoff: Deadline) -> OperationDeadline {
    OperationDeadline::from_cutoff(cutoff, &RuntimeTimer)
}

fn observe(phase: &'static str, status: &'static str) {
    use std::io::Write;
    let mut output = std::io::stderr().lock();
    let event = serde_json::json!({"component":"mdm-audit","event":"audit_projection","phase":phase,"status":status});
    let _ = serde_json::to_writer(&mut output, &event);
    let _ = writeln!(output);
}
