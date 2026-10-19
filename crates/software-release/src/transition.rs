use crate::*;
use rss_contract::Timepoint;

/// Authenticated adapter inputs for an existing publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Retry only a confirmed non-applied current attempt.
    Retry {
        /// Original effect identity.
        publication: PublicationId,
        /// Current attempt being replaced.
        attempt: u64,
    },
    /// Record a fact, including after withdrawal, without reopening admission.
    Record {
        /// Exact effect identity.
        publication: PublicationId,
        /// Current attempt; stale results cannot overwrite a newer attempt.
        attempt: u64,
        /// Source-verified result.
        outcome: PublicationResult,
    },
    /// Close this publication to new consumption and retry; retain all source facts.
    Withdraw,
}
/// Original request envelope; retain every field for idempotent replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Tenant-scoped idempotency key.
    pub id: RequestId,
    /// Authenticated operator.
    pub actor: ActorId,
    /// Expected aggregate revision.
    pub expected_revision: u64,
    /// UTC decision time.
    pub as_of: Timepoint,
    /// Complete requested operation.
    pub operation: Operation,
}
/// Original immutable acknowledgement, distinct from current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Publication record identity.
    pub publication: PublicationKey,
    /// Original request identity.
    pub request: RequestId,
    /// Canonical fingerprint of all original request fields.
    pub fingerprint: Digest,
    /// Revision checked by the original request.
    pub before_revision: u64,
    /// Resulting revision.
    pub revision: u64,
    /// Original decision time.
    pub at: Timepoint,
}
/// Work allowed only after the state, audit and receipt are committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// State changed without a new source write.
    Updated,
    /// Execute this exact attempt.
    Publish(Box<Attempt>),
    /// Observe the existing effect rather than creating a new attempt.
    Reconcile {
        /// Existing effect identity.
        publication: PublicationId,
        /// Existing attempt.
        attempt: u64,
    },
}
/// Pure result; the adapter owns atomic persistence and source I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transition {
    /// New state and receipt to persist with CAS.
    Applied {
        /// Validated next aggregate.
        next: Box<Publication>,
        /// Original acknowledgement.
        receipt: Receipt,
        /// Post-commit work.
        decision: Decision,
    },
    /// Historical acknowledgement, with no executable decision.
    Replayed(Receipt),
}
/// Storage input validated by [`Publication::restore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Stable record and tenant identity.
    pub id: PublicationKey,
    /// Monotonic mutation revision.
    pub revision: u64,
    /// Most recent transition time.
    pub at: Timepoint,
    /// Immutable complete export content.
    pub content: Content,
    /// Consumption and retry are closed; source observations remain recordable.
    pub withdrawn: bool,
    /// Current attempt, present from initial acceptance.
    pub attempt: Attempt,
}
/// One immutable version published to one actual target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication(Snapshot);
impl Publication {
    /// Accept verified content and its first attempt; persist before performing source I/O.
    pub fn new(content: Content, binding: PublicationBinding) -> Result<Self, Error> {
        let at = binding.at;
        Self::restore(Snapshot {
            id: binding.publication.clone(),
            revision: 0,
            at,
            content,
            withdrawn: false,
            attempt: Attempt {
                binding,
                attempt: 1,
                requested_at: at,
                outcome: PublicationOutcome::Pending,
            },
        })
    }
    /// Current read-only state.
    pub fn snapshot(&self) -> &Snapshot {
        &self.0
    }
    /// Validate complete persisted identity and time relationships.
    pub fn restore(snapshot: Snapshot) -> Result<Self, Error> {
        let value = Self(snapshot);
        value.check_snapshot()?;
        Ok(value)
    }
    /// Apply a request without effects; errors leave this aggregate unchanged.
    pub fn transition(
        &self,
        request: Request,
        previous: Option<&Receipt>,
    ) -> Result<Transition, Error> {
        self.tenant(request.id.tenant())?;
        self.tenant(request.actor.tenant())?;
        let fingerprint = crate::fingerprint::request(&self.0.id, &request);
        if let Some(receipt) = previous {
            if receipt.publication != self.0.id
                || receipt.request != request.id
                || receipt.fingerprint != fingerprint
            {
                return Err(Error::RequestConflict);
            }
            if receipt.before_revision != request.expected_revision
                || receipt.before_revision.checked_add(1) != Some(receipt.revision)
                || receipt.revision > self.0.revision
                || receipt.at != request.as_of
                || receipt.at > self.0.at
            {
                return Err(Error::InvalidSnapshot);
            }
            return Ok(Transition::Replayed(receipt.clone()));
        }
        if request.expected_revision != self.0.revision {
            return Err(Error::RevisionConflict {
                expected: request.expected_revision,
                actual: self.0.revision,
            });
        }
        if request.as_of < self.0.at {
            return Err(Error::InvalidTime);
        }
        let mut next = self.clone();
        let decision = match &request.operation {
            Operation::Withdraw => {
                next.0.withdrawn = true;
                Decision::Updated
            }
            Operation::Retry {
                publication,
                attempt,
            } => {
                if next.0.withdrawn {
                    return Err(Error::PublicationClosed);
                }
                let p = next.current(*publication, *attempt)?;
                if !matches!(
                    p.outcome,
                    PublicationOutcome::Reported(PublicationResult::NotApplied(_))
                ) {
                    return Err(Error::ReconciliationRequired);
                }
                p.attempt = p.attempt.checked_add(1).ok_or(Error::Overflow)?;
                p.requested_at = request.as_of;
                p.outcome = PublicationOutcome::Pending;
                Decision::Publish(Box::new(p.clone()))
            }
            Operation::Record {
                publication,
                attempt,
                outcome,
            } => {
                next.evidence(outcome.evidence(), request.as_of)?;
                let p = next.current(*publication, *attempt)?;
                if outcome.evidence().at < p.requested_at
                    || outcome_evidence(&p.outcome).is_some_and(|e| outcome.evidence().at < e.at)
                {
                    return Err(Error::InvalidTime);
                }
                match &p.outcome {
                    PublicationOutcome::Pending
                    | PublicationOutcome::Reported(PublicationResult::Unknown(_)) => {
                        p.outcome = PublicationOutcome::Reported(outcome.clone());
                    }
                    PublicationOutcome::Reported(old) if old == outcome => (),
                    _ => return Err(Error::ResultConflict),
                }
                if matches!(outcome, PublicationResult::Unknown(_)) {
                    Decision::Reconcile {
                        publication: *publication,
                        attempt: *attempt,
                    }
                } else {
                    Decision::Updated
                }
            }
        };
        next.0.revision = next.0.revision.checked_add(1).ok_or(Error::Overflow)?;
        next.0.at = request.as_of;
        next.check_snapshot()?;
        let receipt = Receipt {
            publication: self.0.id.clone(),
            request: request.id,
            fingerprint,
            before_revision: self.0.revision,
            revision: next.0.revision,
            at: request.as_of,
        };
        Ok(Transition::Applied {
            next: Box::new(next),
            receipt,
            decision,
        })
    }
    fn current(&mut self, id: PublicationId, attempt: u64) -> Result<&mut Attempt, Error> {
        let p = &mut self.0.attempt;
        if p.id() != id || p.attempt != attempt {
            return Err(Error::IdentityMismatch);
        }
        Ok(p)
    }
    fn tenant(&self, tenant: rss_request_context::TenantId) -> Result<(), Error> {
        if tenant != self.0.id.tenant() {
            return Err(Error::TenantMismatch);
        }
        Ok(())
    }
    fn evidence(&self, evidence: &Evidence, at: Timepoint) -> Result<(), Error> {
        self.tenant(evidence.actor.tenant())?;
        if evidence.at > at {
            return Err(Error::InvalidTime);
        }
        Ok(())
    }
    fn check_snapshot(&self) -> Result<(), Error> {
        let p = &self.0.attempt;
        let b = &p.binding;
        self.tenant(b.target.tenant())?;
        self.tenant(b.actor.tenant())?;
        self.evidence(&b.evidence, b.at)?;
        if b.publication != self.0.id
            || b.target.value() != self.0.content.software().fields().source
            || b.target_digest != self.0.content.source_snapshot()
            || b.content != self.0.content.digest()
            || b.target_digest == Digest::from_bytes([0; 32])
        {
            return Err(Error::IdentityMismatch);
        }
        if p.attempt == 0 || b.at > p.requested_at || p.requested_at > self.0.at {
            return Err(Error::InvalidSnapshot);
        }
        if self.0.revision == 0
            && (self.0.withdrawn
                || p.attempt != 1
                || self.0.at != b.at
                || p.outcome != PublicationOutcome::Pending)
        {
            return Err(Error::InvalidSnapshot);
        }
        if let Some(e) = outcome_evidence(&p.outcome) {
            self.evidence(e, self.0.at)?;
            if e.at < p.requested_at {
                return Err(Error::InvalidTime);
            }
        }
        Ok(())
    }
}
fn outcome_evidence(outcome: &PublicationOutcome) -> Option<&Evidence> {
    match outcome {
        PublicationOutcome::Pending => None,
        PublicationOutcome::Reported(r) => Some(r.evidence()),
    }
}
