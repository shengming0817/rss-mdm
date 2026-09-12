use crate::*;
use rss_contract::Timepoint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    Replace(Content),
    Validate(Validation),
    Approve {
        ring: Ring,
        publisher: ActorId,
        policy: ActorPolicy,
    },
    Authorize {
        ring: Ring,
        approval: Digest,
    },
    Retry {
        ring: Ring,
        publication: PublicationId,
        attempt: u64,
    },
    Record {
        ring: Ring,
        publication: PublicationId,
        attempt: u64,
        outcome: PublicationOutcome,
    },
    Quarantine,
    Deprecate,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub id: RequestId,
    pub actor: ActorId,
    pub expected_revision: u64,
    pub as_of: Timepoint,
    pub operation: Operation,
}
/// Persisted data, not an executable authorization or an authenticated receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub candidate: CandidateId,
    pub request: RequestId,
    pub fingerprint: Digest,
    pub before_revision: u64,
    pub revision: u64,
    pub at: Timepoint,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Updated,
    ValidationRejected(Verdict),
    Publish(Box<Publication>),
    Reconcile {
        publication: PublicationId,
        attempt: u64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transition {
    Applied {
        next: Box<Candidate>,
        receipt: Receipt,
        decision: Decision,
    },
    Replayed(Receipt),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: CandidateId,
    pub revision: u64,
    pub at: Timepoint,
    pub content: Content,
    pub disposition: Disposition,
    pub rings: [RingState; 3],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate(Snapshot);
impl Candidate {
    pub fn new(id: CandidateId, content: Content, as_of: Timepoint) -> Self {
        Self(Snapshot {
            id,
            content,
            revision: 0,
            at: as_of,
            disposition: Disposition::Active,
            rings: [
                RingState::Candidate,
                RingState::NotStarted,
                RingState::NotStarted,
            ],
        })
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.0
    }
    /// Validates storage structure and all linked evidence. The adapter authenticates
    /// the storage source and must preserve history, uniqueness and CAS across requests.
    pub fn restore(snapshot: Snapshot) -> Result<Self, Error> {
        let candidate = Self(snapshot);
        candidate.check_snapshot()?;
        Ok(candidate)
    }
    /// Pure decision. Apply snapshot + receipt using CAS before executing Publish.
    /// Supply the original request unchanged for replay; a replay has no executable output.
    pub fn transition(
        &self,
        request: Request,
        previous: Option<&Receipt>,
    ) -> Result<Transition, Error> {
        self.tenant(request.id.tenant())?;
        self.tenant(request.actor.tenant())?;
        let fingerprint = crate::fingerprint::request(&self.0.id, &request);
        if let Some(receipt) = previous {
            self.check_receipt(&request, fingerprint, receipt)?;
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
        let decision = next.apply(&request)?;
        next.0.revision = next.0.revision.checked_add(1).ok_or(Error::Overflow)?;
        next.0.at = request.as_of;
        next.check_snapshot()?;
        let receipt = Receipt {
            candidate: self.0.id.clone(),
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
    fn check_receipt(
        &self,
        request: &Request,
        fingerprint: Digest,
        receipt: &Receipt,
    ) -> Result<(), Error> {
        if receipt.candidate != self.0.id
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
        Ok(())
    }
    fn tenant(&self, tenant: rss_request_context::TenantId) -> Result<(), Error> {
        if tenant != self.0.id.tenant() {
            return Err(Error::TenantMismatch);
        }
        Ok(())
    }
    fn evidence(
        &self,
        evidence: &Evidence,
        earliest: Option<Timepoint>,
        at: Timepoint,
    ) -> Result<(), Error> {
        self.tenant(evidence.actor.tenant())?;
        if evidence.at > at || earliest.is_some_and(|t| evidence.at < t) {
            return Err(Error::InvalidTime);
        }
        Ok(())
    }
    fn predecessor(&self, ring: Ring) -> Result<Option<&Publication>, Error> {
        if ring == Ring::Test {
            return Ok(None);
        }
        match &self.0.rings[ring.index() - 1] {
            RingState::Publication(p) if matches!(p.outcome, PublicationOutcome::Applied(_)) => {
                Ok(Some(p))
            }
            _ => Err(Error::PromotionBlocked),
        }
    }
    fn validation(&self, v: &Validation, ring: Ring, at: Timepoint) -> Result<(), Error> {
        self.tenant(v.candidate.tenant())?;
        if v.candidate != self.0.id || v.content != self.0.content.digest() || v.ring != ring {
            return Err(Error::StaleEvidence);
        }
        let predecessor = self.predecessor(ring)?;
        let earliest = predecessor.and_then(|p| match &p.outcome {
            PublicationOutcome::Applied(e) => Some(e.at),
            _ => None,
        });
        self.evidence(&v.evidence, earliest, at)
    }
    fn approval(&self, approval: &Approval, ring: Ring, at: Timepoint) -> Result<(), Error> {
        self.validation(&approval.validation, ring, approval.at)?;
        if approval.validation.verdict != Verdict::Passed {
            return Err(Error::ValidationRequired);
        }
        self.tenant(approval.publisher.tenant())?;
        self.tenant(approval.approver.tenant())?;
        if approval.policy == ActorPolicy::Separate && approval.publisher == approval.approver {
            return Err(Error::ActorConstraint);
        }
        if approval.at > at {
            return Err(Error::InvalidTime);
        }
        if approval.predecessor != self.predecessor(ring)?.map(Publication::id) {
            return Err(Error::StaleEvidence);
        }
        Ok(())
    }
    fn check_snapshot(&self) -> Result<(), Error> {
        if self.0.revision == 0
            && (self.0.disposition != Disposition::Active
                || self.0.rings
                    != [
                        RingState::Candidate,
                        RingState::NotStarted,
                        RingState::NotStarted,
                    ])
        {
            return Err(Error::InvalidSnapshot);
        }
        for ring in Ring::ALL {
            match &self.0.rings[ring.index()] {
                RingState::NotStarted if ring != Ring::Test => (),
                RingState::NotStarted => return Err(Error::InvalidSnapshot),
                RingState::Candidate => {
                    self.predecessor(ring)?;
                }
                RingState::Validated(v) => {
                    self.validation(v, ring, self.0.at)?;
                    if v.verdict != Verdict::Passed {
                        return Err(Error::ValidationRequired);
                    }
                }
                RingState::Approved(a) => self.approval(a, ring, self.0.at)?,
                RingState::Publication(p) => {
                    self.approval(&p.approval, ring, p.authorized_at)?;
                    if p.attempt == 0 {
                        return Err(Error::InvalidSnapshot);
                    }
                    if p.authorized_at > self.0.at {
                        return Err(Error::InvalidTime);
                    }
                    if let Some(e) = outcome_evidence(&p.outcome) {
                        self.evidence(e, Some(p.authorized_at), self.0.at)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn apply(&mut self, request: &Request) -> Result<Decision, Error> {
        if self.0.disposition != Disposition::Active
            && !matches!(
                request.operation,
                Operation::Record { .. } | Operation::Quarantine | Operation::Deprecate
            )
        {
            return Err(Error::PublicationClosed);
        }
        match &request.operation {
            Operation::Replace(content) => {
                if content.software() != self.0.content.software() {
                    return Err(Error::ContentConflict);
                }
                if *content != self.0.content {
                    if self
                        .0
                        .rings
                        .iter()
                        .any(|r| matches!(r, RingState::Publication(_)))
                    {
                        return Err(Error::ContentFrozen);
                    }
                    self.0.content = content.clone();
                    self.0.rings = [
                        RingState::Candidate,
                        RingState::NotStarted,
                        RingState::NotStarted,
                    ];
                }
                Ok(Decision::Updated)
            }
            Operation::Validate(v) => {
                self.validation(v, v.ring, request.as_of)?;
                let state = &mut self.0.rings[v.ring.index()];
                if matches!(state, RingState::Publication(_)) {
                    return Err(Error::ContentFrozen);
                }
                if v.verdict == Verdict::Passed {
                    // An exact re-observation does not invalidate an approval.
                    let same = match state {
                        RingState::Validated(old) => old == v,
                        RingState::Approved(a) => a.validation == *v,
                        _ => false,
                    };
                    if !same {
                        *state = RingState::Validated(v.clone());
                    }
                    Ok(Decision::Updated)
                } else {
                    *state = RingState::Candidate;
                    Ok(Decision::ValidationRejected(v.verdict))
                }
            }
            Operation::Approve {
                ring,
                publisher,
                policy,
            } => {
                self.tenant(publisher.tenant())?;
                self.predecessor(*ring)?;
                let validation = match &self.0.rings[ring.index()] {
                    RingState::Validated(v) => v.clone(),
                    RingState::Approved(a) => a.validation.clone(),
                    _ => return Err(Error::ValidationRequired),
                };
                let approval = Approval {
                    validation,
                    publisher: publisher.clone(),
                    approver: request.actor.clone(),
                    policy: *policy,
                    at: request.as_of,
                    predecessor: self.predecessor(*ring)?.map(Publication::id),
                };
                self.approval(&approval, *ring, request.as_of)?;
                self.0.rings[ring.index()] = RingState::Approved(approval);
                Ok(Decision::Updated)
            }
            Operation::Authorize { ring, approval } => self.authorize(*ring, *approval, request),
            Operation::Retry {
                ring,
                publication,
                attempt,
            } => self.retry(*ring, *publication, *attempt, request),
            Operation::Record {
                ring,
                publication,
                attempt,
                outcome,
            } => self.record(*ring, *publication, *attempt, outcome, request.as_of),
            Operation::Quarantine => {
                if self.0.disposition == Disposition::Deprecated {
                    return Err(Error::InvalidTransition);
                }
                self.0.disposition = Disposition::Quarantined;
                Ok(Decision::Updated)
            }
            Operation::Deprecate => {
                if self.0.disposition == Disposition::Quarantined {
                    return Err(Error::InvalidTransition);
                }
                self.0.disposition = Disposition::Deprecated;
                Ok(Decision::Updated)
            }
        }
    }
    fn authorize(
        &mut self,
        ring: Ring,
        digest: Digest,
        request: &Request,
    ) -> Result<Decision, Error> {
        self.predecessor(ring)?;
        let approval = match &self.0.rings[ring.index()] {
            RingState::Approved(a) => a,
            RingState::Publication(p) => &p.approval,
            _ => return Err(Error::ValidationRequired),
        };
        if approval.digest() != digest {
            return Err(Error::StaleEvidence);
        }
        if approval.publisher != request.actor {
            return Err(Error::ActorConstraint);
        }
        if let RingState::Publication(p) = &self.0.rings[ring.index()] {
            return match p.outcome {
                PublicationOutcome::Pending | PublicationOutcome::Unknown(_) => {
                    Ok(Decision::Reconcile {
                        publication: p.id(),
                        attempt: p.attempt,
                    })
                }
                PublicationOutcome::Applied(_) => Ok(Decision::Updated),
                PublicationOutcome::NotApplied(_) => Err(Error::ReconciliationRequired),
            };
        }
        let publication = Publication {
            approval: approval.clone(),
            attempt: 1,
            authorized_at: request.as_of,
            outcome: PublicationOutcome::Pending,
        };
        self.0.rings[ring.index()] = RingState::Publication(publication.clone());
        Ok(Decision::Publish(Box::new(publication)))
    }
    fn retry(
        &mut self,
        ring: Ring,
        id: PublicationId,
        attempt: u64,
        request: &Request,
    ) -> Result<Decision, Error> {
        let publication = self.publication_mut(ring, id, attempt)?;
        if publication.approval.publisher != request.actor {
            return Err(Error::ActorConstraint);
        }
        if !matches!(publication.outcome, PublicationOutcome::NotApplied(_)) {
            return Err(Error::ReconciliationRequired);
        }
        publication.attempt = publication.attempt.checked_add(1).ok_or(Error::Overflow)?;
        publication.authorized_at = request.as_of;
        publication.outcome = PublicationOutcome::Pending;
        Ok(Decision::Publish(Box::new(publication.clone())))
    }
    fn publication_mut(
        &mut self,
        ring: Ring,
        id: PublicationId,
        attempt: u64,
    ) -> Result<&mut Publication, Error> {
        match &mut self.0.rings[ring.index()] {
            RingState::Publication(p) if p.id() == id && p.attempt == attempt => Ok(p),
            _ => Err(Error::IdentityMismatch),
        }
    }
    fn record(
        &mut self,
        ring: Ring,
        id: PublicationId,
        attempt: u64,
        outcome: &PublicationOutcome,
        at: Timepoint,
    ) -> Result<Decision, Error> {
        let evidence = outcome_evidence(outcome).ok_or(Error::InvalidTransition)?;
        self.evidence(evidence, None, at)?;
        let publication = self.publication_mut(ring, id, attempt)?;
        if evidence.at < publication.authorized_at
            || outcome_evidence(&publication.outcome).is_some_and(|e| evidence.at < e.at)
        {
            return Err(Error::InvalidTime);
        }
        match &publication.outcome {
            PublicationOutcome::Pending | PublicationOutcome::Unknown(_) => {
                publication.outcome = outcome.clone()
            }
            terminal if terminal == outcome => (),
            _ => return Err(Error::ResultConflict),
        }
        if matches!(outcome, PublicationOutcome::Unknown(_)) {
            Ok(Decision::Reconcile {
                publication: id,
                attempt,
            })
        } else {
            Ok(Decision::Updated)
        }
    }
}
fn outcome_evidence(outcome: &PublicationOutcome) -> Option<&Evidence> {
    match outcome {
        PublicationOutcome::Pending => None,
        PublicationOutcome::Unknown(e)
        | PublicationOutcome::NotApplied(e)
        | PublicationOutcome::Applied(e) => Some(e),
    }
}
