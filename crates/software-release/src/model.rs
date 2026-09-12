use crate::{
    ActorId, CandidateId, Digest, Error, PublicationId,
    identity::{Encoding, checked_name, validate_name},
};
use rss_contract::Timepoint;

/// Named composition/storage input. [`SoftwareIdentity::new`] validates all fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareIdentityFields {
    /// Internal source identity, not a URL or credential.
    pub source: String,
    /// Exact package identity supplied by the source adapter.
    pub package: String,
    /// Exact version label; the core does not interpret version ordering.
    pub version: String,
    /// Target platform key, such as `windows` or `macos`.
    pub platform: String,
    /// Target architecture key, such as `x64` or `arm64`.
    pub architecture: String,
    /// Variant that distinguishes artifacts for the same package/version/platform.
    pub variant: String,
}
impl SoftwareIdentityFields {
    fn values(&self) -> [&str; 6] {
        [
            &self.source,
            &self.package,
            &self.version,
            &self.platform,
            &self.architecture,
            &self.variant,
        ]
    }
}
/// Validated exact software identity, immutable after construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareIdentity(SoftwareIdentityFields);
impl SoftwareIdentity {
    /// Validates all six exact fields using the bounded syntax of [`ActorId::new`].
    ///
    /// # Errors
    /// Returns [`Error::InvalidIdentity`] if any field is invalid; no normalization occurs.
    pub fn new(fields: SoftwareIdentityFields) -> Result<Self, Error> {
        for value in fields.values() {
            validate_name(value)?;
        }
        Ok(Self(fields))
    }
    /// Returns the validated fields without allowing mutation of the identity.
    pub fn fields(&self) -> &SoftwareIdentityFields {
        &self.0
    }
}
/// One named artifact digest in the caller-declared, complete content set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    key: String,
    digest: Digest,
}
impl Artifact {
    /// Binds a digest to a key using the bounded syntax of [`ActorId::new`].
    ///
    /// # Errors
    /// Returns [`Error::InvalidIdentity`] for an invalid key.
    pub fn new(key: impl Into<String>, digest: Digest) -> Result<Self, Error> {
        Ok(Self {
            key: checked_name(key.into())?,
            digest,
        })
    }
    /// Returns the exact artifact key used for ordering and duplicate detection.
    pub fn key(&self) -> &str {
        &self.key
    }
    /// Returns the digest attested by the caller; the core never downloads bytes.
    pub fn digest(&self) -> Digest {
        self.digest
    }
}
/// Immutable content. No URLs, credentials, executable code or provider types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Content {
    software: SoftwareIdentity,
    description: Digest,
    source_snapshot: Digest,
    manifest: Digest,
    artifacts: Vec<Artifact>,
}
impl Content {
    /// Creates immutable content and sorts artifacts by key for canonical hashing.
    /// The caller supplies the complete artifact set, including required dependencies.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArtifacts`] unless there are 1–256 distinct artifact keys.
    pub fn new(
        software: SoftwareIdentity,
        description: Digest,
        source_snapshot: Digest,
        manifest: Digest,
        mut artifacts: Vec<Artifact>,
    ) -> Result<Self, Error> {
        if artifacts.is_empty() || artifacts.len() > 256 {
            return Err(Error::InvalidArtifacts);
        }
        artifacts.sort_by(|a, b| a.key.cmp(&b.key));
        if artifacts.windows(2).any(|w| w[0].key == w[1].key) {
            return Err(Error::InvalidArtifacts);
        }
        Ok(Self {
            software,
            description,
            source_snapshot,
            manifest,
            artifacts,
        })
    }
    /// Returns the exact software identity that replacement cannot change.
    pub fn software(&self) -> &SoftwareIdentity {
        &self.software
    }
    /// Returns the digest of the approved description, not its text.
    pub fn description(&self) -> Digest {
        self.description
    }
    /// Returns the digest of the source snapshot used to obtain this content.
    pub fn source_snapshot(&self) -> Digest {
        self.source_snapshot
    }
    /// Returns the manifest digest included in every approval's content binding.
    pub fn manifest(&self) -> Digest {
        self.manifest
    }
    /// Returns all declared artifacts in ascending key order.
    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }
    /// Hashes every identity field, metadata digest and ordered artifact under the V1 content domain.
    pub fn digest(&self) -> Digest {
        let mut e = Encoding::new(b"rss-mdm-software-release/content/v1");
        for part in self.software.fields().values() {
            e.bytes(part.as_bytes());
        }
        e.digest(self.description);
        e.digest(self.source_snapshot);
        e.digest(self.manifest);
        e.number(self.artifacts.len() as u64);
        for a in &self.artifacts {
            e.bytes(a.key.as_bytes());
            e.digest(a.digest);
        }
        e.finish()
    }
}
/// Fixed promotion order; each ring requires its own validation and approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ring {
    /// First ring; validation must not predate the current content.
    Test,
    /// Requires a confirmed Test publication and subsequent validation evidence.
    Pilot,
    /// Requires a confirmed Pilot publication and subsequent validation evidence.
    Production,
}
impl Ring {
    /// All rings in their only supported promotion order.
    pub const ALL: [Self; 3] = [Self::Test, Self::Pilot, Self::Production];
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Test => 0,
            Self::Pilot => 1,
            Self::Production => 2,
        }
    }
}
/// Caller-selected separation constraint bound into the approval fingerprint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ActorPolicy {
    /// Requires distinct publisher and approver identities; the default.
    #[default]
    Separate,
    /// Explicitly permits one actor to publish and approve.
    AllowSameActor,
}
/// Candidate-wide publication permission, independent of recorded backend facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// New validations, approvals and publication decisions remain possible.
    Active,
    /// Closed by quarantine; no reopening, but late results remain recordable.
    Quarantined,
    /// Closed by deprecation; no reopening or conversion to quarantine.
    Deprecated,
}
/// Caller-attested validation conclusion; the core does not execute validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The bound content passed the caller's required checks.
    Passed,
    /// Validation failed; any existing approval is invalidated.
    Failed,
    /// Validation is inconclusive; it cannot support an approval.
    Unknown,
}

/// Caller-attested evidence; authenticity and completeness are the caller's responsibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Tenant-scoped attesting actor, authenticated by the adapter.
    pub actor: ActorId,
    /// Digest binding the caller's retained evidence record.
    pub digest: Digest,
    /// Explicit UTC observation time; checked against the facts it supports.
    pub at: Timepoint,
}
/// Validation of one candidate's exact content for a specific ring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validation {
    /// Candidate identity, including its tenant.
    pub candidate: CandidateId,
    /// Current [`Content::digest`]; stale content is rejected.
    pub content: Digest,
    /// Ring for which this evidence was collected.
    pub ring: Ring,
    /// Evidence no earlier than current content or predecessor success, and not from the future.
    pub evidence: Evidence,
    /// Conclusion that determines whether this validation can support approval.
    pub verdict: Verdict,
}
/// Immutable authority snapshot admitted by [`crate::Candidate`] after validation.
/// Public fields are storage input, not proof of authorization on their own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    /// Passed validation binding candidate, content, ring and evidence.
    pub validation: Validation,
    /// Only this actor may authorize or retry the publication.
    pub publisher: ActorId,
    /// Actor that issued the approval request.
    pub approver: ActorId,
    /// Explicit separation rule checked against publisher and approver.
    pub policy: ActorPolicy,
    /// UTC approval time, no earlier than validation evidence.
    pub at: Timepoint,
    /// Confirmed previous ring's publication identity; `None` only for Test.
    pub predecessor: Option<PublicationId>,
}
impl Approval {
    /// Hashes the complete authority snapshot under the V1 approval domain.
    pub fn digest(&self) -> Digest {
        let mut e = Encoding::new(b"rss-mdm-software-release/approval/v1");
        encode_validation(&mut e, &self.validation);
        e.object(self.publisher.tenant(), self.publisher.value());
        e.object(self.approver.tenant(), self.approver.value());
        e.number(match self.policy {
            ActorPolicy::Separate => 0,
            ActorPolicy::AllowSameActor => 1,
        });
        encode_time(&mut e, self.at);
        match self.predecessor {
            Some(id) => {
                e.number(1);
                e.digest(id.digest());
            }
            None => e.number(0),
        }
        e.finish()
    }
    /// Derives a stable publication identity from this approval, excluding attempts and requests.
    pub fn publication_id(&self) -> PublicationId {
        let mut e = Encoding::new(b"rss-mdm-software-release/publication/v1");
        e.digest(self.digest());
        PublicationId(e.finish())
    }
}
/// Result states always retain the authorization, even after withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    /// Authorized locally; whether an external call started or succeeded is still unconfirmed.
    Pending,
    /// Caller-attested observation for the current attempt.
    Reported(PublicationResult),
}
/// An observation of an external attempt; Pending is not a reportable result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationResult {
    /// Uncertain outcome: reconcile the original identity and never retry blindly.
    Unknown(Evidence),
    /// This attempt did not apply and can no longer apply; permits an explicit retry.
    /// A temporarily missing backend record does not establish this conclusion.
    NotApplied(Evidence),
    /// Backend content was verified against the approval; contradictory results are rejected.
    Applied(Evidence),
}
impl PublicationResult {
    /// Returns the evidence retained by every reportable result.
    pub fn evidence(&self) -> &Evidence {
        match self {
            Self::Unknown(e) | Self::NotApplied(e) | Self::Applied(e) => e,
        }
    }
}
/// Current external attempt, retaining its original approval even after withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    /// Original authority snapshot, unchanged across retries.
    pub approval: Approval,
    /// Nonzero attempt number, incremented only after confirmed NotApplied.
    pub attempt: u64,
    /// UTC time this attempt was authorized; result evidence cannot predate it.
    pub authorized_at: Timepoint,
    /// Current attempt's pending state or retained backend report.
    pub outcome: PublicationOutcome,
}
impl Publication {
    /// Returns the approval-derived identity, stable across attempts.
    pub fn id(&self) -> PublicationId {
        self.approval.publication_id()
    }
}
/// Public storage input; only [`crate::Candidate::restore`] admits it as a valid aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RingState {
    /// No validation has begun; valid only for Pilot and Production.
    NotStarted,
    /// Awaiting passed validation, including after failed or unknown validation.
    Candidate,
    /// Passed evidence for the current content; not yet approved.
    Validated(Validation),
    /// Approved authority snapshot; no publication attempt yet.
    Approved(Approval),
    /// An authorized attempt and its pending or reported outcome.
    Publication(Publication),
}
impl RingState {
    /// Reports only confirmed Applied, even if the candidate has since been withdrawn.
    pub fn is_published(&self) -> bool {
        matches!(
            self,
            Self::Publication(Publication {
                outcome: PublicationOutcome::Reported(PublicationResult::Applied(_)),
                ..
            })
        )
    }
}
pub(crate) fn encode_time(e: &mut Encoding, time: Timepoint) {
    e.number(time.unix_seconds() as u64);
}
pub(crate) fn encode_evidence(e: &mut Encoding, evidence: &Evidence) {
    e.object(evidence.actor.tenant(), evidence.actor.value());
    e.digest(evidence.digest);
    encode_time(e, evidence.at);
}
pub(crate) fn encode_validation(e: &mut Encoding, v: &Validation) {
    e.object(v.candidate.tenant(), v.candidate.value());
    e.digest(v.content);
    e.number(v.ring.index() as u64);
    encode_evidence(e, &v.evidence);
    e.number(match v.verdict {
        Verdict::Passed => 0,
        Verdict::Failed => 1,
        Verdict::Unknown => 2,
    });
}
