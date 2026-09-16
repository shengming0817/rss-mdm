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
}
impl SoftwareIdentityFields {
    fn values(&self) -> [&str; 4] {
        [&self.source, &self.package, &self.version, &self.platform]
    }
}
/// Validated exact software identity, immutable after construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareIdentity(SoftwareIdentityFields);
impl SoftwareIdentity {
    /// Validates all four exact fields using the bounded syntax of [`ActorId::new`].
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
/// One architecture/variant and its complete artifact closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantContent {
    architecture: String,
    variant: String,
    artifacts: Vec<Artifact>,
}
impl VariantContent {
    /// Validate and sort 1–256 artifacts; duplicate keys are rejected.
    pub fn new(
        architecture: impl Into<String>,
        variant: impl Into<String>,
        mut artifacts: Vec<Artifact>,
    ) -> Result<Self, Error> {
        let architecture = checked_name(architecture.into())?;
        let variant = checked_name(variant.into())?;
        if artifacts.is_empty() || artifacts.len() > 256 {
            return Err(Error::InvalidArtifacts);
        }
        artifacts.sort_by(|a, b| a.key.cmp(&b.key));
        if artifacts.windows(2).any(|w| w[0].key == w[1].key) {
            return Err(Error::InvalidArtifacts);
        }
        Ok(Self {
            architecture,
            variant,
            artifacts,
        })
    }
    /// Exact architecture declared by the product mapping.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    /// Exact variant declared by the product mapping.
    pub fn variant(&self) -> &str {
        &self.variant
    }
    /// Complete artifact set in canonical key order.
    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }
}
/// Complete immutable platform package version; no URLs or provider types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Content {
    software: SoftwareIdentity,
    description: Digest,
    source_snapshot: Digest,
    manifest: Digest,
    variants: Vec<VariantContent>,
}
impl Content {
    /// Freeze 1–64 unique variants and at most 256 artifact references.
    /// The same artifact key may be shared only with the same digest.
    pub fn new(
        software: SoftwareIdentity,
        description: Digest,
        source_snapshot: Digest,
        manifest: Digest,
        mut variants: Vec<VariantContent>,
    ) -> Result<Self, Error> {
        if variants.is_empty()
            || variants.len() > 64
            || variants.iter().map(|v| v.artifacts.len()).sum::<usize>() > 256
        {
            return Err(Error::InvalidArtifacts);
        }
        variants.sort_by(|a, b| (&a.architecture, &a.variant).cmp(&(&b.architecture, &b.variant)));
        if variants
            .windows(2)
            .any(|w| (w[0].architecture(), w[0].variant()) == (w[1].architecture(), w[1].variant()))
        {
            return Err(Error::InvalidArtifacts);
        }
        let mut artifacts = std::collections::BTreeMap::new();
        for a in variants.iter().flat_map(|v| &v.artifacts) {
            if artifacts
                .insert(&a.key, a.digest)
                .is_some_and(|old| old != a.digest)
            {
                return Err(Error::InvalidArtifacts);
            }
        }
        Ok(Self {
            software,
            description,
            source_snapshot,
            manifest,
            variants,
        })
    }
    /// Exact platform package version identity.
    pub fn software(&self) -> &SoftwareIdentity {
        &self.software
    }
    /// Approved description digest.
    pub fn description(&self) -> Digest {
        self.description
    }
    /// Approved source/configuration snapshot digest.
    pub fn source_snapshot(&self) -> Digest {
        self.source_snapshot
    }
    /// Complete manifest or controlled document digest.
    pub fn manifest(&self) -> Digest {
        self.manifest
    }
    /// Complete variants in architecture/variant order.
    pub fn variants(&self) -> &[VariantContent] {
        &self.variants
    }
    /// Canonical V2 content identity; V1 single-variant identities are retired.
    pub fn digest(&self) -> Digest {
        let mut e = Encoding::new(b"rss-mdm-software-release/content/v2");
        for part in self.software.fields().values() {
            e.bytes(part.as_bytes());
        }
        e.digest(self.description);
        e.digest(self.source_snapshot);
        e.digest(self.manifest);
        e.number(self.variants.len() as u64);
        for v in &self.variants {
            e.bytes(v.architecture.as_bytes());
            e.bytes(v.variant.as_bytes());
            e.number(v.artifacts.len() as u64);
            for a in &v.artifacts {
                e.bytes(a.key.as_bytes());
                e.digest(a.digest);
            }
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
    /// Hashes the complete authority snapshot under the V2 approval domain.
    pub fn digest(&self) -> Digest {
        let mut e = Encoding::new(b"rss-mdm-software-release/approval/v2");
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
        let mut e = Encoding::new(b"rss-mdm-software-release/publication/v2");
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
