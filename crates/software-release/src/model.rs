use crate::{
    ActorId, CandidateId, Digest, Error, PublicationId,
    identity::{Encoding, checked_name, validate_name},
};
use rss_contract::Timepoint;

/// Named composition/storage input. SoftwareIdentity::new validates all fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareIdentityFields {
    pub source: String,
    pub package: String,
    pub version: String,
    pub platform: String,
    pub architecture: String,
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
    pub fn new(fields: SoftwareIdentityFields) -> Result<Self, Error> {
        for value in fields.values() {
            validate_name(value)?;
        }
        Ok(Self(fields))
    }
    pub fn fields(&self) -> &SoftwareIdentityFields {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    key: String,
    digest: Digest,
}
impl Artifact {
    pub fn new(key: impl Into<String>, digest: Digest) -> Result<Self, Error> {
        Ok(Self {
            key: checked_name(key.into())?,
            digest,
        })
    }
    pub fn key(&self) -> &str {
        &self.key
    }
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
    pub fn software(&self) -> &SoftwareIdentity {
        &self.software
    }
    pub fn description(&self) -> Digest {
        self.description
    }
    pub fn source_snapshot(&self) -> Digest {
        self.source_snapshot
    }
    pub fn manifest(&self) -> Digest {
        self.manifest
    }
    pub fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ring {
    Test,
    Pilot,
    Production,
}
impl Ring {
    pub const ALL: [Self; 3] = [Self::Test, Self::Pilot, Self::Production];
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Test => 0,
            Self::Pilot => 1,
            Self::Production => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ActorPolicy {
    #[default]
    Separate,
    AllowSameActor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Active,
    Quarantined,
    Deprecated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Passed,
    Failed,
    Unknown,
}

/// Caller-attested evidence; authenticity and completeness are the caller's responsibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub actor: ActorId,
    pub digest: Digest,
    pub at: Timepoint,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validation {
    pub candidate: CandidateId,
    pub content: Digest,
    pub ring: Ring,
    pub evidence: Evidence,
    pub verdict: Verdict,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    pub validation: Validation,
    pub publisher: ActorId,
    pub approver: ActorId,
    pub policy: ActorPolicy,
    pub at: Timepoint,
    pub predecessor: Option<PublicationId>,
}
impl Approval {
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
    pub fn publication_id(&self) -> PublicationId {
        let mut e = Encoding::new(b"rss-mdm-software-release/publication/v1");
        e.digest(self.digest());
        PublicationId(e.finish())
    }
}
/// Result states always retain the authorization, even after withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    Pending,
    Reported(PublicationResult),
}
/// An observation of an external attempt; Pending is not a reportable result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationResult {
    Unknown(Evidence),
    NotApplied(Evidence),
    Applied(Evidence),
}
impl PublicationResult {
    pub fn evidence(&self) -> &Evidence {
        match self {
            Self::Unknown(e) | Self::NotApplied(e) | Self::Applied(e) => e,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub approval: Approval,
    pub attempt: u64,
    pub authorized_at: Timepoint,
    pub outcome: PublicationOutcome,
}
impl Publication {
    pub fn id(&self) -> PublicationId {
        self.approval.publication_id()
    }
}
/// Public storage input; only Candidate::restore admits it as a valid aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RingState {
    NotStarted,
    Candidate,
    Validated(Validation),
    Approved(Approval),
    Publication(Publication),
}
impl RingState {
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
