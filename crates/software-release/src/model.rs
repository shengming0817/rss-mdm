use crate::{
    ActorId, Digest, Error, PublicationId, PublicationKey, TargetId,
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
    /// Frozen description digest.
    pub fn description(&self) -> Digest {
        self.description
    }
    /// Frozen source/configuration snapshot digest.
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
    /// Canonical identity of the complete immutable export content.
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
/// Caller-attested source observation; the adapter authenticates it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Tenant-scoped attesting actor.
    pub actor: ActorId,
    /// Digest of the retained technical evidence.
    pub digest: Digest,
    /// Explicit UTC observation time.
    pub at: Timepoint,
}
/// Immutable authority for one actual target publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationBinding {
    /// Tenant-scoped record identity, fixed by the original creation request.
    pub publication: PublicationKey,
    /// Complete frozen export content digest.
    pub content: Digest,
    /// Actual independently configured output target.
    pub target: TargetId,
    /// Exact physical target and protocol configuration snapshot.
    pub target_digest: Digest,
    /// Technical verification performed before accepting publication.
    pub evidence: Evidence,
    /// Source, version and dependency lifecycle fingerprint.
    pub lifecycle: Digest,
    /// Original authenticated operator.
    pub actor: ActorId,
    /// Original publication decision time.
    pub at: Timepoint,
}
impl PublicationBinding {
    /// Stable effect identity; retries and other targets cannot change it.
    pub fn publication_id(&self) -> PublicationId {
        let mut e = Encoding::new(b"rss-mdm-software-release/publication/v4");
        e.object(self.publication.tenant(), self.publication.value());
        e.digest(self.content);
        e.object(self.target.tenant(), self.target.value());
        e.digest(self.target_digest);
        PublicationId(e.finish())
    }
}
/// Current attempt state, independent of withdrawal admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    /// Accepted, with an unconfirmed effect.
    Pending,
    /// Source observation for this attempt.
    Reported(PublicationResult),
}
/// An observation; a missing source record alone does not prove non-application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationResult {
    /// Reconcile the original effect identity; do not blindly retry.
    Unknown(Evidence),
    /// This attempt cannot apply any more; explicit retry is allowed.
    NotApplied(Evidence),
    /// Exact source content was verified.
    Applied(Evidence),
}
impl PublicationResult {
    /// Retained evidence for every observation.
    pub fn evidence(&self) -> &Evidence {
        match self {
            Self::Unknown(e) | Self::NotApplied(e) | Self::Applied(e) => e,
        }
    }
}
/// Current source attempt; its authority is immutable across retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    /// Original target and content authority.
    pub binding: PublicationBinding,
    /// Positive attempt number.
    pub attempt: u64,
    /// UTC time this attempt was requested.
    pub requested_at: Timepoint,
    /// Pending or observed source result.
    pub outcome: PublicationOutcome,
}
impl Attempt {
    /// Stable effect identity shared by retries of this publication.
    pub fn id(&self) -> PublicationId {
        self.binding.publication_id()
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
