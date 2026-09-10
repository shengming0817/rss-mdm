//! Immutable, tenant-scoped resource definitions. No storage or execution authority.
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInput,
    InvalidDigest,
    IdentityConflict,
    TenantMismatch,
    KindMismatch,
    DuplicateVariant,
    MissingVariant,
    MissingVersion,
    InvalidTransition,
    IncompleteReferences,
    Referenced,
    StaleTime,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resource: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Opaque bounded identity, deliberately not a URL, secret or executable body.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Id(String);
impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let s = value.into();
        if s.is_empty()
            || s.len() > 128
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
            || s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; 32]);
impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidDigest);
        }
        let mut out = [0; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error::InvalidDigest)?;
        }
        Ok(Self(out))
    }
    pub fn verify(self, bytes: &[u8]) -> Result<(), Error> {
        if self == Self::of(bytes) {
            Ok(())
        } else {
            Err(Error::InvalidDigest)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Software,
    Script,
    Configuration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Platform {
    Windows,
    MacOS,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    reference: Id,
    length: u64,
    digest: Digest,
}
impl Artifact {
    pub fn new(reference: Id, length: u64, digest: Digest) -> Result<Self, Error> {
        if length == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            reference,
            length,
            digest,
        })
    }
    pub fn reference(&self) -> &Id {
        &self.reference
    }
    pub const fn length(&self) -> u64 {
        self.length
    }
    pub const fn digest(&self) -> Digest {
        self.digest
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() as u64 != self.length {
            return Err(Error::InvalidDigest);
        }
        self.digest.verify(bytes)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Package {
    source: Id,
    package: Id,
    version: Id,
}
impl Package {
    pub fn new(source: Id, package: Id, version: Id) -> Self {
        Self {
            source,
            package,
            version,
        }
    }
    pub fn source(&self) -> &Id {
        &self.source
    }
    pub fn package(&self) -> &Id {
        &self.package
    }
    pub fn version(&self) -> &Id {
        &self.version
    }
}
/// Data only. Executor/schema identities are interpreted by a future consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Declaration {
    Software {
        package: Package,
        artifact: Artifact,
        install: Id,
        detect: Id,
        uninstall: Option<Id>,
    },
    Script {
        artifact: Artifact,
        interpreter: Id,
        detect: Id,
    },
    Configuration {
        artifact: Artifact,
        schema: Id,
        apply: Id,
        detect: Id,
        remove: Option<Id>,
    },
}
impl Declaration {
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Software { .. } => Kind::Software,
            Self::Script { .. } => Kind::Script,
            Self::Configuration { .. } => Kind::Configuration,
        }
    }
    pub fn artifact(&self) -> &Artifact {
        match self {
            Self::Software { artifact, .. }
            | Self::Script { artifact, .. }
            | Self::Configuration { artifact, .. } => artifact,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variant {
    platform: Platform,
    architecture: Architecture,
    key: Id,
    declaration: Declaration,
}
impl Variant {
    pub fn new(
        platform: Platform,
        architecture: Architecture,
        key: Id,
        declaration: Declaration,
    ) -> Self {
        Self {
            platform,
            architecture,
            key,
            declaration,
        }
    }
    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }
    pub const fn platform(&self) -> Platform {
        self.platform
    }
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
    pub fn key(&self) -> &Id {
        &self.key
    }
}
/// INVARIANT: RESOURCE-FROZEN-CONTENT-01: private fields, no Deserialize or mutation.
/// ```compile_fail
/// use rss_mdm_resource::{Version, Digest};
/// fn overwrite(version: &mut Version) { version.digest = Digest::from_bytes([0;32]); }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    tenant: TenantId,
    resource: Id,
    label: Id,
    kind: Kind,
    variants: Vec<Variant>,
    digest: Digest,
}
impl Version {
    pub fn new(
        tenant: TenantId,
        resource: Id,
        label: Id,
        kind: Kind,
        mut variants: Vec<Variant>,
    ) -> Result<Self, Error> {
        if variants.is_empty() || variants.len() > 64 {
            return Err(Error::InvalidInput);
        }
        if variants.iter().any(|v| v.declaration.kind() != kind) {
            return Err(Error::KindMismatch);
        }
        variants.sort_by(|a, b| {
            (a.platform, a.architecture, &a.key).cmp(&(b.platform, b.architecture, &b.key))
        });
        if variants.windows(2).any(|w| {
            (w[0].platform, w[0].architecture, &w[0].key)
                == (w[1].platform, w[1].architecture, &w[1].key)
        }) {
            return Err(Error::DuplicateVariant);
        }
        let mut value = Self {
            tenant,
            resource,
            label,
            kind,
            variants,
            digest: Digest::from_bytes([0; 32]),
        };
        value.digest = Digest::of(&value.canonical());
        Ok(value)
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn resource(&self) -> &Id {
        &self.resource
    }
    pub fn label(&self) -> &Id {
        &self.label
    }
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    pub const fn digest(&self) -> Digest {
        self.digest
    }
    pub fn variants(&self) -> &[Variant] {
        &self.variants
    }
    pub fn resolve(
        &self,
        platform: Platform,
        architecture: Architecture,
        key: &Id,
    ) -> Result<&Variant, Error> {
        self.variants
            .iter()
            .find(|v| v.platform == platform && v.architecture == architecture && &v.key == key)
            .ok_or(Error::MissingVariant)
    }
    // V1: domain separator, tenant, length-prefixed identities, explicit tags/counts.
    fn canonical(&self) -> Vec<u8> {
        let mut e = Encoding(b"rss-mdm-resource-v1\0".to_vec());
        e.0.extend(self.tenant.octets());
        e.id(&self.resource);
        e.id(&self.label);
        e.0.push(match self.kind {
            Kind::Software => 1,
            Kind::Script => 2,
            Kind::Configuration => 3,
        });
        e.0.extend((self.variants.len() as u32).to_be_bytes());
        for v in &self.variants {
            e.0.push(match v.platform {
                Platform::Windows => 1,
                Platform::MacOS => 2,
            });
            e.0.push(match v.architecture {
                Architecture::X86_64 => 1,
                Architecture::Aarch64 => 2,
            });
            e.id(&v.key);
            let a = v.declaration.artifact();
            e.id(&a.reference);
            e.0.extend(a.length.to_be_bytes());
            e.0.extend(a.digest.0);
            match &v.declaration {
                Declaration::Software {
                    package,
                    install,
                    detect,
                    uninstall,
                    ..
                } => {
                    e.id(&package.source);
                    e.id(&package.package);
                    e.id(&package.version);
                    e.id(install);
                    e.id(detect);
                    e.optional(uninstall);
                }
                Declaration::Script {
                    interpreter,
                    detect,
                    ..
                } => {
                    e.id(interpreter);
                    e.id(detect);
                }
                Declaration::Configuration {
                    schema,
                    apply,
                    detect,
                    remove,
                    ..
                } => {
                    e.id(schema);
                    e.id(apply);
                    e.id(detect);
                    e.optional(remove);
                }
            }
        }
        e.0
    }
}
struct Encoding(Vec<u8>);
impl Encoding {
    fn id(&mut self, id: &Id) {
        self.0.extend((id.0.len() as u32).to_be_bytes());
        self.0.extend(id.0.as_bytes());
    }
    fn optional(&mut self, id: &Option<Id>) {
        self.0.push(u8::from(id.is_some()));
        if let Some(id) = id {
            self.id(id)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Frozen,
    Active,
    Deprecated,
    Archived,
}
#[derive(Clone, Debug)]
struct Entry {
    version: Version,
    state: State,
}
/// In-memory decision aggregate. Persistence/locking remains the adapter's responsibility.
#[derive(Clone, Debug)]
pub struct Resource {
    tenant: TenantId,
    key: Id,
    kind: Kind,
    versions: BTreeMap<Id, Entry>,
    changed_at: Option<Timepoint>,
}
impl Resource {
    pub fn new(tenant: TenantId, key: Id, kind: Kind) -> Self {
        Self {
            tenant,
            key,
            kind,
            versions: BTreeMap::new(),
            changed_at: None,
        }
    }
    fn time(&self, at: Timepoint) -> Result<(), Error> {
        if self.changed_at.is_some_and(|old| at < old) {
            Err(Error::StaleTime)
        } else {
            Ok(())
        }
    }
    pub fn insert(&mut self, version: Version, at: Timepoint) -> Result<bool, Error> {
        self.time(at)?;
        if version.tenant != self.tenant {
            return Err(Error::TenantMismatch);
        }
        if version.resource != self.key {
            return Err(Error::IdentityConflict);
        }
        if version.kind != self.kind {
            return Err(Error::KindMismatch);
        }
        if let Some(old) = self.versions.get(&version.label) {
            return if old.version == version {
                Ok(false)
            } else {
                Err(Error::IdentityConflict)
            };
        }
        self.versions.insert(
            version.label.clone(),
            Entry {
                version,
                state: State::Frozen,
            },
        );
        self.changed_at = Some(at);
        Ok(true)
    }
    pub fn version(&self, label: &Id) -> Result<&Version, Error> {
        self.versions
            .get(label)
            .map(|e| &e.version)
            .ok_or(Error::MissingVersion)
    }
    pub fn state(&self, label: &Id) -> Result<State, Error> {
        self.versions
            .get(label)
            .map(|e| e.state)
            .ok_or(Error::MissingVersion)
    }
    pub fn activate(&mut self, label: &Id, at: Timepoint) -> Result<(), Error> {
        self.time(at)?;
        if self.state(label)? == State::Archived {
            return Err(Error::InvalidTransition);
        }
        for (key, entry) in &mut self.versions {
            if key == label {
                entry.state = State::Active
            } else if entry.state == State::Active {
                entry.state = State::Deprecated
            }
        }
        self.changed_at = Some(at);
        Ok(())
    }
    pub fn deprecate(&mut self, label: &Id, at: Timepoint) -> Result<(), Error> {
        self.time(at)?;
        match self.state(label)? {
            State::Active | State::Deprecated => (),
            _ => return Err(Error::InvalidTransition),
        }
        self.versions
            .get_mut(label)
            .ok_or(Error::MissingVersion)?
            .state = State::Deprecated;
        self.changed_at = Some(at);
        Ok(())
    }
    pub fn archive(&mut self, label: &Id, refs: &References, at: Timepoint) -> Result<(), Error> {
        self.time(at)?;
        self.state(label)?;
        if refs.tenant != self.tenant {
            return Err(Error::TenantMismatch);
        }
        if refs.resource != self.key || &refs.version != label {
            return Err(Error::IdentityConflict);
        }
        if !refs.complete {
            return Err(Error::IncompleteReferences);
        }
        if refs.count != 0 {
            return Err(Error::Referenced);
        }
        self.versions
            .get_mut(label)
            .ok_or(Error::MissingVersion)?
            .state = State::Archived;
        self.changed_at = Some(at);
        Ok(())
    }
}
/// Caller-supplied facts, not a verified authorization or concurrency proof.
#[derive(Clone, Debug)]
pub struct References {
    tenant: TenantId,
    resource: Id,
    version: Id,
    complete: bool,
    count: u64,
}
impl References {
    pub fn new(tenant: TenantId, resource: Id, version: Id, complete: bool, count: u64) -> Self {
        Self {
            tenant,
            resource,
            version,
            complete,
            count,
        }
    }
}
/// Access metadata deliberately separate from immutable content identity.
#[derive(Clone)]
pub struct AccessBinding {
    tenant: TenantId,
    source: Id,
    source_credential: Id,
    artifact_credential: Id,
}
impl AccessBinding {
    pub fn new(
        tenant: TenantId,
        source: Id,
        source_credential: Id,
        artifact_credential: Id,
    ) -> Self {
        Self {
            tenant,
            source,
            source_credential,
            artifact_credential,
        }
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn source(&self) -> &Id {
        &self.source
    }
    pub fn source_credential(&self) -> &Id {
        &self.source_credential
    }
    pub fn artifact_credential(&self) -> &Id {
        &self.artifact_credential
    }
}
impl fmt::Debug for AccessBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessBinding([redacted])")
    }
}
