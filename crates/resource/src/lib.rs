#![deny(missing_docs)]
//! Immutable, tenant-scoped resource definitions. No storage or execution authority.
//!
//! Build a [`Version`] from typed declarations, then use [`Resource`] to decide its
//! lifecycle in memory. Constructors validate structure, not artifact availability,
//! caller authorization or device effects. [`Artifact::verify`] checks supplied bytes.
//! Persist snapshots and reference checks atomically in the consuming adapter; a
//! returned decision does not prove a database commit or execution on a device.
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed validation and lifecycle failures; rejected operations leave the aggregate unchanged.
pub enum Error {
    /// An identity, length, variant count or restored aggregate shape is invalid.
    InvalidInput,
    /// A SHA-256 string is malformed, or supplied bytes differ in length or digest.
    InvalidDigest,
    /// Resource/version coordinates differ, a label is duplicated, or its content changed.
    IdentityConflict,
    /// The version or reference facts belong to another tenant.
    TenantMismatch,
    /// A declaration or version has a different resource kind.
    KindMismatch,
    /// Two variants have the same platform, architecture and key.
    DuplicateVariant,
    /// No variant matches all requested selection coordinates.
    MissingVariant,
    /// The aggregate does not contain the requested version label.
    MissingVersion,
    /// The current lifecycle state does not admit the requested transition.
    InvalidTransition,
    /// The caller has not supplied a complete reference check for archival.
    IncompleteReferences,
    /// The complete reference check reports a nonzero reference count.
    Referenced,
    /// The supplied time precedes the last accepted aggregate change.
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
    /// Parse 1–128 ASCII bytes using letters, digits, `.`, `_`, `-` and `/`.
    /// Returns [`Error::InvalidInput`] for empty, `.` or `..` path segments or invalid bytes.
    /// This is an opaque identity, not a filesystem path authorization.
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
    /// Borrow the validated identity without normalization.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// SHA-256 of supplied bytes; possession alone does not authenticate their source.
pub struct Digest([u8; 32]);
impl Digest {
    /// Wrap an already computed 32-byte SHA-256 value without verification.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Return the raw SHA-256 bytes.
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
    /// Hash the exact supplied bytes without I/O.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    /// Parse exactly 64 hexadecimal characters, accepting either case.
    /// Returns [`Error::InvalidDigest`] for invalid length or non-hexadecimal bytes.
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
    /// Compare the SHA-256 of these bytes with this digest.
    /// Returns [`Error::InvalidDigest`] on mismatch; this does not authenticate the bytes.
    pub fn verify(self, bytes: &[u8]) -> Result<(), Error> {
        if self == Self::of(bytes) {
            Ok(())
        } else {
            Err(Error::InvalidDigest)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Resource declaration family; all variants of a version must share it.
pub enum Kind {
    /// A package artifact with installation and detection identities.
    Software,
    /// A script artifact with an interpreter and detection identity.
    Script,
    /// A configuration artifact with schema, application and detection identities.
    Configuration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// Operating system selected by an exact variant lookup.
pub enum Platform {
    /// Windows target.
    Windows,
    /// macOS target.
    MacOS,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
/// CPU architecture selected by an exact variant lookup.
pub enum Architecture {
    /// 64-bit x86 target.
    X86_64,
    /// 64-bit ARM target.
    Aarch64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Immutable artifact coordinates and expected bytes, without fetch or execution authority.
pub struct Artifact {
    reference: Id,
    length: u64,
    digest: Digest,
}
impl Artifact {
    /// Bind an opaque reference, positive byte length and expected digest.
    /// Zero length returns [`Error::InvalidInput`]; no content is fetched or checked.
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
    /// Borrow the caller-resolved artifact reference.
    pub fn reference(&self) -> &Id {
        &self.reference
    }
    /// Return the expected length in bytes.
    pub const fn length(&self) -> u64 {
        self.length
    }
    /// Return the expected SHA-256 of the artifact bytes.
    pub const fn digest(&self) -> Digest {
        self.digest
    }
    /// Check both exact length and SHA-256 of supplied content.
    /// Either mismatch returns [`Error::InvalidDigest`]; this performs no I/O.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() as u64 != self.length {
            return Err(Error::InvalidDigest);
        }
        self.digest.verify(bytes)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Exact source/package/version coordinates; no package resolution or existence check.
pub struct Package {
    source: Id,
    package: Id,
    version: Id,
}
impl Package {
    /// Bind exact coordinates without contacting or authorizing the source.
    pub fn new(source: Id, package: Id, version: Id) -> Self {
        Self {
            source,
            package,
            version,
        }
    }
    /// Borrow the source identity interpreted by the consumer.
    pub fn source(&self) -> &Id {
        &self.source
    }
    /// Borrow the package identity within the source.
    pub fn package(&self) -> &Id {
        &self.package
    }
    /// Borrow the exact package version identity; no version ordering is implied.
    pub fn version(&self) -> &Id {
        &self.version
    }
}
/// Data only. Executor/schema identities are interpreted by a future consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Declaration {
    /// Software metadata; executor identities are references, not commands.
    Software {
        /// Exact package coordinates in the selected source.
        package: Package,
        /// Expected immutable artifact; construction does not load its bytes.
        artifact: Artifact,
        /// Consumer-owned installation operation identity.
        install: Id,
        /// Consumer-owned detection operation identity.
        detect: Id,
        /// Optional uninstallation operation identity; `None` declares none.
        uninstall: Option<Id>,
    },
    /// Script metadata; construction does not interpret or execute the artifact.
    Script {
        /// Expected immutable artifact; construction does not load its bytes.
        artifact: Artifact,
        /// Consumer-owned interpreter identity.
        interpreter: Id,
        /// Consumer-owned detection operation identity.
        detect: Id,
    },
    /// Configuration metadata; construction does not apply it.
    Configuration {
        /// Expected immutable artifact; construction does not load its bytes.
        artifact: Artifact,
        /// Consumer-owned configuration schema identity.
        schema: Id,
        /// Consumer-owned configuration application identity.
        apply: Id,
        /// Consumer-owned detection operation identity.
        detect: Id,
        /// Optional configuration removal identity; `None` declares none.
        remove: Option<Id>,
    },
}
impl Declaration {
    /// Return the declaration family.
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Software { .. } => Kind::Software,
            Self::Script { .. } => Kind::Script,
            Self::Configuration { .. } => Kind::Configuration,
        }
    }
    /// Borrow the expected artifact shared by every declaration family.
    pub fn artifact(&self) -> &Artifact {
        match self {
            Self::Software { artifact, .. }
            | Self::Script { artifact, .. }
            | Self::Configuration { artifact, .. } => artifact,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// One platform, architecture and variant key bound to an immutable declaration.
pub struct Variant {
    platform: Platform,
    architecture: Architecture,
    key: Id,
    declaration: Declaration,
}
impl Variant {
    /// Bind selection coordinates and a declaration without I/O.
    /// Cross-variant uniqueness and kind consistency are checked by [`Version::new`].
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
    /// Borrow the immutable declaration.
    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }
    /// Return the target operating system.
    pub const fn platform(&self) -> Platform {
        self.platform
    }
    /// Return the target CPU architecture.
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }
    /// Borrow the variant key within its platform and architecture.
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
    /// Freeze 1–64 variants, sorted by platform, architecture and key.
    /// Returns [`Error::InvalidInput`] for an invalid count, [`Error::KindMismatch`]
    /// for a different declaration kind, or [`Error::DuplicateVariant`] for duplicate
    /// selection coordinates. Computes the V1 content digest; does not verify artifacts.
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
    /// Return the owning tenant; this is not an authorization check.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Borrow the resource identity within the tenant.
    pub fn resource(&self) -> &Id {
        &self.resource
    }
    /// Borrow the immutable version label.
    pub fn label(&self) -> &Id {
        &self.label
    }
    /// Return the kind shared by every declaration.
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Return the digest of the canonical V1 version encoding, not an artifact digest.
    pub const fn digest(&self) -> Digest {
        self.digest
    }
    /// Borrow variants in canonical platform/architecture/key order.
    pub fn variants(&self) -> &[Variant] {
        &self.variants
    }
    /// Select one exact platform, architecture and key without fallback.
    /// Returns [`Error::MissingVariant`] when no such variant exists.
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
/// Stored lifecycle state; none of these states proves an effect on a device.
pub enum State {
    /// Inserted, immutable content that has not been activated.
    Frozen,
    /// The aggregate's sole active version, without proof of deployment.
    Active,
    /// No longer active; may be explicitly reactivated.
    Deprecated,
    /// Archived after a complete zero-reference check; cannot be activated.
    Archived,
}
#[derive(Clone, Debug)]
struct Entry {
    version: Version,
    state: State,
}
/// Trusted storage input. Only Resource::restore validates aggregate consistency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    /// Tenant to which every stored version must belong.
    pub tenant: TenantId,
    /// Resource identity to which every stored version must belong.
    pub key: Id,
    /// Declaration kind shared by all versions.
    pub kind: Kind,
    /// Last accepted aggregate change time; absent exactly when there are no versions.
    pub changed_at: Option<Timepoint>,
    /// Uniquely labelled versions with at most one active entry.
    pub versions: Vec<StoredVersion>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// One frozen version and its separately persisted lifecycle state.
pub struct StoredVersion {
    /// Validated immutable version content.
    pub version: Version,
    /// Lifecycle state supplied by trusted storage, not inferred from device state.
    pub state: State,
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
    /// Create an empty in-memory aggregate without persistence or authorization.
    pub fn new(tenant: TenantId, key: Id, kind: Kind) -> Self {
        Self {
            tenant,
            key,
            kind,
            versions: BTreeMap::new(),
            changed_at: None,
        }
    }
    /// Copy current state in version-label order for caller-owned persistence.
    pub fn snapshot(&self) -> ResourceSnapshot {
        ResourceSnapshot {
            tenant: self.tenant,
            key: self.key.clone(),
            kind: self.kind,
            changed_at: self.changed_at,
            versions: self
                .versions
                .values()
                .map(|e| StoredVersion {
                    version: e.version.clone(),
                    state: e.state,
                })
                .collect(),
        }
    }
    /// Validate trusted stored state before constructing an aggregate.
    /// Rejects inconsistent timestamp presence or multiple active entries with
    /// [`Error::InvalidInput`], foreign tenants with [`Error::TenantMismatch`], duplicate
    /// labels or foreign resource IDs with [`Error::IdentityConflict`], and wrong kinds
    /// with [`Error::KindMismatch`]. Validation does not authenticate storage or history.
    pub fn restore(snapshot: ResourceSnapshot) -> Result<Self, Error> {
        if snapshot.versions.is_empty() != snapshot.changed_at.is_none()
            || snapshot
                .versions
                .iter()
                .filter(|v| v.state == State::Active)
                .count()
                > 1
        {
            return Err(Error::InvalidInput);
        }
        let mut resource = Self::new(snapshot.tenant, snapshot.key, snapshot.kind);
        for item in snapshot.versions {
            let v = item.version;
            if v.tenant != resource.tenant {
                return Err(Error::TenantMismatch);
            }
            if v.resource != resource.key || resource.versions.contains_key(&v.label) {
                return Err(Error::IdentityConflict);
            }
            if v.kind != resource.kind {
                return Err(Error::KindMismatch);
            }
            resource.versions.insert(
                v.label.clone(),
                Entry {
                    version: v,
                    state: item.state,
                },
            );
        }
        resource.changed_at = snapshot.changed_at;
        Ok(resource)
    }
    fn time(&self, at: Timepoint) -> Result<(), Error> {
        if self.changed_at.is_some_and(|old| at < old) {
            Err(Error::StaleTime)
        } else {
            Ok(())
        }
    }
    /// Insert a new label as [`State::Frozen`]; identical existing content returns `false`.
    /// Checks nondecreasing time, tenant, resource and kind before changing state. Reusing
    /// a label with different content returns [`Error::IdentityConflict`]. Exact replay
    /// does not advance `changed_at`; the adapter owns durable atomicity.
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
    /// Borrow content for a label, or return [`Error::MissingVersion`].
    pub fn version(&self, label: &Id) -> Result<&Version, Error> {
        self.versions
            .get(label)
            .map(|e| &e.version)
            .ok_or(Error::MissingVersion)
    }
    /// Read a label's lifecycle state, or return [`Error::MissingVersion`].
    pub fn state(&self, label: &Id) -> Result<State, Error> {
        self.versions
            .get(label)
            .map(|e| e.state)
            .ok_or(Error::MissingVersion)
    }
    /// Activate an existing non-archived version and deprecate the previous active one.
    /// Rejects stale time, missing labels and archived versions; updates only memory.
    /// Reactivating the active or a deprecated version is allowed.
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
    /// Deprecate an active or already deprecated version at nondecreasing time.
    /// Frozen/archived versions return [`Error::InvalidTransition`]; missing labels and
    /// stale time are rejected before mutation. Does not uninstall deployed content.
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
    /// Archive an existing version only with matching, complete zero-reference facts.
    /// Rejects stale time, missing versions, mismatched coordinates, incomplete checks
    /// and nonzero counts. Any current state may be archived; bytes are not deleted.
    /// The caller must authorize the action and keep the reference check atomic with persistence.
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
    /// Record caller-asserted reference facts for one exact tenant/resource/version.
    /// `complete` attests full coverage; `count` is the number of remaining references.
    /// Construction does not query storage or prove these facts; [`Resource::archive`]
    /// requires matching coordinates, `complete == true` and `count == 0`.
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
