//! Versioned task-signing trust distributed over the existing authenticated Agent channel.
//! PKI trust and task-signing trust have independent revisions and acknowledgements.
use crate::runtime::WireError;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Fingerprint of the generated, fixed public schema artifact.
pub const SCHEMA_FINGERPRINT: &str =
    "d8a681c51e149aaafe2539bd4760e0a3e87afa98eb900e1027e94ccc9d59cc16";
/// Canonical manifest for fixed consumer artifacts.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/task_trust/manifest.json");
/// Task-signing trust protocol version.
pub const API_VERSION: u8 = 1;
/// Maximum number of concurrently retained task-signing public keys.
pub const MAX_KEYS: usize = 16;
/// Exact task-signing key lifecycle. Retirement removes a key from the next complete set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Installed before the server starts signing with this key.
    Prepared,
    /// The sole key used for newly signed tasks.
    Active,
    /// Retained to authenticate previously issued tasks.
    VerifyOnly,
}
/// Ed25519 public material. Private keys never appear in this contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// Stable, never reused key identifier.
    pub id: String,
    /// Exactly 32 public-key bytes encoded as canonical unpadded base64url.
    pub public_key: String,
    /// Approved use of this key.
    pub state: KeyState,
}
/// Complete server-authorized task-signing trust for one tenant and runtime origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// Exact protocol version.
    pub version: u8,
    /// Canonical HTTPS runtime origin, with no path, query or fragment.
    pub origin: String,
    /// Tenant owning the authenticated Agent channel.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant: Uuid,
    /// Monotonically increasing revision, never inferred from a timestamp.
    pub revision: u64,
    /// Full key set, strictly sorted by key ID for a unique digest.
    pub keys: Vec<PublicKey>,
}
impl Trust {
    /// Validate public shape and canonical identity before persisting or using the key set.
    /// The caller must also bind tenant/origin to the authenticated channel and reject rollback.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.version != API_VERSION
            || self.tenant.is_nil()
            || !(1..=i64::MAX as u64).contains(&self.revision)
            || !(1..=MAX_KEYS).contains(&self.keys.len())
            || self
                .keys
                .iter()
                .filter(|key| key.state == KeyState::Active)
                .count()
                != 1
        {
            return Err(WireError::InvalidValue);
        }
        let url = url::Url::parse(&self.origin).map_err(|_| WireError::InvalidValue)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.origin().ascii_serialization() != self.origin
        {
            return Err(WireError::InvalidValue);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut public_keys = std::collections::BTreeSet::new();
        for key in &self.keys {
            if key.id.is_empty()
                || key.id.len() > 128
                || !key
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || !ids.insert(&key.id)
            {
                return Err(WireError::InvalidValue);
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&key.public_key)
                .map_err(|_| WireError::InvalidValue)?;
            if decoded.len() != 32
                || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded)
                    != key.public_key
                || !public_keys.insert(decoded)
            {
                return Err(WireError::InvalidValue);
            }
        }
        if self.keys.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Domain-separated digest of the exact validated public set and its authority coordinates.
    pub fn installation_digest(&self) -> Result<String, WireError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&("rss-mdm/task-signing-trust/v1", self))
            .map_err(|_| WireError::InvalidValue)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    /// Validate an update against the installed set. Same revision requires identical content;
    /// new revisions cannot reuse an existing key ID for different public bytes.
    pub fn validate_successor(&self, installed: &Self) -> Result<(), WireError> {
        self.validate()?;
        installed.validate()?;
        if self.tenant != installed.tenant
            || self.origin != installed.origin
            || self.revision < installed.revision
            || (self.revision == installed.revision && self != installed)
        {
            return Err(WireError::InvalidValue);
        }
        for previous in &installed.keys {
            let next = self.keys.iter().find(|key| key.id == previous.id);
            if next.is_some_and(|key| key.public_key != previous.public_key) {
                return Err(WireError::InvalidValue);
            }
            match (previous.state, next.map(|key| key.state)) {
                (KeyState::Active, Some(KeyState::Active | KeyState::VerifyOnly))
                | (KeyState::Prepared, Some(KeyState::Prepared | KeyState::Active) | None)
                | (KeyState::VerifyOnly, Some(KeyState::VerifyOnly) | None) => (),
                _ => return Err(WireError::InvalidValue),
            }
        }
        if self.keys.iter().any(|key| {
            !installed.keys.iter().any(|old| old.id == key.id) && key.state != KeyState::Prepared
        }) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Acknowledgement after durable installation and readback, sent over an authenticated channel.
/// The service compares registration and generation with authenticated identity, not request claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    /// Stable operation ID reused after response loss.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation: Uuid,
    /// Exact protocol version.
    pub version: u8,
    /// Existing registration; this operation never creates a new device identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration: Uuid,
    /// Existing registration generation.
    pub generation: u64,
    /// Installed complete-set revision.
    pub revision: u64,
    /// Digest returned by `Trust::installation_digest`.
    pub digest: String,
}
impl Acknowledgement {
    /// Check shape before comparing the registration with the authenticated channel.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.operation.is_nil()
            || self.registration.is_nil()
            || self.version != API_VERSION
            || !(1..=i64::MAX as u64).contains(&self.generation)
            || !(1..=i64::MAX as u64).contains(&self.revision)
            || self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Match the exact approved material. Does not authenticate the caller or prove disk writes.
    pub fn matches(&self, trust: &Trust) -> Result<bool, WireError> {
        self.validate()?;
        Ok(self.revision == trust.revision && self.digest == trust.installation_digest()?)
    }
}

/// Device-reported installation observation; never a rotation acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Stable report operation, retained across response loss.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation: Uuid,
    /// Exact observation format.
    pub version: u8,
    /// Authenticated registration identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration: Uuid,
    /// Authenticated registration generation.
    pub generation: u64,
    /// Monotonic sequence within this registration generation and domain.
    pub sequence: u64,
    /// Target revision, absent when fetching the target failed.
    pub target_revision: Option<u64>,
    /// Target installation digest, paired with target_revision.
    pub target_digest: Option<String>,
    /// Last durably installed revision, absent when no state can be read.
    pub actual_revision: Option<u64>,
    /// Read-back installation digest, paired with actual_revision.
    pub actual_digest: Option<String>,
    /// Local result; applied does not imply ACK confirmation or current connectivity.
    pub state: ObservationState,
    /// Closed, non-secret failure category.
    pub reason: Option<ObservationReason>,
    /// Device observation time in Unix seconds; not ordering authority.
    pub observed_at: i64,
}
/// Installation result independently reported by the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    /// Target received but not durably installed.
    Received,
    /// Commit and readback completed.
    Applied,
    /// Attempt failed; prior installed state may remain usable.
    Failed,
    /// Local installed state cannot be determined.
    Unknown,
}
/// Closed failure reasons; raw errors and material bytes are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationReason {
    /// Authenticated transport unavailable.
    Transport,
    /// Material or successor validation failed.
    Validation,
    /// Durable write or readback failed.
    Storage,
    /// Device credential unavailable or rejected.
    Credential,
    /// Local machine trust installation failed.
    Installation,
    /// Restart requires a fresh observation.
    Restart,
}
impl Observation {
    /// Validate shape, state consistency and bounded coordinates. The service authenticates identity.
    pub fn validate(&self) -> Result<(), WireError> {
        let number = |v: u64| (1..=i64::MAX as u64).contains(&v);
        let material = |revision: Option<u64>, digest: &Option<String>| match (revision, digest) {
            (None, None) => true,
            (Some(r), Some(d)) => {
                number(r)
                    && d.len() == 64
                    && d.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            _ => false,
        };
        if self.version != API_VERSION
            || self.operation.is_nil()
            || self.registration.is_nil()
            || !number(self.generation)
            || !number(self.sequence)
            || self.observed_at < 0
            || !material(self.target_revision, &self.target_digest)
            || !material(self.actual_revision, &self.actual_digest)
            || match self.state {
                ObservationState::Applied => {
                    self.reason.is_some()
                        || self.target_revision.is_none()
                        || self.target_revision != self.actual_revision
                        || self.target_digest != self.actual_digest
                }
                ObservationState::Received => {
                    self.reason.is_some() || self.target_revision.is_none()
                }
                ObservationState::Failed | ObservationState::Unknown => self.reason.is_none(),
            }
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Last report with server reception time. Absence means unknown, never successful installation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedInstallation {
    /// Device statement, not a server assertion of disk contents or CRL freshness.
    pub observation: Observation,
    /// Server receipt time in Unix seconds.
    pub received_at: i64,
}
