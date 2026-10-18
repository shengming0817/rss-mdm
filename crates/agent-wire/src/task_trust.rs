//! Versioned task-signing trust distributed over the existing authenticated Agent channel.
//! PKI trust and task-signing trust have independent revisions and acknowledgements.
use crate::runtime::WireError;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

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
            if self
                .keys
                .iter()
                .any(|key| key.id == previous.id && key.public_key != previous.public_key)
            {
                return Err(WireError::InvalidValue);
            }
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
