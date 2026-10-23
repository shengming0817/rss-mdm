//! Signed Agent connection locations, independent of durable service identity.
//! ref: ring src/ec/curve25519/ed25519/signing.rs (Ed25519 signs domain-separated bytes).
use crate::runtime::WireError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Generated current connection contract manifest.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/connections/manifest.json");
/// SHA256 of the ordered generated schemas.
pub const SCHEMA_FINGERPRINT: &str =
    "2e83a7c7699144f0e77e2d20e9ab7bf7cdc8f61014db8845a6d560f4fed0c55d";

/// Maximum number of explicitly authorized Agent HTTPS destinations.
pub const MAX_ORIGINS: usize = 8;
/// Maximum complete signed connection file, before JSON decoding.
pub const MAX_FILE_BYTES: usize = 65_536;
/// Suggested basename for protected offline connection updates.
pub const FILENAME: &str = "rss-agent-connections.json";

/// Transport addresses never form the service, device or credential identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    /// Current product format, independent of configuration revision.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Immutable product installation instance, shared by all its entrances.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub service_id: Uuid,
    /// Tenant to which the installed device belongs.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Strictly increasing installation revision; equal revisions require identical bytes.
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub revision: u64,
    /// Preferred address, necessarily a member of origins.
    #[schemars(length(min = 1, max = 2048))]
    pub preferred_origin: String,
    /// Exact canonical HTTPS origins, sorted for one signed representation.
    #[schemars(length(min = 1, max = 8))]
    pub origins: Vec<String>,
    /// Already installed configuration verification key; never supplied as public key bytes.
    #[schemars(length(min = 1, max = 128), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub key_id: String,
}

/// A transferable public configuration; no device credential or CA private key is included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedConfiguration {
    /// Exact signed connection configuration.
    pub configuration: Configuration,
    /// Canonical unpadded base64url Ed25519 signature.
    #[schemars(length(min = 86, max = 86), regex(pattern = r"^[A-Za-z0-9_-]{86}$"))]
    pub signature: String,
}

/// Device installation report, authenticated against its current registration and generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acknowledgement {
    /// Original operation retained through retries.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Installed complete configuration revision.
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub revision: u64,
    /// Digest of the exact signed configuration body.
    #[schemars(length(min = 64, max = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    pub digest: String,
    /// Actual selected address; not a device statement of an arbitrary new destination.
    #[schemars(length(min = 1, max = 2048))]
    pub origin: String,
}
/// Closed device observations; none of these reports changes trust or the installed revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// Configuration signature is invalid or its key is not installed.
    SignatureRejected,
    /// Configuration belongs to a different service or tenant.
    IdentityMismatch,
    /// Revision rolled back or reused for different content.
    RevisionRejected,
    /// Local atomic persistence could not complete.
    PersistenceFailed,
    /// No authorized destination was reachable through a network connection.
    NetworkUnavailable,
}
/// Best-effort report over a still trusted connection after a failed installation attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureReport {
    /// Original report operation retained across uncertain responses.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Server-published target, never a claim of successful installation.
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub revision: u64,
    /// Closed failure classification without credentials or diagnostic payloads.
    pub reason: FailureReason,
}

/// Validate one exact HTTPS origin; no user information, path, query or implicit rewrite.
pub fn validate_origin(value: &str) -> Result<(), WireError> {
    let url = url::Url::parse(value).map_err(|_| WireError::InvalidValue)?;
    if value.len() > 2048
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.origin().ascii_serialization() != value
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}

impl Configuration {
    /// Validate constructed values before signing or making any network request.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.wire_version != 1
            || self.service_id.is_nil()
            || self.tenant_id.is_nil()
            || !(1..=i64::MAX as u64).contains(&self.revision)
            || !(1..=MAX_ORIGINS).contains(&self.origins.len())
            || self.key_id.is_empty()
            || self.key_id.len() > 128
            || !self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.origins.windows(2).any(|p| p[0] >= p[1])
            || !self.origins.contains(&self.preferred_origin)
        {
            return Err(WireError::InvalidValue);
        }
        for origin in &self.origins {
            validate_origin(origin)?;
        }
        Ok(())
    }

    /// The sole signature encoding shared by producer and consumers.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        serde_json::to_vec(&("rss-mdm/agent-connections/v1", self))
            .map_err(|_| WireError::InvalidValue)
    }

    /// Public exact-body fingerprint; possession of this digest grants no authority.
    pub fn digest(&self) -> Result<String, WireError> {
        Ok(format!("{:x}", Sha256::digest(self.signing_bytes()?)))
    }

    /// Compare only after verifying the incoming signature with an installed key.
    pub fn validate_successor(&self, installed: &Self) -> Result<(), WireError> {
        self.validate()?;
        installed.validate()?;
        if self.service_id != installed.service_id
            || self.tenant_id != installed.tenant_id
            || self.revision < installed.revision
            || (self.revision == installed.revision && self != installed)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

impl SignedConfiguration {
    /// Structural validation only; consumers must verify against their protected key set.
    pub fn validate(&self) -> Result<(), WireError> {
        self.configuration.validate()?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| WireError::InvalidValue)?;
        if signature.len() != 64 || URL_SAFE_NO_PAD.encode(signature) != self.signature {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

impl Acknowledgement {
    /// Check a device report against the exact server-owned revision.
    pub fn validate_for(&self, configuration: &Configuration) -> Result<(), WireError> {
        configuration.validate()?;
        if self.operation_id.is_nil()
            || self.revision != configuration.revision
            || self.digest != configuration.digest()?
            || !configuration.origins.contains(&self.origin)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configuration() -> Configuration {
        Configuration {
            wire_version: 1,
            service_id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            revision: 1,
            preferred_origin: "https://agent.example.test:9445".into(),
            origins: vec!["https://agent.example.test:9445".into()],
            key_id: "configuration-key".into(),
        }
    }
    #[test]
    fn locations_can_change_without_changing_service_identity() {
        let first = configuration();
        let mut overlap = first.clone();
        overlap.revision = 2;
        overlap.origins.push("https://new.example.test".into());
        overlap.preferred_origin = overlap.origins[1].clone();
        overlap.validate_successor(&first).unwrap();
        let mut last = overlap.clone();
        last.revision = 3;
        last.origins.remove(0);
        last.validate_successor(&overlap).unwrap();
        assert_eq!(last.service_id, first.service_id);
        assert!(first.validate_successor(&last).is_err());
        let mut changed = last.clone();
        changed.preferred_origin = first.preferred_origin.clone();
        changed.origins = first.origins.clone();
        assert!(changed.validate_successor(&last).is_err());
        changed = last.clone();
        changed.service_id = Uuid::from_u128(3);
        assert!(changed.validate_successor(&last).is_err());
    }
    #[test]
    fn rejects_ambiguous_addresses_and_forged_acknowledgements() {
        let configuration = configuration();
        for address in [
            "http://agent.example.test",
            "https://a:b@agent.example.test",
            "https://agent.example.test/path",
            "https://agent.example.test/",
            "https://agent.example.test?query=1",
        ] {
            assert!(validate_origin(address).is_err());
        }
        let mut ack = Acknowledgement {
            operation_id: Uuid::from_u128(3),
            revision: 1,
            digest: configuration.digest().unwrap(),
            origin: configuration.preferred_origin.clone(),
        };
        ack.validate_for(&configuration).unwrap();
        ack.origin = "https://other.example.test".into();
        assert!(ack.validate_for(&configuration).is_err());
    }
}
