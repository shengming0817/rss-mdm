//! Device Access contracts. PKI is shared; configuration authority has its own signing domain.
use crate::runtime::{AccessConfiguration, Secret, WireError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Administrator-authorized CSR-bound registration or credential renewal grant.
pub struct GrantRequest {
    /// Stable caller operation identity; changed input under the same ID conflicts.
    pub operation_id: Uuid,
    /// Canonical random bootstrap secret, never included in receipts or audit.
    pub secret: Secret,
    /// Canonical base64 DER RSA CSR with the dedicated DA device subject.
    pub csr: String,
    /// Requested grant lifetime, bounded from 60 seconds to seven days.
    pub expires_in_seconds: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Durable grant receipt; possession of its secret is still required to issue.
pub struct Grant {
    /// Identifier of the original persisted authorization.
    pub grant_id: Uuid,
    /// Stable caller operation identity; changed input under the same ID conflicts.
    pub operation_id: Uuid,
    /// Registration-owner allocated endpoint identity.
    pub device: String,
    /// Exclusive validity limit in Unix seconds.
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Issue the exact CSR authorized by the existing grant.
pub struct CertificateRequest {
    /// Stable caller operation identity; changed input under the same ID conflicts.
    pub operation_id: Uuid,
    /// Identifier of the original persisted authorization.
    pub grant_id: Uuid,
    /// Canonical random bootstrap secret, never included in receipts or audit.
    pub secret: Secret,
    /// Canonical base64 DER RSA CSR with the dedicated DA device subject.
    pub csr: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Committed credential mapping after proof of possession.
pub struct Registration {
    /// Stable installation instance, independent of its network location.
    pub service_id: Uuid,
    /// Tenant owning this identity and signing authority.
    pub tenant: Uuid,
    /// Registration-owner allocated endpoint identity.
    pub device: String,
    /// Registration identity; renewed credentials retain the same generation.
    pub registration: Uuid,
    /// Positive registration generation, checked against the current mapping.
    pub generation: u64,
    /// Exact current credential identity.
    pub credential: Uuid,
    /// Original persisted certificate signing attempt.
    pub issuance_id: Uuid,
    /// Stable caller operation identity; changed input under the same ID conflicts.
    pub operation_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Authorized recipients of an immutable configuration.
pub enum Audience {
    /// Any current DA device in this tenant.
    Tenant,
    /// One exact endpoint registration generation.
    Device {
        /// Registration-owner allocated endpoint identity.
        device: String,
        /// Registration identity; renewed credentials retain the same generation.
        registration: Uuid,
        /// Positive registration generation, checked against the current mapping.
        generation: u64,
    },
}
/// Permission to transport content is separate from proof of its actual delivery channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPermission {
    /// DA transport is permitted.
    Da,
    /// Managed mandatory delivery is required by the consuming policy.
    ManagedMandatory,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Typed DA inner configuration and all signed authority coordinates.
pub struct Configuration {
    /// Stable installation instance, independent of its network location.
    pub service_id: Uuid,
    /// Tenant owning this identity and signing authority.
    pub tenant: Uuid,
    /// Stable configuration identity.
    pub id: Uuid,
    /// Positive monotonically increasing publication revision.
    pub revision: u64,
    /// Positive configuration authority epoch.
    pub epoch: u64,
    /// Recipients bound into the signature.
    pub audience: Audience,
    /// Permitted delivery class; it does not attest the actual transport.
    pub delivery: DeliveryPermission,
    /// Signing validity start in Unix seconds, checked against server time.
    pub issued_at: i64,
    /// Exclusive validity limit in Unix seconds.
    pub expires_at: i64,
    /// Validated platform account and login configuration.
    pub content: AccessConfiguration,
}
impl Configuration {
    /// Validate and encode the fixed, domain-separated signing payload.
    pub fn signing_bytes(&self, key: &str) -> Result<Vec<u8>, WireError> {
        self.content.validate()?;
        if self.service_id.is_nil()
            || self.tenant.is_nil()
            || self.id.is_nil()
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || self.issued_at <= 0
            || self.expires_at <= self.issued_at
            || key.is_empty()
            || key.len() > 128
        {
            return Err(WireError::InvalidValue);
        }
        if let Audience::Device {
            device,
            registration,
            generation,
        } = &self.audience
            && (device.is_empty()
                || device.len() > 256
                || device.chars().any(char::is_control)
                || registration.is_nil()
                || *generation == 0
                || *generation > i64::MAX as u64)
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-da-configuration-v1-ed25519\0".to_vec();
        bytes.extend(
            serde_json::to_vec(&(key, "da_configuration", self))
                .map_err(|_| WireError::InvalidValue)?,
        );
        if bytes.len() > 65536 {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Ed25519 signature over the typed configuration in the DA signing domain.
pub struct SignedConfiguration {
    /// Complete typed configuration covered by the signature.
    pub configuration: Configuration,
    /// Stable key identifier from DA configuration trust.
    pub key_id: String,
    /// Canonical unpadded base64url Ed25519 signature.
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An administrator export request with an immutable operation identity.
pub struct Export {
    /// Stable caller operation identity; changed input under the same ID conflicts.
    pub operation_id: Uuid,
    /// Complete typed configuration covered by the signature.
    pub configuration: Configuration,
}
/// Exact DA content trust. Public keys never establish their own authority.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationTrust {
    /// Stable installation instance, independent of its network location.
    pub service_id: Uuid,
    /// Tenant owning this identity and signing authority.
    pub tenant: Uuid,
    /// Positive monotonically increasing publication revision.
    pub revision: u64,
    /// Complete sorted set of configuration public keys and lifecycle states.
    pub keys: Vec<crate::task_trust::PublicKey>,
}
impl ConfigurationTrust {
    /// Digest the full validated set with the DA configuration-use domain.
    pub fn installation_digest(&self) -> Result<String, WireError> {
        crate::task_trust::Trust {
            version: 1,
            service_id: self.service_id,
            tenant: self.tenant,
            revision: self.revision,
            keys: self.keys.clone(),
        }
        .validate()?;
        let bytes =
            serde_json::to_vec(&("rss-da/configuration-trust/v1", "da_configuration", self))
                .map_err(|_| WireError::InvalidValue)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Read-only original grant, signing and activation status.
pub struct Progress {
    /// Original grant receipt.
    pub grant: Grant,
    /// Original persisted certificate signing attempt.
    pub issuance_id: Option<Uuid>,
    /// A dispatched attempt lacks a proven result; retry cannot sign again.
    pub issuance_unknown: bool,
    /// Registration identity; renewed credentials retain the same generation.
    pub registration: Option<Registration>,
}

/// Fingerprint of the generated Device Access protocol schema.
pub const SCHEMA_FINGERPRINT: &str =
    "1a486e88629cbecf06344309aaa475f21f11663c143d039ebd861f8f1dfa4d0f";
/// Canonical current Device Access schema manifest.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/da/manifest.json");
