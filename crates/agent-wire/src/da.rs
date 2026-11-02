//! Device Access contracts. PKI is shared; configuration authority has its own signing domain.
use crate::runtime::{Secret, WireError};
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
mod configuration;
mod status;
pub use configuration::*;
pub use status::*;

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
    "3553c8ce7ad12d794d8239e9dd42d472b063b80289b8dfc407eb4fbf2568f05c";
/// Canonical current Device Access schema manifest.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/da/manifest.json");
