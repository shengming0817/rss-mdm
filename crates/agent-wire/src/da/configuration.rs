//! Current DA configuration wire. The inner payload is transported without reserialization.
use super::{Audience, DeliveryPermission};
use crate::runtime::{AccessConfiguration, WireError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Atomic client-setting groups which a DA issuer may authorize for managed delivery.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationField {
    /// Complete macOS native login configuration; server authorization remains independent.
    Mac,
    /// Complete Windows login mechanism; server account admission remains independent.
    Windows,
}

/// Native payload identity bound by the inner signature, never mutable display metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeBinding {
    /// Native schema identity, including Configuration for the outer profile.
    pub schema: String,
    /// Platform-native payload identifier.
    pub identifier: String,
    /// Platform-native payload UUID.
    pub uuid: Uuid,
    /// Native payload version.
    pub version: u32,
}

/// Public deployment inputs consumed by the existing PSSO native payload generator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacNativeInput {
    /// Signed application/extension identity; never contains private keys.
    pub deployment: crate::platform_sso::Configuration,
    /// Canonical product HTTPS origin used to derive tenant-scoped protocol endpoints.
    pub origin: String,
}
/// Input contract for platform generators; it does not prove native installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExpectation {
    /// Mac generator inputs from the same live platform owner as the bound native identities.
    pub mac: Option<MacNativeInput>,
    /// Canonical expectation format; currently one.
    pub version: u8,
    /// SHA-256 of the canonical native expectation, including bound identities.
    pub digest: String,
    /// Native identities that an outer transport must preserve.
    pub bindings: Vec<NativeBinding>,
}
impl NativeExpectation {
    /// Freeze the platform settings and their exact native identities from the same source.
    pub fn new(
        content: &AccessConfiguration,
        bindings: Vec<NativeBinding>,
        mac: Option<MacNativeInput>,
    ) -> Result<Self, WireError> {
        content.validate()?;
        if content.mac.is_some() != mac.is_some() {
            return Err(WireError::InvalidValue);
        }
        if let Some(mac) = &mac {
            mac.deployment.validate()?;
            if mac.origin.len() > 2048 {
                return Err(WireError::InvalidValue);
            }
            let origin = url::Url::parse(&mac.origin).map_err(|_| WireError::InvalidValue)?;
            if origin.scheme() != "https"
                || origin.domain().is_none()
                || !origin.username().is_empty()
                || origin.password().is_some()
                || origin.query().is_some()
                || origin.fragment().is_some()
                || origin.path() != "/"
                || bindings.len() < 2
                || bindings[0].schema != "Configuration"
            {
                return Err(WireError::InvalidValue);
            }
        } else if !bindings.is_empty() {
            return Err(WireError::InvalidValue);
        }

        if bindings.len() > 16
            || bindings.iter().any(|b| {
                b.schema.is_empty()
                    || b.schema.len() > 256
                    || b.schema.chars().any(char::is_control)
                    || b.uuid.is_nil()
                    || b.version == 0
                    || b.identifier.is_empty()
                    || b.identifier.len() > 256
                    || b.identifier.chars().any(char::is_control)
            })
        {
            return Err(WireError::InvalidValue);
        }
        let mut identifiers = std::collections::BTreeSet::new();
        let mut uuids = std::collections::BTreeSet::new();
        if bindings
            .iter()
            .any(|b| !identifiers.insert(&b.identifier) || !uuids.insert(b.uuid))
        {
            return Err(WireError::InvalidValue);
        }
        let bytes = serde_json::to_vec(&(
            "rss.da.native-expectation.v1",
            &content.mac,
            &content.windows,
            &bindings,
            &mac,
        ))
        .map_err(|_| WireError::InvalidValue)?;
        Ok(Self {
            mac,
            version: 1,
            digest: format!("{:x}", Sha256::digest(bytes)),
            bindings,
        })
    }
}

/// Fully bound content, constructed from an immutable Policy publication by the server.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    /// Installation identity.
    pub service_id: Uuid,
    /// Owning tenant.
    pub tenant: Uuid,
    /// Policy identity, never a second independently versioned configuration.
    pub id: Uuid,
    /// Immutable Policy version.
    pub version: Uuid,
    /// Policy publication CAS revision.
    pub revision: u64,
    /// Exact signing trust revision, independent from Policy revision.
    pub trust_revision: u64,
    /// Original export operation; also the immutable artifact identity.
    pub operation_id: Uuid,
    /// Exact permitted recipients.
    pub audience: Audience,
    /// Issuer permission, not evidence of actual transport.
    pub delivery: DeliveryPermission,
    /// Only these client groups may acquire managed locks.
    pub managed_fields: Vec<ConfigurationField>,
    /// Server issue time in Unix seconds.
    pub issued_at: i64,
    /// Exclusive expiry in Unix seconds.
    pub expires_at: i64,
    /// The complete published configuration.
    pub content: AccessConfiguration,
    /// Expectations consumed by platform export generators.
    pub native: NativeExpectation,
}
impl Configuration {
    /// Validate structural, group and authority coordinates; this does not authenticate a signature.
    pub fn validate(&self) -> Result<(), WireError> {
        self.content.validate()?;
        if self.service_id.is_nil()
            || self.tenant.is_nil()
            || self.id.is_nil()
            || self.version.is_nil()
            || self.operation_id.is_nil()
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.trust_revision == 0
            || self.trust_revision > i64::MAX as u64
            || self.issued_at <= 0
            || self.expires_at <= self.issued_at
            || self.managed_fields.len() > 2
            || self.managed_fields.windows(2).any(|v| v[0] >= v[1])
            || (self.delivery == DeliveryPermission::Da && !self.managed_fields.is_empty())
            || (self.delivery == DeliveryPermission::ManagedMandatory
                && self.managed_fields.is_empty())
            || self.native
                != NativeExpectation::new(
                    &self.content,
                    self.native.bindings.clone(),
                    self.native.mac.clone(),
                )?
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
        Ok(())
    }
    /// Match an already authenticated DA identity. This checks audience only, not time,
    /// signature, current publication or native installation; consumers qualify those separately.
    pub fn permits(&self, identity: &super::ReportIdentity, device: &str) -> bool {
        identity.validate().is_ok()
            && self.service_id == identity.service_id
            && self.tenant == identity.tenant
            && match &self.audience {
                Audience::Tenant => true,
                Audience::Device {
                    device: d,
                    registration,
                    generation,
                } => {
                    d == device
                        && *registration == identity.registration
                        && *generation == identity.generation as u64
                }
            }
    }
    /// Encode the original payload once at the signing boundary.
    pub fn payload(&self) -> Result<String, WireError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?;
        if bytes.len() > 65536 {
            return Err(WireError::InvalidValue);
        }
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// Inner envelope. MDM may rewrap this envelope but must preserve its opaque payload.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedConfiguration {
    /// Canonical base64url encoding of the exact signed UTF-8 payload bytes.
    pub payload: String,
    /// Key selected from independently installed DA trust.
    pub key_id: String,
    /// Canonical base64url Ed25519 signature.
    pub signature: String,
    /// SHA-256 of the original payload bytes; never a substitute for verification.
    pub digest: String,
}
impl SignedConfiguration {
    /// Frame original bytes, binding the fixed purpose and key without parsing/reencoding JSON.
    pub fn signing_bytes(payload: &str, key: &str) -> Result<Vec<u8>, WireError> {
        if payload.len() > 87382
            || key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| WireError::InvalidValue)?;
        if bytes.len() > 65536 || URL_SAFE_NO_PAD.encode(&bytes) != payload {
            return Err(WireError::InvalidValue);
        }
        let mut framed = b"rss-da-configuration-v1-ed25519\0da_configuration\0".to_vec();
        framed.extend_from_slice(&(key.len() as u32).to_be_bytes());
        framed.extend_from_slice(key.as_bytes());
        framed.extend_from_slice(&bytes);
        Ok(framed)
    }
    /// Compute the transport-integrity digest of an opaque payload.
    pub fn payload_digest(payload: &str) -> Result<String, WireError> {
        if payload.len() > 87382 {
            return Err(WireError::InvalidValue);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| WireError::InvalidValue)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    /// Decode only after the caller has verified the original bytes using installed trust.
    /// Calling this alone establishes no authenticity or managed-delivery qualification.
    pub fn decode(&self) -> Result<Configuration, WireError> {
        Self::signing_bytes(&self.payload, &self.key_id)?;
        if self.digest != Self::payload_digest(&self.payload)? {
            return Err(WireError::InvalidValue);
        }
        let value: Configuration = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.payload)
                .map_err(|_| WireError::InvalidValue)?,
        )
        .map_err(|_| WireError::InvalidValue)?;
        value.validate()?;
        Ok(value)
    }
}

/// Export a currently published version. Callers cannot provide signable content.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Export {
    /// Stable idempotency and artifact identity.
    pub operation_id: Uuid,
    /// Policy selected by the administrator.
    pub policy: Uuid,
    /// Exact immutable version; stale versions cannot be newly exported.
    pub version: Uuid,
    /// Authorized delivery purpose.
    pub delivery: DeliveryPermission,
    /// Explicit lifetime within the host's configured ceiling.
    pub lifetime_seconds: u32,
}

/// Actual source observation. Missing and explicit release have different safety meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    /// No source was found, not permission to release an existing lock.
    Missing,
    /// A complete candidate was obtained.
    Present,
    /// Platform source could not be read.
    ReadFailed,
    /// Validation failed.
    Invalid,
    /// Candidate has expired.
    Expired,
    /// Conflicting same-level candidates.
    Conflict,
    /// Source explicitly withdrawn; a protected release is still required to unlock.
    Withdrawn,
}
/// Evidence level; ordinary device input cannot choose Verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Authenticated device reported the fact.
    Reported,
    /// Explicit platform authority independently verified the exact fact.
    Verified,
}
