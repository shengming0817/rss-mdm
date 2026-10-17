//! Closed recovery execution and encrypted escrow. This module owns both consumers' wire bytes.
use crate::runtime::{
    TaskArchitecture, TaskAuthorization, TaskPermit, TaskPlatform, WIRE_VERSION, WireError,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// An exact Windows object, never an account display name or drive letter.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialSubject {
    /// Numerical recovery protector on a stable volume.
    Bitlocker {
        /// Stable WMI volume DeviceID.
        volume: String,
        /// Recovery protector identity.
        protector: Uuid,
    },
    /// Explicit RSS-managed local account.
    LocalAdministrator {
        /// Stable Windows account SID.
        sid: String,
    },
}
impl CredentialSubject {
    /// Check bounded stable identity syntax.
    pub fn validate(&self) -> Result<(), WireError> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::Bitlocker { volume, protector } => bounded(volume) && !protector.is_nil(),
            Self::LocalAdministrator { sid } => {
                bounded(sid)
                    && sid.starts_with("S-1-5-")
                    && sid
                        .split('-')
                        .skip(1)
                        .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(WireError::InvalidValue)
        }
    }
}
/// The only native operations; no shell command, script or arbitrary WMI method is accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialOperation {
    /// Read numerical recovery protectors from system and fixed data volumes.
    CollectBitlocker,
    /// Verify an existing protector without creating or deleting one.
    VerifyBitlocker {
        /// Stable volume DeviceID.
        volume: String,
        /// Exact existing protector.
        protector: Uuid,
    },
    /// Replace precisely one recovery protector, retaining it until escrow acknowledgment.
    RotateBitlocker {
        /// Stable volume DeviceID.
        volume: String,
        /// Exact old protector to replace.
        protector: Uuid,
    },
    /// Reset only the named local administrator account, rejecting another password owner.
    RotateLocalAdministrator {
        /// Exact account SID.
        sid: String,
    },
    /// Verify the last RSS-managed password using protected local recovery state.
    VerifyLocalAdministrator {
        /// Exact account SID.
        sid: String,
    },
}
impl CredentialOperation {
    /// Reject unsupported or ambiguous object identities.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::CollectBitlocker => Ok(()),
            Self::VerifyBitlocker { volume, protector }
            | Self::RotateBitlocker { volume, protector } => CredentialSubject::Bitlocker {
                volume: volume.clone(),
                protector: *protector,
            }
            .validate(),
            Self::RotateLocalAdministrator { sid } | Self::VerifyLocalAdministrator { sid } => {
                CredentialSubject::LocalAdministrator { sid: sid.clone() }.validate()
            }
        }
    }
}
/// Public RSA-OAEP-SHA256 recipient. AES-256-GCM protects each material with task-bound AAD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRecipient {
    /// Exact configured recipient certificate SHA-256 identity.
    pub key_id: String,
    /// Base64 DER SubjectPublicKeyInfo; no private key is transmitted.
    pub public_key: String,
}
/// Revision frozen before a task begins; new discovered objects use revision zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialVersion {
    /// Exact material subject.
    pub subject: CredentialSubject,
    /// Last known material revision.
    pub revision: i64,
}
/// Signed, bounded execution intent using the standard Offer/Received/Start lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialTaskSpec {
    /// Current runtime wire major.
    pub wire_version: u8,
    /// Authenticated tenant.
    pub tenant_id: Uuid,
    /// Exact device.
    pub device_id: String,
    /// Native platform, Windows for this capability.
    pub platform: TaskPlatform,
    /// Native processor architecture.
    pub architecture: TaskArchitecture,
    /// Current registration.
    pub registration_id: Uuid,
    /// Current registration generation.
    pub generation: u64,
    /// Persistent run identity and credential operation identity.
    pub task_id: Uuid,
    /// Exact attempt.
    pub attempt_id: Uuid,
    /// Offer or Start.
    pub permit: TaskPermit,
    /// Signed permit expiry.
    pub expires_at: i64,
    /// Original execution deadline.
    pub deadline: i64,
    /// Existing product authorization decision.
    pub authorization: TaskAuthorization,
    /// Closed platform intent.
    pub operation: CredentialOperation,
    /// Pinned public recipient.
    pub recipient: CredentialRecipient,
    /// Expected revisions, sorted by subject without duplicates.
    pub expected: Vec<CredentialVersion>,
    /// Digest of operation, recipient and expected revisions.
    pub definition_digest: [u8; 32],
}
impl CredentialTaskSpec {
    /// Canonical immutable definition identity.
    pub fn digest(
        operation: &CredentialOperation,
        recipient: &CredentialRecipient,
        expected: &[CredentialVersion],
    ) -> Result<[u8; 32], WireError> {
        Ok(Sha256::digest(
            serde_json::to_vec(&(operation, recipient, expected))
                .map_err(|_| WireError::InvalidValue)?,
        )
        .into())
    }
    /// Validate coordinates and capability without granting execution authority.
    pub fn validate(&self) -> Result<(), WireError> {
        self.operation.validate()?;
        self.authorization.validate(self.tenant_id)?;
        if self.wire_version != WIRE_VERSION
            || self.platform != TaskPlatform::Windows
            || [
                self.tenant_id,
                self.registration_id,
                self.task_id,
                self.attempt_id,
            ]
            .iter()
            .any(Uuid::is_nil)
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.device_id.is_empty()
            || self.device_id.len() > 1024
            || self.device_id.chars().any(char::is_control)
            || self.expires_at < 0
            || self.deadline < self.expires_at
            || self.expected.len() > 512
            || self.recipient.key_id.len() != 64
            || !self.recipient.key_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.recipient.public_key.len() > 8192
            || STANDARD
                .decode(&self.recipient.public_key)
                .map_err(|_| WireError::InvalidValue)?
                .is_empty()
        {
            return Err(WireError::InvalidValue);
        }
        if !matches!(self.authorization, TaskAuthorization::Policy { .. }) {
            return Err(WireError::InvalidValue);
        }
        for value in &self.expected {
            value.subject.validate()?;
            if value.revision < 0 {
                return Err(WireError::InvalidValue);
            }
        }
        if self
            .expected
            .windows(2)
            .any(|v| v[0].subject >= v[1].subject)
            || Self::digest(&self.operation, &self.recipient, &self.expected)?
                != self.definition_digest
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Domain-separated Ed25519 input shared by producer and consumer.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-agent-credential-task-v1-ed25519\0".to_vec();
        bytes.extend((key_id.len() as u32).to_be_bytes());
        bytes.extend(key_id.as_bytes());
        bytes.extend(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?);
        Ok(bytes)
    }
    /// Exact authenticated context for one result envelope. The receiver uses its stored task.
    pub fn material_aad(
        &self,
        subject: &CredentialSubject,
        revision: i64,
    ) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        subject.validate()?;
        let expected = self
            .expected
            .iter()
            .find(|v| &v.subject == subject)
            .map(|v| v.revision)
            .unwrap_or(0);
        if revision != expected {
            return Err(WireError::InvalidValue);
        }
        serde_json::to_vec(&(
            "rss-mdm/credential-envelope/v1",
            self.tenant_id,
            &self.device_id,
            self.registration_id,
            self.generation,
            self.task_id,
            self.attempt_id,
            &self.operation,
            subject,
            revision,
            &self.recipient.key_id,
        ))
        .map_err(|_| WireError::InvalidValue)
    }
}
/// Ciphertext only; this structure is safe to persist in the ordinary communication journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialEnvelope {
    /// Exact material identity.
    pub subject: CredentialSubject,
    /// Frozen revision before this operation.
    pub expected_revision: i64,
    /// RSA-OAEP-SHA256 wrapped 32-byte AES key, base64 encoded.
    pub wrapped_key: String,
    /// AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Base64 ciphertext with the 16-byte GCM tag appended.
    pub ciphertext: String,
}
impl std::fmt::Debug for CredentialEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialEnvelope([REDACTED])")
    }
}
/// One bounded escrow batch, acknowledged only after durable storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialEscrow {
    /// Frozen task digest.
    pub definition_digest: [u8; 32],
    /// Secret-bearing envelopes, never plaintext or diagnostic output.
    pub materials: Vec<CredentialEnvelope>,
}
impl CredentialEscrow {
    /// Validate size and duplicate identities before decrypting anything.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.materials.is_empty() || self.materials.len() > 512 {
            return Err(WireError::InvalidValue);
        }
        let mut seen = std::collections::BTreeSet::new();
        for m in &self.materials {
            m.subject.validate()?;
            if m.expected_revision < 0
                || !seen.insert(&m.subject)
                || !(256..=1024).contains(
                    &STANDARD
                        .decode(&m.wrapped_key)
                        .map_err(|_| WireError::InvalidValue)?
                        .len(),
                )
                || !(17..=4112).contains(
                    &STANDARD
                        .decode(&m.ciphertext)
                        .map_err(|_| WireError::InvalidValue)?
                        .len(),
                )
            {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
}
/// Closed endpoint result; protocol acknowledgment and recovery verification stay separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOutcome {
    /// Native state and the selected material were verified; not a physical recovery test.
    Verified,
    /// Material was escrowed without a native verification proof.
    Escrowed,
    /// The effect cannot be determined safely.
    Unknown,
    /// No successful effect was established.
    Failed,
    /// OS, permissions or competing ownership prevented execution.
    Blocked,
}
/// Final non-secret evidence after escrow acknowledgment and necessary local cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialResult {
    /// Closed overall failure, including an empty material inventory.
    pub failure: Option<CredentialFailure>,
    /// Frozen task digest.
    pub definition_digest: [u8; 32],
    /// Whether enumeration completed, separately from each object's result.
    pub complete: bool,
    /// Per-object outcomes; an empty successful result is forbidden.
    pub items: Vec<CredentialItemResult>,
}
/// A material outcome contains no password, native output or arbitrary error text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialItemResult {
    /// Exact object.
    pub subject: CredentialSubject,
    /// Closed result category.
    pub outcome: CredentialOutcome,
}
impl CredentialResult {
    /// Reject duplicate or empty successful result collections.
    pub fn validate(&self) -> Result<(), WireError> {
        if (self.items.is_empty() && self.failure.is_none()) || self.items.len() > 512 {
            return Err(WireError::InvalidValue);
        }
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.items {
            i.subject.validate()?;
            if !seen.insert(&i.subject) {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
}

/// Bounded diagnoses do not contain native error messages or account passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFailure {
    /// No numerical recovery material is present.
    NoMaterials,
    /// The host does not support this operation.
    Unsupported,
    /// The system service lacks the required privilege.
    PermissionDenied,
    /// Another password-management owner is active.
    OwnerConflict,
    /// The exact selected object no longer exists.
    TargetMissing,
    /// Required local recovery state is missing or invalid.
    RecoveryState,
    /// A platform result could not be confirmed.
    NativeFailure,
}
