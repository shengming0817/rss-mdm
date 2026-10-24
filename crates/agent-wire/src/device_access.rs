//! Device Access account identity and application receipts. No password or token bytes.
use super::{TaskPlatform, WireError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bounded native account action; system passwords are supplied only through local UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessAction {
    /// Associate or configure one exact existing local account.
    Apply {
        /// Stable local identity.
        account: AccessAccount,
        /// Desired integration and privilege.
        configuration: AccessConfiguration,
    },
    /// Create an account through the authenticated native broker; never adopt an existing name.
    Create {
        /// Requested local account name; collisions must fail.
        name: String,
        /// New accounts default to standard privilege when role is absent.
        configuration: AccessConfiguration,
    },
    /// Remove RSS integration and apply the explicitly authorized account disposition.
    Unbind {
        /// Exact account whose integration must be removed.
        account: AccessAccount,
        /// Account handling; never deletes the account or its data.
        disposition: AccessAccountDisposition,
    },
}

/// Signed task carried by the existing offer/received/start/result protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessTaskSpec {
    /// Exact wire major.
    pub wire_version: u8,
    /// Authenticated tenant.
    pub tenant_id: Uuid,
    /// Exact endpoint.
    pub device_id: String,
    /// Current registration.
    pub registration_id: Uuid,
    /// Registration generation, not binding revision.
    pub generation: u64,
    /// Required operating system.
    pub platform: TaskPlatform,
    /// Required architecture.
    pub architecture: super::TaskArchitecture,
    /// Existing durable task.
    pub task_id: Uuid,
    /// Exact attempt.
    pub attempt_id: Uuid,
    /// Offer or freshly authorized Start.
    pub permit: super::TaskPermit,
    /// Signed permission deadline.
    pub expires_at: i64,
    /// Original operation deadline.
    pub deadline: i64,
    /// Stable business binding.
    pub binding_id: Uuid,
    /// Identity authority instance selected by the server.
    pub instance_id: Uuid,
    /// RSS person selected by the authenticated ceremony or authorized administrator.
    pub principal_id: Uuid,
    /// Monotonic association generation.
    pub binding_generation: i64,
    /// Independent factor replacement generation. Configuration changes preserve it.
    pub factor_generation: i64,
    /// Exact desired state revision.
    pub revision: i64,
    /// Frozen owner definition digest.
    pub definition_digest: [u8; 32],
    /// Closed native action.
    pub action: AccessAction,
    /// Windows factor provisioning; absent for macOS and unlink.
    pub windows: Option<AccessWindowsPlan>,
    /// Current product authorization.
    pub authorization: super::TaskAuthorization,
}
impl AccessTaskSpec {
    /// Validate coordinates without granting native authority.
    pub fn validate(&self) -> Result<(), WireError> {
        self.authorization.validate(self.tenant_id)?;
        if self.wire_version != super::WIRE_VERSION
            || [
                self.tenant_id,
                self.registration_id,
                self.task_id,
                self.attempt_id,
                self.binding_id,
                self.instance_id,
                self.principal_id,
            ]
            .iter()
            .any(Uuid::is_nil)
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.binding_generation < 1
            || self.factor_generation < 1
            || self.revision < 1
            || self.definition_digest == [0; 32]
            || self.device_id.is_empty()
            || self.device_id.len() > 256
            || self.device_id.chars().any(char::is_control)
            || self.expires_at <= 0
            || self.deadline < self.expires_at
            || !matches!(self.authorization, super::TaskAuthorization::Policy { .. })
            || !matches!(
                (self.platform, self.architecture),
                (TaskPlatform::Windows, super::TaskArchitecture::X86_64)
                    | (TaskPlatform::Macos, super::TaskArchitecture::Aarch64)
            )
        {
            return Err(WireError::InvalidValue);
        }
        match &self.action {
            AccessAction::Apply { account, .. } | AccessAction::Unbind { account, .. } => {
                account.validate()?;
                if account.platform() != self.platform {
                    return Err(WireError::InvalidValue);
                }
            }
            AccessAction::Create { name, .. } => {
                if name.is_empty()
                    || name.len() > 20
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || !name.as_bytes()[0].is_ascii_alphabetic()
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        match &self.action {
            AccessAction::Apply {
                account,
                configuration,
            } if !configuration.admits(account) => return Err(WireError::InvalidValue),
            AccessAction::Create { configuration, .. } => {
                configuration.validate()?;
                if (self.platform == TaskPlatform::Macos && configuration.mac.is_none())
                    || (self.platform == TaskPlatform::Windows
                        && !configuration
                            .windows_accounts
                            .contains(&AccessWindowsKind::Local))
                {
                    return Err(WireError::InvalidValue);
                }
            }
            _ => (),
        }
        let provisioning = self.platform == TaskPlatform::Windows
            && !matches!(self.action, AccessAction::Unbind { .. });
        if self.windows.is_some() != provisioning {
            return Err(WireError::InvalidValue);
        }
        if let Some(plan) = &self.windows {
            plan.validate()?;
            if let AccessWindowsPlan::Preserve { facts } = plan {
                let super::CredentialSubject::RssLogin {
                    binding,
                    binding_generation,
                    sid,
                } = &facts.recovery.subject
                else {
                    return Err(WireError::InvalidValue);
                };
                if facts.factor_generation != self.factor_generation
                    || *binding != self.binding_id
                    || *binding_generation != self.binding_generation
                    || !matches!(&self.action, AccessAction::Apply { account: AccessAccount::Windows { sid: expected, .. }, .. } if expected == sid)
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        Ok(())
    }
    /// Bind an encrypted first/replacement recovery candidate to this exact signed task.
    pub fn material_aad(
        &self,
        subject: &super::CredentialSubject,
        revision: i64,
    ) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        subject.validate()?;
        let Some(AccessWindowsPlan::Initialize {
            recipient,
            expected_revision,
        }) = &self.windows
        else {
            return Err(WireError::InvalidValue);
        };
        let super::CredentialSubject::RssLogin {
            binding,
            binding_generation,
            sid,
        } = subject
        else {
            return Err(WireError::InvalidValue);
        };
        if *binding != self.binding_id
            || *binding_generation != self.binding_generation
            || revision != *expected_revision
        {
            return Err(WireError::InvalidValue);
        }
        if let AccessAction::Apply { account, .. } = &self.action
            && !matches!(account, AccessAccount::Windows { sid: expected, .. } if expected == sid)
        {
            return Err(WireError::InvalidValue);
        }
        serde_json::to_vec(&(
            "rss-mdm/device-access/recovery/v1",
            self,
            subject,
            revision,
            &recipient.key_id,
        ))
        .map_err(|_| WireError::InvalidValue)
    }
    /// Domain-separated canonical signing bytes include every identity and desired value.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        if key_id.is_empty() || key_id.len() > 128 {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-device-access-v1-ed25519\0".to_vec();
        bytes.extend(serde_json::to_vec(&(key_id, self)).map_err(|_| WireError::InvalidValue)?);
        Ok(bytes)
    }
}

/// Begin the first association; neither account nor person is caller-selected.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessBegin {
    /// Unique ceremony identity. A lost nonce requires a new ceremony.
    pub operation_id: Uuid,
    /// One enabled Device Access policy eligible for this device.
    pub policy: Uuid,
}
/// Short-lived, one-use association challenge. This is never an Identity login credential.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessChallenge {
    /// Exact ceremony identity.
    pub id: Uuid,
    /// One-use secret; persisted only as a hash on the server.
    pub nonce: super::Secret,
    /// Server UTC expiry of this ceremony, unrelated to recovery-secret lifetime.
    pub expires_at: i64,
    /// Exact native login which the Agent must recheck before confirmation.
    pub local_session: AccessLocalSession,
}
impl std::fmt::Debug for AccessChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessChallenge([REDACTED])")
    }
}
/// Confirmation from the authenticated Agent and the same RSS user.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessConfirm {
    /// Persistent operation identity for recovery after a lost response.
    pub operation_id: Uuid,
    /// Original ceremony identity.
    pub challenge: Uuid,
    /// Original one-use secret.
    pub nonce: super::Secret,
    /// Native broker rechecks this exact live login; a user switch cannot reuse the challenge.
    pub local_session: AccessLocalSession,
}

/// Stable local account identity, never a display name or a transient Unix UID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "platform",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessAccount {
    /// Windows account, with provenance reported by the authenticated native session.
    Windows {
        /// SID returned by the native account operation.
        sid: String,
        /// Local machine, AD domain or Entra tenant authority; never inferred from a name.
        authority: AccessWindowsAuthority,
    },
    /// macOS local directory account.
    Macos {
        /// Persistent directory identity, distinct from numeric UID.
        generated_uid: Uuid,
    },
}
impl AccessAccount {
    /// Check syntax; the endpoint must separately establish local account provenance.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid = match self {
            Self::Windows { sid, authority } => authority.valid_for(sid),
            Self::Macos { generated_uid } => !generated_uid.is_nil(),
        };
        if valid {
            Ok(())
        } else {
            Err(WireError::InvalidValue)
        }
    }
    /// Required native platform.
    pub const fn platform(&self) -> TaskPlatform {
        match self {
            Self::Windows { .. } => TaskPlatform::Windows,
            Self::Macos { .. } => TaskPlatform::Macos,
        }
    }
}

/// Requested account privilege. Absence preserves an existing account's privilege.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessRole {
    /// Ordinary local user.
    Standard,
    /// Local administrator, requiring explicit RSS device-account authorization.
    Administrator,
}

/// Explicit OS account handling when removing RSS integration. Data is always retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessAccountDisposition {
    /// Preserve the account's enabled state and privilege.
    Keep,
    /// Disable interactive login without deleting the account.
    Disable,
    /// Remove administrator privilege while preserving login.
    Standard,
}

/// Common product configuration; Apple protocol payloads remain with the Apple owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessConfiguration {
    /// Device-wide Mac profile settings; absence excludes Mac integration from this policy.
    pub mac: Option<crate::platform_sso::LoginConfiguration>,
    /// Explicit admitted Windows account authorities.
    pub windows_accounts: Vec<AccessWindowsKind>,
    /// Permit the first association to the currently authenticated interactive local account.
    pub self_enrollment: bool,
    /// Enable the platform's RSS login integration.
    pub enabled: bool,
    /// Explicit role convergence; null preserves existing role, new accounts default standard.
    pub role: Option<AccessRole>,
}

/// Exact account and login session attested by the authenticated native Agent ingress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessLocalSession {
    /// Current account, not selected by the browser.
    pub account: AccessAccount,
    /// Native login instance; logoff/switch invalidates the pending ceremony.
    pub session_id: Uuid,
}
impl AccessLocalSession {
    /// Validate bounded identities before any authority lookup.
    pub fn validate(&self) -> Result<(), WireError> {
        self.account.validate()?;
        if self.session_id.is_nil() {
            Err(WireError::InvalidValue)
        } else {
            Ok(())
        }
    }
}

/// One independent native capability observation, never inferred from transport success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessObservation {
    /// The capability has been verified for this exact local account.
    Present,
    /// Native inspection verified the capability is absent.
    Absent,
    /// Inspection could not establish the capability.
    Unknown,
    /// A qualified local administrator must authorize the operation.
    NeedsAdministrator,
}

/// Apple account facts are separate from PSSO registration and Secure Enclave keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessMacFacts {
    /// Native account password synchronization, never inferred from the IdP exchange.
    pub password_sync: AccessObservation,
    /// Native login keychain synchronization, independent of account password success.
    pub keychain_sync: AccessObservation,
    /// The account's Secure Token status, not Bootstrap Token custody.
    pub secure_token: AccessObservation,
    /// Apple silicon volume ownership.
    pub volume_owner: AccessObservation,
    /// Actual FileVault unlock eligibility, not merely the disk encryption setting.
    pub filevault_unlock: AccessObservation,
}

/// Closed native failure classes; never include command output or user credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessFailure {
    /// The native integration is not installed or supported.
    Unsupported,
    /// The exact local identity or current login changed.
    AccountChanged,
    /// A requested name already belongs to a different account.
    NameConflict,
    /// An operation would remove the last administrator or recovery-capable account.
    RecoveryAccountProtected,
    /// User input is needed locally; no password is returned to the server.
    NeedsUser,
    /// Native persistence or read-back failed.
    NativeFailure,
}

/// Effect receipt. Received/start ACKs are carried by the existing task protocol separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessEffect {
    /// The exact requested configuration has been durably installed and read back.
    Applied {
        /// Identity actually changed or confirmed.
        account: AccessAccount,
        /// Actual native privilege after the operation.
        role: AccessRole,
        /// macOS-specific facts; required on macOS and absent on Windows.
        mac: Option<AccessMacFacts>,
        /// Installed Windows factors and exact durable escrow coordinates.
        windows: Option<AccessWindowsFacts>,
    },
    /// Integration removal and the requested OS disposition were independently read back.
    Unbound {
        /// Verified account handling; account data is retained.
        disposition: AccessAccountDisposition,
    },
    /// The device cannot yet establish the effect of the original attempt.
    Unknown,
    /// A known failure without claiming the requested state was installed.
    Failed {
        /// Bounded public failure reason.
        reason: AccessFailure,
    },
}
impl AccessEffect {
    /// Reject cross-platform or incomplete successful evidence.
    pub fn validate_for(&self, platform: TaskPlatform) -> Result<(), WireError> {
        if let Self::Applied {
            account,
            mac,
            windows,
            ..
        } = self
        {
            account.validate()?;
            if account.platform() != platform
                || mac.is_some() != (platform == TaskPlatform::Macos)
                || windows.is_some() != (platform == TaskPlatform::Windows)
            {
                return Err(WireError::InvalidValue);
            }
        }
        if let Self::Applied {
            account,
            windows: Some(facts),
            ..
        } = self
        {
            if facts.factor_generation < 1 {
                return Err(WireError::InvalidValue);
            }
            facts.recovery.validate()?;
            if !matches!((&facts.recovery.subject, account), (super::CredentialSubject::RssLogin { sid, .. }, AccessAccount::Windows { sid: expected, .. }) if sid == expected)
            {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
    /// Application completion includes Secure Token confirmation on macOS.
    pub fn complete(&self, configuration: &AccessConfiguration) -> bool {
        match self {
            Self::Applied { mac: Some(mac), .. } => {
                let Some(login) = &configuration.mac else {
                    return false;
                };
                mac.secure_token == AccessObservation::Present
                    && (login.authentication != crate::platform_sso::AuthenticationMode::Password
                        || (mac.password_sync == AccessObservation::Present
                            && mac.keychain_sync == AccessObservation::Present))
                    && (login.filevault == crate::platform_sso::LoginPolicy::Local
                        || (mac.filevault_unlock == AccessObservation::Present
                            && mac.volume_owner == AccessObservation::Present))
            }
            Self::Applied { mac: None, .. } | Self::Unbound { .. } => true,
            Self::Unknown | Self::Failed { .. } => false,
        }
    }
}

/// Exactly correlated application report; cannot select a different tenant or device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessResult {
    /// Stable business binding identity.
    pub binding_id: Uuid,
    /// Fences replacement/revocation of the personnel association.
    pub binding_generation: i64,
    /// Exact desired configuration revision.
    pub revision: i64,
    /// Digest frozen into the signed task.
    pub definition_digest: [u8; 32],
    /// Actual native effect.
    pub effect: AccessEffect,
}
impl AccessResult {
    /// Validate a report before correlating its task and attempt.
    pub fn validate_for(&self, platform: TaskPlatform) -> Result<(), WireError> {
        if self.binding_id.is_nil()
            || self.binding_generation < 1
            || self.revision < 1
            || self.definition_digest == [0; 32]
        {
            return Err(WireError::InvalidValue);
        }
        self.effect.validate_for(platform)
    }
}

/// Offline RSS recovery usage fact. It neither consumes a key nor authenticates a person.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessRecoveryUse {
    /// Durable local event identity, preserved during upload retries.
    pub operation_id: Uuid,
    /// Exact escrow entry.
    pub material: Uuid,
    /// Exact material version used locally.
    pub version: i64,
    /// Device-observed UTC seconds; receipt time remains a separate server fact.
    pub used_at: i64,
}
impl AccessRecoveryUse {
    /// Validate bounded coordinates, without inferring current credential validity.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.operation_id.is_nil()
            || self.material.is_nil()
            || self.version < 1
            || self.used_at < 1
        {
            Err(WireError::InvalidValue)
        } else {
            Ok(())
        }
    }
}

/// Windows initialization is part of the access task, not a second policy or scheduler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessWindowsPlan {
    /// Install a new factor generation after durable escrow acknowledgement.
    Initialize {
        /// Public encryption recipient; never used for offline verification.
        recipient: super::CredentialRecipient,
        /// Exact recovery revision before this mutation.
        expected_revision: i64,
    },
    /// Apply configuration while preserving existing factors.
    Preserve {
        /// Last applied factor facts; the endpoint must independently read them back.
        facts: AccessWindowsFacts,
    },
}
impl AccessWindowsPlan {
    /// Structural validation does not establish task authority.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Initialize {
                recipient,
                expected_revision,
            } => {
                use base64::Engine;
                if *expected_revision < 0
                    || recipient.key_id.len() != 64
                    || !recipient.key_id.bytes().all(|v| v.is_ascii_hexdigit())
                    || recipient.public_key.len() > 8192
                    || base64::engine::general_purpose::STANDARD
                        .decode(&recipient.public_key)
                        .map_err(|_| WireError::InvalidValue)?
                        .is_empty()
                {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::Preserve { facts } => {
                if facts.factor_generation < 1 {
                    return Err(WireError::InvalidValue);
                }
                facts.recovery.validate()?;
            }
        }
        Ok(())
    }
}
/// Installed factor identity is independent of the account association and configuration revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessWindowsFacts {
    /// Exact installed factor generation.
    pub factor_generation: i64,
    /// Exact recovery material retained on this endpoint.
    pub recovery: super::CredentialReceipt,
}
/// Actual native account identity observed by a started task; not a successful application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessPrepared {
    /// Exact binding being prepared.
    pub binding_id: Uuid,
    /// Exact binding generation.
    pub binding_generation: i64,
    /// Exact configuration revision.
    pub revision: i64,
    /// Original signed definition.
    pub definition_digest: [u8; 32],
    /// Actual stable OS identity; never an account name.
    pub account: AccessAccount,
}
/// Safe employee-facing binding projection. This is not a login credential.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessBindingStatus {
    /// Desired account handling on revocation.
    pub account_disposition: AccessAccountDisposition,
    /// Stable binding.
    pub id: Uuid,
    /// Association generation.
    pub binding_generation: i64,
    /// Factor replacement generation.
    pub factor_generation: i64,
    /// Desired revision.
    pub revision: i64,
    /// Whether this association is revoked on the server.
    pub revoked: bool,
    /// Actual native account, if known.
    pub account: Option<AccessAccount>,
    /// Desired configuration.
    pub configuration: AccessConfiguration,
    /// Last received desired revision.
    pub received_revision: Option<i64>,
    /// Last confirmed applied revision.
    pub applied_revision: Option<i64>,
    /// Native effect, not inferred from transport acknowledgement.
    pub effect: Option<AccessEffect>,
}
/// One currently eligible first-enrollment policy.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessPolicyOption {
    /// Policy identity used by begin.
    pub policy: Uuid,
    /// Current published policy version.
    pub version: Uuid,
    /// Safe configuration preview; begin rechecks current authority.
    pub configuration: AccessConfiguration,
}
/// Bounded employee discovery; cursors advance scanned rows, including ineligible policies.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessDirectory {
    /// Eligible policies in this scan page.
    pub policies: Vec<AccessPolicyOption>,
    /// Cursor for the next policy scan.
    pub after: Option<Uuid>,
    /// This authenticated person's bindings in the current device registration.
    pub bindings: Vec<AccessBindingStatus>,
}

/// Stable Windows identity authority. Display names and email addresses are excluded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessWindowsAuthority {
    /// The current registered computer's SAM database.
    Local,
    /// Native directory domain SID, distinct from the user's account SID.
    ActiveDirectory {
        /// SID of the native AD domain, excluding the user's RID.
        domain_sid: String,
    },
    /// Stable directory identifiers from the native Entra account.
    Entra {
        /// Tenant that owns the native directory account.
        tenant_id: Uuid,
        /// Immutable user object identifier within that tenant.
        object_id: Uuid,
    },
}
impl AccessWindowsAuthority {
    /// Structural validation; the authenticated Agent must establish the native provenance.
    pub fn valid_for(&self, sid: &str) -> bool {
        if !valid_windows_account_sid(sid) {
            return false;
        }
        match self {
            Self::Local => sid.starts_with("S-1-5-21-"),
            Self::ActiveDirectory { domain_sid } => {
                sid.starts_with("S-1-5-21-")
                    && sid
                        .rsplit_once('-')
                        .is_some_and(|(domain, _)| domain == domain_sid)
            }
            Self::Entra {
                tenant_id,
                object_id,
            } => !tenant_id.is_nil() && !object_id.is_nil() && sid.starts_with("S-1-12-1-"),
        }
    }
}
/// A native user SID, not a display name. This check alone grants no identity authority.
pub fn valid_windows_account_sid(sid: &str) -> bool {
    let parts: Vec<_> = sid.split('-').collect();
    parts.len() == 8
        && (parts[..4] == ["S", "1", "5", "21"] || parts[..4] == ["S", "1", "12", "1"])
        && parts[4..]
            .iter()
            .all(|p| p.parse::<u32>().is_ok_and(|n| n.to_string() == *p))
        && parts[4..].iter().any(|p| *p != "0")
}

/// Windows account classes admitted by the selected policy.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessWindowsKind {
    /// Local SAM account.
    Local,
    /// AD domain account.
    ActiveDirectory,
    /// Entra directory account.
    Entra,
}
impl AccessWindowsAuthority {
    /// Policy class of this native authority.
    pub const fn kind(&self) -> AccessWindowsKind {
        match self {
            Self::Local => AccessWindowsKind::Local,
            Self::ActiveDirectory { .. } => AccessWindowsKind::ActiveDirectory,
            Self::Entra { .. } => AccessWindowsKind::Entra,
        }
    }
}
impl AccessConfiguration {
    /// Check explicit platform policy and bounded settings.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.windows_accounts.len() > 3
            || self
                .windows_accounts
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.windows_accounts.len()
            || (self.mac.is_none() && self.windows_accounts.is_empty())
        {
            return Err(WireError::InvalidValue);
        }
        if let Some(mac) = &self.mac {
            mac.validate()?;
        }
        Ok(())
    }
    /// Account admission; display names never choose a platform identity class.
    pub fn admits(&self, account: &AccessAccount) -> bool {
        self.validate().is_ok()
            && match account {
                AccessAccount::Windows { authority, .. } => {
                    self.windows_accounts.contains(&authority.kind())
                }
                AccessAccount::Macos { .. } => self.mac.is_some(),
            }
    }
}
