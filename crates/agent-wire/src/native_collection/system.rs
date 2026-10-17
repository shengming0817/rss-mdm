//! Closed security, account, certificate and update reads. No executable or SQL input.
//! ref: osquery/osquery osquery/tables/system/windows/bitlocker_info.cpp@5.23.1
//! ref: osquery/osquery osquery/tables/system/darwin/gatekeeper.cpp@5.23.1
use super::*;

/// Approved local account set; never a directory recursion or effective authorization query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountSelection {
    /// All local accounts, including disabled and system accounts.
    Local,
    /// Only these stable SIDs (Windows) or GeneratedUIDs (macOS).
    Selected {
        /// Nonempty bounded stable account identities.
        identities: BTreeSet<String>,
    },
}
/// Local account evidence families. Membership is direct, not transitive permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountSection {
    /// Stable account identity, type and enabled state.
    Accounts,
    /// Direct members of the local administrators group; no recursive expansion.
    Administrators,
    /// Sessions necessary to explain local execution, never personal activity.
    Sessions,
}
/// Approved Windows store; collection must not mount offline user hives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WindowsCertificateStore {
    /// Personal certificate metadata.
    My,
    /// Trusted root metadata.
    Root,
    /// Intermediate certificate metadata.
    Ca,
    /// Trusted publisher certificate metadata.
    TrustedPublisher,
}
/// Approved macOS keychain. Never prompts, unlocks a keychain or traverses arbitrary paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MacosCertificateStore {
    /// Machine System keychain.
    System,
    /// System root certificate keychain.
    SystemRoots,
    /// Only the bound user’s login keychain.
    Login,
}
/// Read mode is execution evidence, not an asset namespace or permission to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateScanMode {
    /// Read locally available evidence; no online refresh.
    Local,
    /// Explicit read-only online discovery through the existing configured source.
    Online,
}
/// Independent evidence sets. History cannot prove the installed or applicable set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateSection {
    /// Availability, observed source, scan interval and coverage.
    Scan,
    /// Applicable updates, with source evidence.
    Available,
    /// Verified installed update set.
    Installed,
    /// Historical results; not an inventory of installed updates.
    History,
    /// Observed pending reboot, not permission to restart.
    Reboot,
}
/// macOS states remain distinct; local token evidence never proves server escrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MacosSecuritySection {
    /// Assessment configuration, component presence and observable availability.
    Gatekeeper,
    /// Component/version presence and observable protection state.
    Xprotect,
    /// Extension signing identity, configuration and activation evidence.
    SystemExtensions,
    /// Local FileVault state, independent from key escrow.
    Filevault,
    /// Local application firewall state.
    Firewall,
    /// System integrity protection observation.
    Sip,
    /// Hardware encryption observation, independent from FileVault.
    HardwareEncryption,
    /// Bound user’s local Secure Token observation.
    SecureToken,
    /// Local Bootstrap Token observation, never server escrow success.
    BootstrapToken,
}
/// Only permissions needed by the explicitly selected application, never a TCC dump.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationPermission {
    /// Probe only the selected application’s required Full Disk Access.
    FullDiskAccess,
    /// Probe only the selected application’s accessibility permission.
    Accessibility,
    /// Probe only the selected application’s screen-capture permission.
    ScreenCapture,
}
/// The running product or an explicitly approved Windows service and signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsApplicationTarget {
    /// The running, registered product itself.
    Agent,
    /// One explicitly approved signing and application identity.
    Signed {
        /// Exact approved service.
        service: String,
        /// Approved signer.
        publisher: String,
    },
}
/// The running product or one explicitly approved macOS signed bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosApplicationTarget {
    /// The running, registered product itself.
    Agent,
    /// One explicitly approved signing and application identity.
    Signed {
        /// Exact bundle identifier.
        bundle_id: String,
        /// Approved signing team.
        team_id: String,
    },
}
/// Update scan provenance survives empty lists and failed queries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeScanEvidence {
    /// Exact requested read mode.
    pub mode: UpdateScanMode,
    /// Observed source identifier, never a credential-bearing URL. None means unavailable.
    pub source: Option<String>,
    /// Actual scan start time, not report upload time. None means not scanned.
    pub started_at: Option<i64>,
    /// Actual scan finish time. Local cache reads retain the original scan interval.
    pub finished_at: Option<i64>,
}
impl NativeScanEvidence {
    /// Validate chronology and source without inventing a completed scan.
    pub fn valid(&self, collected_at: i64, complete: bool) -> bool {
        self.source.as_deref().is_none_or(identifier)
            && self.started_at.is_none_or(|t| t > 0 && t <= collected_at)
            && self
                .finished_at
                .is_none_or(|t| self.started_at.is_some_and(|s| t >= s && t <= collected_at))
            && (!complete
                || (self.source.is_some()
                    && self.started_at.is_some()
                    && self.finished_at.is_some()))
    }
}
/// Fixed native reads; output schemas and instance identity are owned by this enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeSystemQuery {
    /// Read-only GetConversionStatus/GetLockStatus/etc., never arbitrary WMI methods.
    WindowsBitlocker,
    /// Domain, private and public profiles individually, not one aggregate switch.
    WindowsFirewall,
    /// Defender configuration, mode and observed protection health.
    WindowsDefender,
    /// Secure Boot firmware observation, independent from TPM presence.
    WindowsSecureBoot,
    /// Local AD/Entra/MDM observations, never server management authority.
    WindowsJoin,
    /// Approved local Windows identity facts.
    WindowsAccounts {
        /// Closed evidence section.
        section: AccountSection,
        /// Approved account universe.
        selection: AccountSelection,
    },
    /// Read-only metadata from one approved machine or current-user store.
    WindowsCertificates {
        /// Exact approved store.
        store: WindowsCertificateStore,
        /// True requires the current signed user session.
        user: bool,
    },
    /// Use the currently configured WUA source. Always disable automatic WUA upgrade;
    /// never register a service, change its selection, download, install or reboot.
    WindowsUpdates {
        /// Closed evidence section.
        section: UpdateSection,
        /// Explicit read mode; never a deployment action.
        mode: UpdateScanMode,
    },
    /// One fixed local macOS security observation.
    MacosSecurity {
        /// Closed evidence section.
        section: MacosSecuritySection,
    },
    /// Approved local macOS identity facts.
    MacosAccounts {
        /// Closed evidence section.
        section: AccountSection,
        /// Approved account universe.
        selection: AccountSelection,
    },
    /// Read-only metadata from one approved keychain.
    MacosCertificates {
        /// Exact approved store.
        store: MacosCertificateStore,
    },
    /// Version-probed read-only queries; no install/download/restart or silent shell fallback.
    MacosUpdates {
        /// Closed evidence section.
        section: UpdateSection,
        /// Explicit read mode; never a deployment action.
        mode: UpdateScanMode,
    },
    /// Exact service identity and signer; no executable path or invocation parameters.
    WindowsApplication {
        /// Approved application identity.
        target: WindowsApplicationTarget,
    },
    /// Exact signed application identity; no all-application privacy scan.
    MacosApplication {
        /// Approved application identity.
        target: MacosApplicationTarget,
        /// Exact required permission probes, never global privacy inventory.
        permissions: BTreeSet<ApplicationPermission>,
    },
}
fn strings(names: &[&str]) -> BTreeMap<String, NativeType> {
    names
        .iter()
        .map(|k| ((*k).into(), NativeType::String))
        .collect()
}
fn text<'a>(row: &'a BTreeMap<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    row.get(key).and_then(|v| v.as_str())
}
/// Stable GeneratedUID, distinct from Apple MDM user identity and transient Unix UID.
pub fn generated_uid_valid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|id| !id.is_nil() && id.to_string() == s)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl NativeSystemQuery {
    /// Update mode for evidence binding; other queries must not attach scan provenance.
    pub const fn scan_mode(&self) -> Option<UpdateScanMode> {
        match self {
            Self::WindowsUpdates { mode, .. } | Self::MacosUpdates { mode, .. } => Some(*mode),
            _ => None,
        }
    }
    /// Exact platform; a plan cannot mix platforms.
    pub const fn platform(&self) -> TaskPlatform {
        match self {
            Self::WindowsBitlocker
            | Self::WindowsFirewall
            | Self::WindowsDefender
            | Self::WindowsSecureBoot
            | Self::WindowsJoin
            | Self::WindowsAccounts { .. }
            | Self::WindowsCertificates { .. }
            | Self::WindowsUpdates { .. }
            | Self::WindowsApplication { .. } => TaskPlatform::Windows,
            Self::MacosSecurity { .. }
            | Self::MacosAccounts { .. }
            | Self::MacosCertificates { .. }
            | Self::MacosUpdates { .. }
            | Self::MacosApplication { .. } => TaskPlatform::Macos,
        }
    }
    /// Exact capability contract. Only these declared native engines can execute a recipe.
    pub const fn engine(&self) -> NativeEngine {
        match self {
            Self::WindowsAccounts { .. } | Self::WindowsJoin => NativeEngine::WindowsAccounts,
            Self::WindowsCertificates { .. } => NativeEngine::WindowsCertificates,
            Self::WindowsUpdates { .. } => NativeEngine::WindowsUpdates,
            Self::WindowsBitlocker
            | Self::WindowsFirewall
            | Self::WindowsDefender
            | Self::WindowsSecureBoot
            | Self::WindowsApplication { .. } => NativeEngine::WindowsSecurity,
            Self::MacosAccounts { .. } => NativeEngine::MacosAccounts,
            Self::MacosCertificates { .. } => NativeEngine::MacosCertificates,
            Self::MacosUpdates { .. } => NativeEngine::MacosUpdates,
            Self::MacosSecurity { .. } | Self::MacosApplication { .. } => {
                NativeEngine::MacosSecurity
            }
        }
    }
    /// User keychains and user token/permission evidence require the current helper.
    pub const fn execution_identity(&self) -> ExecutionIdentity {
        match self {
            Self::WindowsCertificates { user: true, .. }
            | Self::MacosCertificates {
                store: MacosCertificateStore::Login,
            }
            | Self::MacosSecurity {
                section: MacosSecuritySection::SecureToken,
            }
            | Self::MacosApplication { .. } => ExecutionIdentity::LoggedInUser,
            _ => ExecutionIdentity::System,
        }
    }
    /// Whether this is a complete enumeration or one observation.
    pub const fn cardinality(&self) -> NativeCardinality {
        match self {
            Self::WindowsBitlocker
            | Self::WindowsFirewall
            | Self::WindowsAccounts { .. }
            | Self::MacosAccounts { .. }
            | Self::WindowsCertificates { .. }
            | Self::MacosCertificates { .. }
            | Self::MacosSecurity {
                section: MacosSecuritySection::SystemExtensions,
            }
            | Self::WindowsUpdates {
                section:
                    UpdateSection::Available | UpdateSection::Installed | UpdateSection::History,
                ..
            }
            | Self::MacosUpdates {
                section:
                    UpdateSection::Available | UpdateSection::Installed | UpdateSection::History,
                ..
            } => NativeCardinality::List,
            _ => NativeCardinality::ExactlyOne,
        }
    }
    /// Closed allowed output. Optional observations are omitted, never fabricated as false.
    pub fn properties(&self) -> BTreeMap<String, NativeType> {
        use NativeType::{Array, Integer, String as S};
        let mut p = match self {
            Self::WindowsBitlocker => {
                strings(&["id", "conversion", "protection", "lock", "algorithm"])
            }
            Self::WindowsFirewall => strings(&["id", "configured", "running"]),
            Self::WindowsDefender => strings(&[
                "presence",
                "configured",
                "running",
                "mode",
                "health",
                "signature_version",
            ]),
            Self::WindowsSecureBoot => strings(&["state"]),
            Self::WindowsJoin => strings(&["ad", "entra", "mdm"]),
            Self::WindowsAccounts {
                section: AccountSection::Accounts,
                ..
            }
            | Self::MacosAccounts {
                section: AccountSection::Accounts,
                ..
            } => strings(&["id", "name", "account_type", "enabled"]),
            Self::WindowsAccounts {
                section: AccountSection::Administrators,
                ..
            }
            | Self::MacosAccounts {
                section: AccountSection::Administrators,
                ..
            } => strings(&["id", "member", "member_type", "resolved"]),
            Self::WindowsAccounts {
                section: AccountSection::Sessions,
                ..
            }
            | Self::MacosAccounts {
                section: AccountSection::Sessions,
                ..
            } => strings(&["id", "owner", "state"]),
            Self::WindowsCertificates { .. } | Self::MacosCertificates { .. } => {
                strings(&["id", "subject", "issuer", "scope", "owner", "store"])
            }
            Self::MacosSecurity {
                section: MacosSecuritySection::SystemExtensions,
            } => strings(&[
                "id",
                "team_id",
                "bundle_id",
                "version",
                "configured",
                "running",
            ]),
            Self::MacosSecurity {
                section: MacosSecuritySection::Gatekeeper | MacosSecuritySection::Xprotect,
            } => strings(&["presence", "configured", "running", "version"]),
            Self::MacosSecurity {
                section: MacosSecuritySection::SecureToken,
            } => strings(&["owner", "state"]),
            Self::MacosSecurity { .. } => strings(&["state"]),
            Self::WindowsUpdates {
                section: UpdateSection::Scan,
                ..
            }
            | Self::MacosUpdates {
                section: UpdateSection::Scan,
                ..
            } => strings(&["availability", "mode", "source", "coverage"]),
            Self::WindowsUpdates {
                section: UpdateSection::Reboot,
                ..
            }
            | Self::MacosUpdates {
                section: UpdateSection::Reboot,
                ..
            } => strings(&["state"]),
            Self::WindowsUpdates { .. } | Self::MacosUpdates { .. } => {
                strings(&["id", "title", "version", "origin", "state"])
            }
            Self::WindowsApplication { .. } | Self::MacosApplication { .. } => strings(&[
                "identity",
                "signer",
                "presence",
                "signature",
                "running",
                "health",
            ]),
        };
        match self {
            Self::WindowsBitlocker => {
                p.insert("encrypted_percent".into(), Integer);
            }
            Self::MacosAccounts {
                section: AccountSection::Accounts,
                ..
            } => {
                p.insert("uid".into(), Integer);
            }
            Self::WindowsCertificates { .. } | Self::MacosCertificates { .. } => {
                p.insert("not_before".into(), Integer);
                p.insert("not_after".into(), Integer);
            }
            Self::WindowsUpdates {
                section: UpdateSection::Scan,
                ..
            }
            | Self::MacosUpdates {
                section: UpdateSection::Scan,
                ..
            } => {
                p.insert("scan_started_at".into(), Integer);
                p.insert("scan_finished_at".into(), Integer);
            }
            Self::MacosApplication { .. } => {
                p.insert("permissions".into(), Array { items: Box::new(S) });
            }
            _ => {}
        }
        p
    }
    /// Reject ambiguous selectors and modes that imply unsupported side effects.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid = match self {
            Self::WindowsAccounts { selection, .. } | Self::MacosAccounts { selection, .. } => {
                match selection {
                    AccountSelection::Local => true,
                    AccountSelection::Selected { identities } => {
                        !identities.is_empty()
                            && identities.len() <= 256
                            && identities.iter().all(|s| {
                                if self.platform() == TaskPlatform::Windows {
                                    sid_valid(s)
                                } else {
                                    generated_uid_valid(s)
                                }
                            })
                    }
                }
            }
            Self::WindowsApplication { target } => match target {
                WindowsApplicationTarget::Agent => true,
                WindowsApplicationTarget::Signed { service, publisher } => {
                    identifier(service)
                        && !publisher.is_empty()
                        && publisher.len() <= 255
                        && !publisher.chars().any(char::is_control)
                }
            },
            Self::MacosApplication {
                target,
                permissions,
            } => {
                permissions.len() <= 3
                    && match target {
                        MacosApplicationTarget::Agent => true,
                        MacosApplicationTarget::Signed { bundle_id, team_id } => {
                            identifier(bundle_id)
                                && team_id.len() == 10
                                && team_id
                                    .bytes()
                                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                        }
                    }
            }
            Self::WindowsUpdates { section, mode } | Self::MacosUpdates { section, mode } => {
                *mode == UpdateScanMode::Local
                    || matches!(section, UpdateSection::Scan | UpdateSection::Available)
            }
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(WireError::InvalidValue)
        }
    }
    /// Stable store identity, shared by declaration, row checks and server scope mapping.
    pub fn certificate_store(&self) -> Option<&'static str> {
        match self {
            Self::WindowsCertificates { store, .. } => Some(match store {
                WindowsCertificateStore::My => "my",
                WindowsCertificateStore::Root => "root",
                WindowsCertificateStore::Ca => "ca",
                WindowsCertificateStore::TrustedPublisher => "trusted_publisher",
            }),
            Self::MacosCertificates { store } => Some(match store {
                MacosCertificateStore::System => "system",
                MacosCertificateStore::SystemRoots => "system_roots",
                MacosCertificateStore::Login => "login",
            }),
            _ => None,
        }
    }
    /// Validate all present data, including partial/failed evidence, before persistence.
    pub fn accepts_row(&self, row: &BTreeMap<String, serde_json::Value>) -> bool {
        let schema = self.properties();
        if row
            .iter()
            .any(|(k, v)| !schema.get(k).is_some_and(|t| t.accepts(v)))
        {
            return false;
        }
        let vocab = |key: &str, values: &[&str]| text(row, key).is_none_or(|v| values.contains(&v));
        if !vocab("presence", &["present", "absent", "unknown"])
            || !vocab("configured", &["enabled", "disabled", "unknown"])
            || !vocab("running", &["enabled", "disabled", "unknown"])
            || !vocab("health", &["healthy", "unhealthy", "passive", "unknown"])
        {
            return false;
        }
        if let Some(store) = self.certificate_store() {
            let user = self.execution_identity() == ExecutionIdentity::LoggedInUser;
            if text(row, "store") != Some(store)
                || text(row, "scope") != Some(if user { "user" } else { "device" })
                || (!user && text(row, "owner") != Some(""))
                || (user
                    && !text(row, "owner").is_some_and(|s| {
                        if self.platform() == TaskPlatform::Windows {
                            sid_valid(s)
                        } else {
                            generated_uid_valid(s)
                        }
                    }))
            {
                return false;
            }
            // SHA-256 of the public certificate only; never serialize DER or key material.
            if !text(row, "id").is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }) {
                return false;
            }
        }
        match self {
            Self::WindowsBitlocker => {
                vocab(
                    "conversion",
                    &[
                        "decrypted",
                        "encrypted",
                        "encrypting",
                        "decrypting",
                        "encryption_paused",
                        "decryption_paused",
                        "unknown",
                    ],
                ) && vocab("protection", &["unprotected", "protected", "unknown"])
                    && vocab("lock", &["unlocked", "locked", "unknown"])
                    && row
                        .get("encrypted_percent")
                        .is_none_or(|v| v.as_i64().is_some_and(|n| (0..=100).contains(&n)))
            }
            Self::WindowsFirewall => {
                matches!(text(row, "id"), Some("domain" | "private" | "public"))
            }
            Self::WindowsDefender => vocab("mode", &["normal", "passive", "disabled", "unknown"]),
            Self::WindowsJoin => ["ad", "entra", "mdm"]
                .iter()
                .all(|key| vocab(key, &["joined", "not_joined", "unknown"])),
            Self::WindowsAccounts { section, selection }
            | Self::MacosAccounts { section, selection } => {
                let key = match section {
                    AccountSection::Accounts => "id",
                    AccountSection::Administrators => "member",
                    AccountSection::Sessions => "owner",
                };
                text(row, key).is_some_and(|s| {
                    (if self.platform() == TaskPlatform::Windows {
                        sid_valid(s)
                    } else {
                        generated_uid_valid(s)
                    }) && match selection {
                        AccountSelection::Local => true,
                        AccountSelection::Selected { identities } => identities.contains(s),
                    }
                }) && vocab("enabled", &["enabled", "disabled", "unknown"])
                    && vocab("resolved", &["resolved", "unresolved"])
            }
            Self::WindowsUpdates { section, mode } | Self::MacosUpdates { section, mode } => {
                match section {
                    UpdateSection::Scan => {
                        text(row, "mode")
                            == Some(match mode {
                                UpdateScanMode::Local => "local",
                                UpdateScanMode::Online => "online",
                            })
                            && vocab("availability", &["available", "unavailable", "unknown"])
                            && vocab(
                                "coverage",
                                &["complete", "partial", "not_scanned", "unknown"],
                            )
                    }
                    UpdateSection::Available => text(row, "state") == Some("available"),
                    UpdateSection::Installed => text(row, "state") == Some("installed"),
                    UpdateSection::History => vocab("state", &["installed", "failed", "unknown"]),
                    UpdateSection::Reboot => {
                        vocab("state", &["required", "not_required", "unknown"])
                    }
                }
            }
            Self::WindowsApplication { target } => {
                vocab("health", &["unknown"])
                    && vocab("signature", &["valid", "invalid", "unknown"])
                    && match target {
                        WindowsApplicationTarget::Agent => {
                            text(row, "identity").is_some_and(identifier)
                        }
                        WindowsApplicationTarget::Signed { service, publisher } => {
                            text(row, "identity") == Some(service)
                                && text(row, "signer") == Some(publisher)
                        }
                    }
            }
            Self::MacosApplication {
                target,
                permissions,
            } => {
                vocab("health", &["unknown"])
                    && vocab("signature", &["valid", "invalid", "unknown"])
                    && (match target {
                        MacosApplicationTarget::Agent => {
                            text(row, "identity").is_some_and(identifier)
                        }
                        MacosApplicationTarget::Signed { bundle_id, team_id } => {
                            text(row, "identity") == Some(bundle_id)
                                && text(row, "signer") == Some(team_id)
                        }
                    })
                    && row.get("permissions").is_none_or(|v| {
                        v.as_array().is_some_and(|a| {
                            a.iter().all(|v| {
                                v.as_str().is_some_and(|s| {
                                    permissions.iter().any(|p| {
                                        let k = match p {
                                            ApplicationPermission::FullDiskAccess => {
                                                "full_disk_access"
                                            }
                                            ApplicationPermission::Accessibility => "accessibility",
                                            ApplicationPermission::ScreenCapture => {
                                                "screen_capture"
                                            }
                                        };
                                        ["granted", "denied", "unknown"]
                                            .iter()
                                            .any(|v| s == format!("{k}:{v}"))
                                    })
                                })
                            })
                        })
                    })
            }
            Self::WindowsSecureBoot
            | Self::MacosSecurity {
                section:
                    MacosSecuritySection::Filevault
                    | MacosSecuritySection::Firewall
                    | MacosSecuritySection::Sip
                    | MacosSecuritySection::HardwareEncryption
                    | MacosSecuritySection::SecureToken
                    | MacosSecuritySection::BootstrapToken,
            } => vocab("state", &["enabled", "disabled", "unknown"]),
            _ => true,
        }
    }
}
