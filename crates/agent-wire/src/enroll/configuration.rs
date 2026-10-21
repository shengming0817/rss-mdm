//! Complete signed configuration files and fixed installer publication identities.
use crate::runtime::{Secret, TaskArchitecture, TaskPlatform, WireError, strict_uuid};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// One native target; emulation does not select a different installer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    /// Native operating system.
    pub platform: TaskPlatform,
    /// Native processor architecture.
    pub architecture: TaskArchitecture,
}
/// A quantity authorization, independent of its expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Quantity {
    /// At most this many independently bound devices.
    Finite {
        /// Strictly positive device count.
        #[schemars(range(min = 1))]
        count: std::num::NonZeroU32,
    },
    /// No configuration count ceiling; all other admission conditions still apply.
    Unlimited,
}
/// Immutable identity of an installation candidate, distinct from installer bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Installation {
    /// Published release binding.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub release_id: Uuid,
}
/// Server-frozen metadata; read responses never contain the configuration secret.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    /// Independent file format version.
    #[serde(deserialize_with = "super::version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Reusable configuration identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub configuration_id: Uuid,
    /// Tenant fixed by the management authority.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Trusted HTTPS Agent origin, checked against the installed candidate.
    pub origin: String,
    /// Allowed native targets.
    pub targets: Vec<Target>,
    /// Final frozen Unix expiry, unrelated to device certificate lifetime.
    pub expires_at: i64,
    /// Explicit finite or unlimited count.
    pub quantity: Quantity,
    /// Key identity trusted by the installed candidate.
    pub key_id: String,
}
/// A complete transferable file. Its secret never belongs in URLs, argv or logs.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationFile {
    /// Frozen signed authorization and installation constraints.
    pub configuration: Configuration,
    /// Configuration exchange secret; each device also generates its own grant secret.
    pub secret: Secret,
    /// Base64url Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}
impl Configuration {
    /// Validate producer values and freeze a closed canonical signature domain.
    pub fn signing_bytes(&self, secret: &Secret) -> Result<Vec<u8>, WireError> {
        validate_scope(&self.targets)?;
        let origin = url::Url::parse(&self.origin).map_err(|_| WireError::InvalidValue)?;
        if self.wire_version != 1
            || self.configuration_id.is_nil()
            || self.tenant_id.is_nil()
            || self.expires_at <= 0
            || origin.scheme() != "https"
            || origin.origin().ascii_serialization() != self.origin
            || !origin.username().is_empty()
            || origin.password().is_some()
            || self.origin.len() > 2048
            || self
                .origin
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.key_id.is_empty()
            || self.key_id.len() > 128
            || !self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let mut out = b"rss-mdm-agent-enrollment-configuration-v1-ed25519\0".to_vec();
        out.extend(serde_json::to_vec(&(self, secret)).map_err(|_| WireError::InvalidValue)?);
        Ok(out)
    }
}
/// Validate explicit bounded native targets without duplicate alternatives.
pub fn validate_scope(targets: &[Target]) -> Result<(), WireError> {
    if targets.is_empty()
        || targets.len() > 4
        || targets
            .iter()
            .enumerate()
            .any(|(i, v)| targets[..i].contains(v))
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
/// Exchange one reusable configuration for independently generated machine authority.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Exchange {
    /// Complete signed configuration file.
    pub file: ConfigurationFile,
    /// Original machine operation, retained after unknown settlement.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Independent secret for this machine's grant and progress.
    pub secret: Secret,
    /// Locally generated proof-of-possession CSR.
    #[schemars(extend("minLength"=1,"maxLength"=43692))]
    pub csr: String,
    /// Exact runtime profile frozen by the exchange.
    pub runtime: super::RuntimeProfile,
    /// Exact installation candidate admitted for this grant.
    pub installation: Installation,
}
/// Lookup never allocates authority, including after the reusable file expires.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExchangeStatus {
    /// Independent enrollment version.
    #[serde(deserialize_with = "super::version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Configuration identity, not its shared secret.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub configuration_id: Uuid,
    /// Original machine exchange operation.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Independent original machine secret.
    pub secret: Secret,
}
/// A secret-bound cancellation affects only an unconsumed machine reservation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    /// Independent enrollment version.
    #[serde(deserialize_with = "super::version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Granted machine authorization.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub grant_id: Uuid,
    /// Stable cancellation operation.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Original creation operation.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub creation_operation_id: Uuid,
    /// This machine's grant secret, never the shared configuration secret.
    pub secret: Secret,
}
/// Package format is part of the immutable release identity, never inferred from a URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstallerFormat {
    /// Windows executable; execution parameters are independently defined.
    WindowsExe,
    /// Windows Installer package for native desktop management.
    WindowsMsi,
    /// Windows packaged application for native modern management.
    WindowsMsix,
    /// macOS enterprise installer package.
    MacosPkg,
}
impl InstallerFormat {
    /// Fixed public suffix; no caller-controlled filename.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::WindowsExe => "exe",
            Self::WindowsMsi => "msi",
            Self::WindowsMsix => "msix",
            Self::MacosPkg => "pkg",
        }
    }
}
/// Public metadata for one explicitly published fixed installer.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    /// Release binding identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub release_id: Uuid,
    /// Tenant whose candidate is packaged.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Supported native target.
    pub target: Target,
    /// Frozen product version.
    pub version: String,
    /// Exact installer format frozen by publication.
    pub format: InstallerFormat,
    /// Secret-free installer filename.
    pub filename: String,
    /// Installer byte length.
    pub length: u64,
    /// Installer digest; never used as the installation candidate identity.
    pub installer_sha256: [u8; 32],
}
