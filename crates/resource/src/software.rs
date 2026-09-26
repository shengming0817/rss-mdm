//! Complete immutable software material. Availability and authorization belong to the product.
use crate::{Architecture, Artifact, Digest, Error, Id, Platform, RunAs};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Closed software validation context; never contains submitted values or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareValidationKind {
    /// Source identity or revision is invalid.
    Source,
    /// Package identity or version text is invalid.
    Identity,
    /// Artifact coordinates, origin or primary selection are invalid.
    Artifact,
    /// Exact dependency identity or uniqueness is invalid.
    Dependency,
    /// Bundle manifest, membership or portable path is invalid.
    Bundle,
    /// Invocation, execution identity, arguments or command budget is invalid.
    Command,
    /// Detection definition is invalid.
    Detection,
    /// Platform or architecture is inconsistent with the definition.
    Target,
    /// The complete definition exceeds a structural or encoding budget.
    Budget,
}
impl SoftwareValidationKind {
    /// Stable input-free diagnostic category for storage and host adapters.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "software_source",
            Self::Identity => "software_identity",
            Self::Artifact => "software_artifact",
            Self::Dependency => "software_dependency",
            Self::Bundle => "software_bundle",
            Self::Command => "software_command",
            Self::Detection => "software_detection",
            Self::Target => "software_target",
            Self::Budget => "software_budget",
        }
    }
}
use SoftwareValidationKind as Validation;
fn invalid(kind: Validation) -> Error {
    Error::SoftwareValidation(kind)
}

/// Exact admitted source revision; neither a URL nor a credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSource {
    /// Tenant-local source identity.
    pub id: String,
    /// Exact source revision, never latest.
    pub revision: String,
    /// Digest of the credential-free source snapshot.
    pub sha256: [u8; 32],
}
/// A member of the complete immutable artifact set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareArtifact {
    /// Opaque content reference, not a download URL.
    pub reference: String,
    /// Optional immutable import URL; host origin policy must independently authorize it.
    pub origin: Option<String>,
    /// Exact positive byte length.
    pub length: u64,
    /// SHA-256 of the complete bytes.
    pub sha256: [u8; 32],
}
impl SoftwareArtifact {
    /// Validate and return the shared artifact value.
    pub fn artifact(&self) -> Result<Artifact, Error> {
        Artifact::new(
            Id::new(&self.reference).map_err(|_| invalid(Validation::Artifact))?,
            self.length,
            Digest::from_bytes(self.sha256),
        )
        .map_err(|_| invalid(Validation::Artifact))
    }
}
/// Finite delivery formats; no ambient package-manager fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareFormat {
    /// Private Windows Installer package.
    Msi,
    /// Private macOS installer package.
    Pkg,
    /// One platform/architecture RSS ZIP.
    Bundle,
    /// Exact imported WinGet package.
    Winget,
    /// Exact imported Brew package.
    Brew,
}
/// Explicit executable implementation, not an arbitrary executable path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareExecutor {
    /// Windows Installer.
    Msi,
    /// macOS installer.
    PackageInstaller,
    /// PowerShell 7 with an immutable script entry.
    PowerShell7,
    /// POSIX shell with an immutable script entry.
    PosixSh,
    /// Bash with an immutable script entry.
    Bash,
    /// Explicit WinGet implementation.
    Winget,
    /// Explicit Brew implementation under a user account.
    Brew,
}
/// Frozen invocation. Arguments are literal values, never shell interpolation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareCommand {
    /// Finite implementation selected by the definition.
    pub executor: SoftwareExecutor,
    /// Script artifact key, or declared Bundle entry; absent for native installers.
    pub entry: Option<String>,
    /// Required identity; no implicit elevation or user fallback.
    pub run_as: RunAs,
    /// Ordered literal arguments.
    pub arguments: Vec<String>,
    /// Explicit product-prefixed environment variables.
    pub environment: BTreeMap<String, String>,
    /// Wall-time budget, 1..=86400 seconds.
    pub timeout_seconds: u32,
    /// Combined output limit, 1..=1 MiB.
    pub output_bytes: u32,
}
/// Independent observation, never inferred from an installer's exit status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareDetection {
    /// Exact Windows product code and expected version.
    MsiProduct {
        /// Canonical braced GUID.
        product_code: String,
        /// Exact expected version.
        version: String,
    },
    /// Exact macOS receipt and expected version.
    PkgReceipt {
        /// Exact pkgutil receipt, never a wildcard.
        receipt: String,
        /// Exact expected version.
        version: String,
    },
    /// A controlled script must return the structured presence/version result.
    Script {
        /// Frozen bounded script invocation.
        command: SoftwareCommand,
    },
}
/// Reboot permission. A reported requirement does not itself authorize a reboot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareReboot {
    /// Block an installation requiring reboot.
    Forbid,
    /// Report required reboot for separately authorized handling.
    Report,
}
/// Explicit permission to replace a newer version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareDowngrade {
    /// Never downgrade.
    Deny,
    /// Permit the exact approved downgrade.
    Allow,
}
/// Existing user software is not silently adopted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareOwnership {
    /// Only organization-managed instances may be changed.
    ManagedOnly,
    /// Explicitly allow changes to an existing user-owned instance.
    AllowUserExisting,
}
/// Exact same-tenant dependency; graph validation occurs under product resource locks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareDependency {
    /// Resource identity in this version's tenant.
    pub resource: String,
    /// Exact immutable resource version.
    pub version: String,
    /// Expected complete resource digest.
    pub sha256: [u8; 32],
}
/// Every ZIP member other than manifest.json is declared here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    /// Exact uncompressed length; empty payload files are allowed.
    pub length: u64,
    /// SHA-256 of uncompressed bytes.
    pub sha256: [u8; 32],
}
/// Canonical manifest.json value. Its canonical bytes and all entries are approved together.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Must be 1. Unknown versions are rejected.
    pub schema: u32,
    /// Exact target platform.
    pub platform: Platform,
    /// Exact target architecture.
    pub architecture: Architecture,
    /// Relative slash-separated regular-file members, excluding manifest.json.
    pub entries: BTreeMap<String, BundleEntry>,
}
/// Public construction/wire input; use SoftwareDefinition to validate it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSpec {
    /// Immutable source snapshot identity.
    pub source: SoftwareSource,
    /// Exact ecosystem package text.
    pub package: String,
    /// Exact ecosystem version text, not SemVer.
    pub version: String,
    /// Explicit package format.
    pub format: SoftwareFormat,
    /// Key of the primary installer in artifacts.
    pub primary: String,
    /// Complete artifact closure including auxiliary scripts.
    pub artifacts: BTreeMap<String, SoftwareArtifact>,
    /// Installation behavior.
    pub install: SoftwareCommand,
    /// Explicit removal behavior; absent means unsupported.
    pub uninstall: Option<SoftwareCommand>,
    /// Required independent detection.
    pub detect: SoftwareDetection,
    /// Reboot policy.
    pub reboot: SoftwareReboot,
    /// Downgrade policy.
    pub downgrade: SoftwareDowngrade,
    /// Existing-installation ownership policy.
    pub ownership: SoftwareOwnership,
    /// At most 32 exact dependencies; canonicalized by resource/version.
    pub dependencies: Vec<SoftwareDependency>,
    /// Present exactly for Bundle format.
    pub bundle: Option<BundleManifest>,
}
/// Validated definition, privately owned and immutable after construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SoftwareSpec", into = "SoftwareSpec")]
pub struct SoftwareDefinition {
    spec: Box<SoftwareSpec>,
    primary: Artifact,
}
impl From<SoftwareDefinition> for SoftwareSpec {
    fn from(value: SoftwareDefinition) -> Self {
        *value.spec
    }
}
impl TryFrom<SoftwareSpec> for SoftwareDefinition {
    type Error = Error;
    fn try_from(spec: SoftwareSpec) -> Result<Self, Error> {
        Self::new(spec)
    }
}
fn text(s: &str, limit: usize) -> Result<(), Error> {
    if s.is_empty() || s.len() > limit || s.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
/// Validate a portable ZIP member name; no absolute, traversal, device or ambiguous names.
pub fn bundle_path(path: &str) -> Result<(), Error> {
    text(path, 1024).map_err(|_| invalid(Validation::Bundle))?;
    if !path.is_ascii()
        || path.contains(['\\', ':', '<', '>', '"', '|', '?', '*'])
        || path.split('/').any(|p| {
            p.is_empty() || p == "." || p == ".." || p.ends_with([' ', '.']) || {
                let base = p.split('.').next().unwrap_or("").to_ascii_uppercase();
                matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || (base.len() == 4
                        && (base.starts_with("COM") || base.starts_with("LPT"))
                        && matches!(base.as_bytes()[3], b'1'..=b'9'))
            }
        })
    {
        return Err(invalid(Validation::Bundle));
    }
    Ok(())
}
impl SoftwareDefinition {
    /// Validate a complete definition without fetching bytes or granting authority.
    pub fn new(mut spec: SoftwareSpec) -> Result<Self, Error> {
        Id::new(&spec.source.id).map_err(|_| invalid(Validation::Source))?;
        Id::new(&spec.source.revision).map_err(|_| invalid(Validation::Source))?;
        text(&spec.package, 1024).map_err(|_| invalid(Validation::Identity))?;
        text(&spec.version, 1024).map_err(|_| invalid(Validation::Identity))?;
        if spec.artifacts.is_empty() {
            return Err(invalid(Validation::Artifact));
        }
        if spec.artifacts.len() > 64 || spec.dependencies.len() > 32 {
            return Err(invalid(Validation::Budget));
        }
        let mut references = BTreeSet::new();
        for (key, a) in &spec.artifacts {
            Id::new(key).map_err(|_| invalid(Validation::Artifact))?;
            a.artifact()?;
            if let Some(origin) = &a.origin {
                text(origin, 2048).map_err(|_| invalid(Validation::Artifact))?;
                if !origin.starts_with("https://") || origin.contains(['?', '#', '@']) {
                    return Err(invalid(Validation::Artifact));
                }
            }
            if !references.insert(&a.reference) {
                return Err(invalid(Validation::Artifact));
            }
        }
        let primary = spec
            .artifacts
            .get(&spec.primary)
            .ok_or(invalid(Validation::Artifact))?
            .artifact()?;
        spec.dependencies
            .sort_by(|a, b| (&a.resource, &a.version).cmp(&(&b.resource, &b.version)));
        let mut deps = BTreeSet::new();
        for dep in &spec.dependencies {
            Id::new(&dep.resource).map_err(|_| invalid(Validation::Dependency))?;
            Id::new(&dep.version).map_err(|_| invalid(Validation::Dependency))?;
            if !deps.insert(&dep.resource) {
                return Err(invalid(Validation::Dependency));
            }
        }
        if (spec.format == SoftwareFormat::Bundle) != spec.bundle.is_some() {
            return Err(invalid(Validation::Bundle));
        }
        if let Some(bundle) = &spec.bundle {
            if bundle.schema != 1
                || bundle.entries.is_empty()
                || bundle.entries.len() > 4096
                || spec.artifacts.len() != 1
            {
                return Err(invalid(Validation::Bundle));
            }
            let mut names = BTreeSet::new();
            for name in bundle.entries.keys() {
                bundle_path(name)?;
                if name.eq_ignore_ascii_case("manifest.json")
                    || !names.insert(name.to_ascii_lowercase())
                {
                    return Err(invalid(Validation::Bundle));
                }
            }
            let ext = if bundle.platform == Platform::Windows {
                "ps1"
            } else {
                "sh"
            };
            if spec.install.entry.as_deref() != Some(format!("install.{ext}").as_str()) {
                return Err(invalid(Validation::Bundle));
            }
            if spec
                .uninstall
                .as_ref()
                .is_some_and(|c| c.entry.as_deref() != Some(format!("uninstall.{ext}").as_str()))
            {
                return Err(invalid(Validation::Bundle));
            }
        }
        Self::command(&spec, &spec.install)?;
        if let Some(c) = &spec.uninstall {
            Self::command(&spec, c)?;
        }
        match &spec.detect {
            SoftwareDetection::MsiProduct {
                product_code,
                version,
            } => {
                let bytes = product_code.as_bytes();
                if bytes.len() != 38
                    || bytes[0] != b'{'
                    || bytes[37] != b'}'
                    || !bytes[1..37].iter().enumerate().all(|(i, c)| {
                        if [8, 13, 18, 23].contains(&i) {
                            *c == b'-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    })
                {
                    return Err(invalid(Validation::Detection));
                }
                text(version, 1024).map_err(|_| invalid(Validation::Detection))?;
            }
            SoftwareDetection::PkgReceipt { receipt, version } => {
                text(receipt, 255).map_err(|_| invalid(Validation::Detection))?;
                text(version, 1024).map_err(|_| invalid(Validation::Detection))?;
                if !receipt
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err(invalid(Validation::Detection));
                }
            }
            SoftwareDetection::Script { command } => {
                Self::command(&spec, command).map_err(|_| invalid(Validation::Detection))?;
                if !is_script(command.executor) {
                    return Err(invalid(Validation::Detection));
                }
            }
        }
        let expected = match spec.format {
            SoftwareFormat::Msi => Some(SoftwareExecutor::Msi),
            SoftwareFormat::Pkg => Some(SoftwareExecutor::PackageInstaller),
            SoftwareFormat::Winget => Some(SoftwareExecutor::Winget),
            SoftwareFormat::Brew => Some(SoftwareExecutor::Brew),
            SoftwareFormat::Bundle => None,
        };
        if expected.is_some_and(|e| spec.install.executor != e)
            || (expected.is_none() && !is_script(spec.install.executor))
        {
            return Err(invalid(Validation::Command));
        }
        if serde_json::to_vec(&spec)
            .map_err(|_| invalid(Validation::Budget))?
            .len()
            > 1_048_576
        {
            return Err(invalid(Validation::Budget));
        }
        Ok(Self {
            spec: Box::new(spec),
            primary,
        })
    }
    fn command(spec: &SoftwareSpec, c: &SoftwareCommand) -> Result<(), Error> {
        if !(1..=86400).contains(&c.timeout_seconds)
            || !(1..=1_048_576).contains(&c.output_bytes)
            || c.arguments.len() > 128
            || c.environment.len() > 32
        {
            return Err(invalid(Validation::Command));
        }
        for arg in &c.arguments {
            if arg.len() > 4096 || arg.contains('\0') {
                return Err(invalid(Validation::Command));
            }
        }
        for (key, value) in &c.environment {
            if !key.starts_with("RSS_PARAM_")
                || key.len() > 128
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || value.len() > 4096
                || value.contains('\0')
            {
                return Err(invalid(Validation::Command));
            }
        }
        if is_script(c.executor) {
            let entry = c.entry.as_ref().ok_or(invalid(Validation::Command))?;
            if let Some(bundle) = &spec.bundle {
                bundle_path(entry).map_err(|_| invalid(Validation::Command))?;
                if !bundle.entries.contains_key(entry) {
                    return Err(invalid(Validation::Command));
                }
            } else if !spec.artifacts.contains_key(entry) {
                return Err(invalid(Validation::Command));
            }
        } else if c.entry.is_some() {
            return Err(invalid(Validation::Command));
        }
        if c.executor == SoftwareExecutor::Brew && c.run_as != RunAs::LoggedInUser {
            return Err(invalid(Validation::Command));
        }
        Ok(())
    }
    /// Borrow the complete frozen data.
    pub fn spec(&self) -> &SoftwareSpec {
        &self.spec
    }
    /// Primary immutable installer coordinates.
    pub fn primary(&self) -> &Artifact {
        &self.primary
    }
    /// Canonical definition bytes, sorted keys and dependencies, without ambient defaults.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&self.spec).expect("validated software")
    }
    /// Check exact platform and architecture against executors, detection and manifest.
    pub fn validate_target(
        &self,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<(), Error> {
        let valid = |e| {
            matches!(
                (platform, e),
                (
                    Platform::Windows,
                    SoftwareExecutor::Msi
                        | SoftwareExecutor::Winget
                        | SoftwareExecutor::PowerShell7
                ) | (
                    Platform::MacOS,
                    SoftwareExecutor::PackageInstaller
                        | SoftwareExecutor::Brew
                        | SoftwareExecutor::PosixSh
                        | SoftwareExecutor::Bash
                )
            )
        };
        if !valid(self.spec.install.executor)
            || self
                .spec
                .uninstall
                .as_ref()
                .is_some_and(|c| !valid(c.executor))
        {
            return Err(invalid(Validation::Target));
        }
        match &self.spec.detect {
            SoftwareDetection::MsiProduct { .. } if platform != Platform::Windows => {
                return Err(invalid(Validation::Target));
            }
            SoftwareDetection::PkgReceipt { .. } if platform != Platform::MacOS => {
                return Err(invalid(Validation::Target));
            }
            SoftwareDetection::Script { command } if !valid(command.executor) => {
                return Err(invalid(Validation::Target));
            }
            _ => (),
        }
        if self
            .spec
            .bundle
            .as_ref()
            .is_some_and(|b| b.platform != platform || b.architecture != architecture)
        {
            return Err(invalid(Validation::Target));
        }
        Ok(())
    }
}
fn is_script(e: SoftwareExecutor) -> bool {
    matches!(
        e,
        SoftwareExecutor::PowerShell7 | SoftwareExecutor::PosixSh | SoftwareExecutor::Bash
    )
}
