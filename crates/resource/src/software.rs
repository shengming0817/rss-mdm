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
mod behavior;
mod validation;
pub use behavior::*;

/// Single current definition; behavior owns format-specific installer semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSpec {
    /// Exact approved source revision.
    pub source: SoftwareSource,
    /// Exact ecosystem package identity.
    pub package: String,
    /// Exact ecosystem version, never a range.
    pub version: String,
    /// Raw source materials and converter identity, without a second resource owner.
    pub provenance: SoftwareProvenance,
    /// Complete immutable runtime artifact closure.
    pub artifacts: BTreeMap<String, SoftwareArtifact>,
    /// Only source of format, installer and payload semantics.
    pub behavior: SoftwareBehavior,
    /// Explicit requirements; an empty list permits unsigned content.
    pub signatures: Vec<SoftwareSignature>,
    /// Independently authorized reboot handling.
    pub reboot: SoftwareReboot,
    /// Explicit downgrade permission.
    pub downgrade: SoftwareDowngrade,
    /// Existing installation ownership boundary.
    pub ownership: SoftwareOwnership,
    /// Exact tenant-local resource prerequisites.
    pub dependencies: Vec<SoftwareDependency>,
    /// Immutable publication metadata; absence of native export is explicit.
    pub export: SoftwareExport,
}
/// Validated immutable software. Construction does not grant authority or prove execution.
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
    /// Validate all references, behaviors and material budgets without I/O.
    pub fn new(mut spec: SoftwareSpec) -> Result<Self, Error> {
        validation::validate(&mut spec)?;
        let primary = spec
            .artifacts
            .get(spec.behavior.installer())
            .ok_or(invalid(Validation::Artifact))?
            .artifact()?;
        Ok(Self {
            spec: Box::new(spec),
            primary,
        })
    }
    /// Complete canonical current material.
    pub fn spec(&self) -> &SoftwareSpec {
        &self.spec
    }
    /// Immutable primary installer coordinates.
    pub fn primary(&self) -> &Artifact {
        &self.primary
    }
    /// Runtime bytes and original source evidence share one immutable content owner.
    pub fn materials(&self) -> impl Iterator<Item = &SoftwareArtifact> {
        let files: &[SoftwareSourceFile] = match &self.spec.provenance {
            SoftwareProvenance::Private => &[],
            SoftwareProvenance::Imported { files, .. } => files,
        };
        self.spec
            .artifacts
            .values()
            .chain(files.iter().map(|file| &file.content))
    }
    /// Canonical bytes. Serialization only contains validated finite value types.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&self.spec).expect("validated software value")
    }
    /// Check the exact selected platform and architecture, including nested payloads.
    pub fn validate_target(
        &self,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<(), Error> {
        validation::target(&self.spec, platform, architecture)
    }
}
