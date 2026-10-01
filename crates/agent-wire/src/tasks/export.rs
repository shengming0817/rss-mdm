//! Frozen native package-manager read authority, derived by the publication owner.
use super::*;
use serde::{Deserialize, Serialize};
/// Exact enterprise release ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareExportRing {
    /// Test publication.
    Test,
    /// Pilot publication.
    Pilot,
    /// Production publication.
    Production,
}
/// One exact definition included in the frozen native source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareExportDependency {
    /// Opaque logical Resource identity.
    pub resource: String,
    /// Exact Resource version.
    pub version: String,
    /// Complete frozen Resource definition digest.
    pub sha256: [u8; 32],
}
/// Exact readonly material URL published with the native document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareExportArtifact {
    /// Credential-free immutable material URL.
    pub url: String,
    /// Complete byte count.
    pub length: u64,
    /// Complete content digest.
    pub sha256: [u8; 32],
}
/// Complete publication identity; these are immutable receipt coordinates, not another catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareExportBinding {
    /// Exact logical output source, distinct from imported provenance.
    pub source: String,
    /// Publication tenant from the signed task.
    #[serde(with = "crate::strict_uuid")]
    pub tenant_id: Uuid,
    /// Exact release environment.
    pub ring: SoftwareExportRing,
    /// Immutable publication receipt identity.
    pub publication: [u8; 32],
    /// Complete configured source snapshot identity.
    pub source_digest: [u8; 32],
    /// Root definition coordinate included in this source.
    pub resource: String,
    /// Exact root Resource version.
    pub resource_version: String,
    /// Complete root Resource digest.
    pub resource_digest: [u8; 32],
    /// Release content digest binds full definition, dependencies, documents and material.
    pub definition_digest: [u8; 32],
    /// Exact derived native document digest.
    pub document_sha256: [u8; 32],
    /// Exact transitive definitions included in the native source.
    pub dependencies: Vec<SoftwareExportDependency>,
    /// Complete immutable public material set.
    pub artifacts: Vec<SoftwareExportArtifact>,
}
/// Native consumers always use the frozen source explicitly, with prerequisites already executed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareTaskExport {
    /// Approved installer material is consumed directly by its concrete native behavior.
    Direct,
    /// Public readonly WinGet REST source for exactly this publication and its dependencies.
    Winget {
        /// Complete immutable source identity.
        binding: SoftwareExportBinding,
        /// Frozen REST base URL.
        uri: String,
        /// Exact identifier returned by the source's information endpoint.
        identifier: String,
    },
    /// Immutable bottle-only Tap; the consumer cannot update it or fall back to source builds.
    Brew {
        /// Complete immutable source identity.
        binding: SoftwareExportBinding,
        /// Fixed readonly upload-pack URL.
        uri: String,
        /// Exact parentless Tap commit.
        commit: String,
        /// Source-scoped frozen tap namespace.
        tap: String,
        /// Opaque locally provisioned readonly credential reference.
        credential_reference: String,
    },
}
fn text(value: &str, max: usize) -> Result<(), WireError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
fn https(value: &str) -> Result<(), WireError> {
    text(value, 2048)?;
    let u = url::Url::parse(value).map_err(|_| WireError::InvalidValue)?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
impl SoftwareTaskExport {
    /// Validate the exact source and all retained material against this signed local step.
    pub fn validate_for(
        &self,
        step: &SoftwareTaskStep,
        tenant: Uuid,
        context: &SoftwareExecutionContext,
    ) -> Result<(), WireError> {
        use SoftwareTaskBehavior as B;
        let (binding, uri) = match (self, &step.action.behavior) {
            (Self::Direct, B::Winget(_) | B::Brew(_)) => return Err(WireError::InvalidValue),
            (Self::Direct, _) => return Ok(()),
            (
                Self::Winget {
                    binding,
                    uri,
                    identifier,
                },
                B::Winget(_),
            ) => {
                text(identifier, 128)?;
                if !uri.ends_with('/') {
                    return Err(WireError::InvalidValue);
                }
                (binding, uri)
            }
            (
                Self::Brew {
                    binding,
                    uri,
                    commit,
                    tap,
                    credential_reference,
                },
                B::Brew(_),
            ) => {
                if commit.len() != 40
                    || !commit
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !uri.ends_with(".git")
                {
                    return Err(WireError::InvalidValue);
                }
                text(tap, 128)?;
                text(credential_reference, 128)?;
                if !context
                    .source_credentials
                    .iter()
                    .any(|c| c.source == binding.source && c.reference == *credential_reference)
                {
                    return Err(WireError::InvalidValue);
                }
                (binding, uri)
            }
            _ => return Err(WireError::InvalidValue),
        };
        https(uri)?;
        text(&binding.source, 128)?;
        text(&binding.resource, 128)?;
        text(&binding.resource_version, 128)?;
        if binding.tenant_id != tenant
            || binding.dependencies.len() > 255
            || binding.artifacts.is_empty()
            || binding.artifacts.len() > 256
            || [
                binding.publication,
                binding.source_digest,
                binding.resource_digest,
                binding.definition_digest,
                binding.document_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(WireError::InvalidValue);
        }
        let mut coordinates = std::collections::BTreeSet::new();
        for dep in &binding.dependencies {
            text(&dep.resource, 128)?;
            text(&dep.version, 128)?;
            if dep.sha256 == [0; 32] || !coordinates.insert((&dep.resource, &dep.version)) {
                return Err(WireError::InvalidValue);
            }
        }
        let mut urls = std::collections::BTreeSet::new();
        for artifact in &binding.artifacts {
            https(&artifact.url)?;
            if artifact.length == 0
                || artifact.length > 1_099_511_627_776
                || artifact.sha256 == [0; 32]
                || !urls.insert(&artifact.url)
            {
                return Err(WireError::InvalidValue);
            }
        }
        if step.artifacts.iter().any(|a| {
            !binding
                .artifacts
                .iter()
                .any(|export| export.length == a.length && export.sha256 == a.sha256)
        }) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
