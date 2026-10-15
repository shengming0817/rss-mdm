//! Immutable collection blueprints. Instantiation creates ordinary editable Resource versions.
//! ref: Microsoft Learn windows/client-management/mdm/devdetail-csp;
//! apple/device-management mdm/commands/information.device.yaml.
use crate::*;
use serde::Serialize;
/// One immutable, platform-specific official starting point.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Blueprint {
    /// Official identity, independent of tenant Resource identities.
    pub id: String,
    /// Exact official revision; published revisions are never overwritten.
    pub version: String,
    /// User-facing inventory category.
    pub category: String,
    /// Native platform.
    pub platform: Platform,
    /// Actual executable template, not an empty coverage placeholder.
    pub definition: Definition,
}
/// Executable content owned by its existing Resource family.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Definition {
    /// Declarative native Agent template.
    AgentCollection {
        /// Validated plan and server-side field mapping.
        template: AgentCollectionDefinition,
    },
    /// Native read-only collection template.
    NativeCollection {
        /// Validated immutable read template.
        template: NativeCollectionDefinition,
    },
    /// Native desired-state configuration artifact.
    Configuration {
        /// Canonical configuration document, validated by the execution owner at publication.
        content: serde_json::Value,
    },
}
impl From<NativeCollectionDefinition> for Definition {
    fn from(template: NativeCollectionDefinition) -> Self {
        Self::NativeCollection { template }
    }
}
impl Definition {
    /// Exact Resource family.
    pub fn kind(&self) -> Kind {
        match self {
            Self::NativeCollection { .. } => Kind::NativeCollection,
            Self::AgentCollection { .. } => Kind::AgentCollection,
            Self::Configuration { .. } => Kind::Configuration,
        }
    }
    /// Stable artifact identity.
    pub fn reference(&self) -> &'static str {
        match self {
            Self::NativeCollection { .. } => "collection.json",
            Self::AgentCollection { .. } => "agent-collection.json",
            Self::Configuration { .. } => "configuration.json",
        }
    }
    /// Exact bytes uploaded by the content owner.
    pub fn canonical(&self) -> Vec<u8> {
        match self {
            Self::NativeCollection { template } => template.canonical(),
            Self::AgentCollection { template } => template.canonical(),
            Self::Configuration { content } => {
                serde_json::to_vec(content).expect("closed blueprint")
            }
        }
    }
}
impl Blueprint {
    /// Create the exact initial tenant version. Subsequent versions use normal Resource APIs.
    pub fn instantiate(
        &self,
        tenant: rss_request_context::TenantId,
        resource: Id,
    ) -> Result<Version, Error> {
        let content = self.definition.canonical();
        let artifact = Artifact::new(
            Id::new(self.definition.reference())?,
            content.len() as u64,
            Digest::of(&content),
        )?;
        Version::new(
            tenant,
            resource,
            Id::new(self.label())?,
            self.definition.kind(),
            [Architecture::X86_64, Architecture::Aarch64]
                .into_iter()
                .map(|architecture| {
                    Variant::new(
                        self.platform,
                        architecture,
                        Id::new(match architecture {
                            Architecture::X86_64 => "x86_64",
                            Architecture::Aarch64 => "aarch64",
                        })
                        .expect("constant"),
                        match &self.definition {
                            Definition::AgentCollection { template } => {
                                Declaration::AgentCollection {
                                    artifact: artifact.clone(),
                                    definition: template.clone(),
                                }
                            }
                            Definition::NativeCollection { template } => {
                                Declaration::NativeCollection {
                                    artifact: artifact.clone(),
                                    definition: template.clone(),
                                }
                            }
                            Definition::Configuration { .. } => Declaration::Configuration {
                                artifact: artifact.clone(),
                            },
                        },
                    )
                })
                .collect(),
        )
    }
    /// Origin remains inspectable in the immutable initial version label and digest.
    pub fn label(&self) -> String {
        format!("builtin.{}.{}", self.id, self.version)
    }
}
/// The six catalog categories; readiness is represented by actual blueprints only.
pub const CATEGORIES: [&str; 6] = [
    "identity",
    "hardware",
    "software",
    "security",
    "management",
    "updates",
];
/// Executable native templates with already implemented protocol adapters.
pub fn catalog() -> Vec<Blueprint> {
    let mut out = apple::catalog();
    out.extend(windows::catalog());
    out.extend(agent_windows::catalog());
    out.extend(apple::status_catalog());
    out
}
/// Exact lookup; there is no moving latest pointer.
pub fn get(id: &str, version: &str) -> Option<Blueprint> {
    catalog()
        .into_iter()
        .find(|b| b.id == id && b.version == version)
}

mod apple;
mod windows;

mod agent_windows;
