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
    pub definition: NativeCollectionDefinition,
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
            Id::new("collection.json")?,
            content.len() as u64,
            Digest::of(&content),
        )?;
        Version::new(
            tenant,
            resource,
            Id::new(self.label())?,
            Kind::NativeCollection,
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
                        Declaration::NativeCollection {
                            artifact: artifact.clone(),
                            definition: self.definition.clone(),
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
    let mut out = Vec::new();
    for (platform, name, adapter, os, model) in [
        (
            Platform::Windows,
            "windows",
            NativeAdapter::WindowsCsp,
            "./DevDetail/SwV",
            "./DevInfo/Mod",
        ),
        (
            Platform::MacOS,
            "macos",
            NativeAdapter::AppleDeviceInformation,
            "OSVersion",
            "Model",
        ),
    ] {
        for (category, field, query) in [
            ("identity", "device.os.version", os),
            ("hardware", "device.model", model),
        ] {
            out.push(Blueprint {
                id: format!("{name}.{category}"),
                version: "1".into(),
                category: category.into(),
                platform,
                definition: NativeCollectionDefinition::new(NativeCollectionSpec {
                    scope: crate::TemplateScope::Device,
                    applicability: Default::default(),
                    adapter,
                    mappings: [(
                        field.into(),
                        NativeMapping {
                            query: query.into(),
                            mapping: ValueMapping::identity(""),
                        },
                    )]
                    .into(),
                    timeout_seconds: 300,
                    output_bytes: 1048576,
                })
                .expect("official template"),
            });
        }
    }
    out
}
/// Exact lookup; there is no moving latest pointer.
pub fn get(id: &str, version: &str) -> Option<Blueprint> {
    catalog()
        .into_iter()
        .find(|b| b.id == id && b.version == version)
}
