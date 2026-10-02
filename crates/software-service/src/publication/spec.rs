//! Product mappings own Resource ↔ platform ↔ release correspondence.
use super::{
    Error, Result,
    config::{ExportProtocol, ExportSources},
};
use rss_mdm_brew_source as brew;
use rss_mdm_resource as resource;
use rss_mdm_software_release as rel;
use rss_mdm_winget_source as winget;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicArtifact {
    pub key: String,
    pub url: String,
    pub length: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrewArtifact {
    pub architecture: String,
    pub artifact: PublicArtifact,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BottleInput {
    pub cellar: String,
    pub tag: String,
    pub root_url: String,
    pub artifact: PublicArtifact,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrewDependency {
    pub recipe: Box<BrewRecipe>,
    pub tap: String,
    pub name: String,
    pub snapshot: [u8; 32],
    pub artifacts: Vec<PublicArtifact>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CaskInstall {
    App { path: String },
    Pkg { path: String, receipts: Vec<String> },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum BrewPayload {
    Cask {
        artifacts: Vec<BrewArtifact>,
        install: CaskInstall,
    },
    Formula {
        revision: u32,
        rebuild: u32,
        source: PublicArtifact,
        executable: String,
        bottles: Vec<BottleInput>,
        dependencies: Vec<BrewDependency>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrewRecipe {
    pub package: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub homepage: String,
    pub payload: BrewPayload,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ExportDocument {
    Winget { manifest: serde_json::Value },
    Brew { recipe: Box<BrewRecipe> },
}
pub(super) struct PreparedContent {
    pub resources: Vec<resource::Version>,
    pub content: rel::Content,
    pub artifacts: Vec<PublicArtifact>,
    pub coordinate: String,
    pub document: ExportDocument,
}
fn architecture(a: resource::Architecture) -> &'static str {
    match a {
        resource::Architecture::X86_64 => "x86_64",
        resource::Architecture::Aarch64 => "aarch64",
    }
}
pub(super) fn prepare(
    sources: &ExportSources,
    version: &resource::Version,
    dependencies: &[resource::Version],
) -> Result<PreparedContent> {
    if version.tenant() != sources.tenant || version.kind() != resource::Kind::Software {
        return Err(Error::Content);
    }
    let artifact_base = &sources.artifacts_base;
    let document = super::derive_document(version, dependencies, artifact_base)?;
    let exported = super::derive::exported_materials(version, dependencies, artifact_base)?;
    let (platform, package, package_version, manifest, coordinate) = match &document {
        ExportDocument::Winget { manifest } => {
            if !matches!(sources.bindings[0].protocol, ExportProtocol::Winget { .. }) {
                return Err(Error::Unsupported);
            }
            let m = winget::VersionManifest::parse(
                sources.tenant,
                &sources.logical,
                &serde_json::to_vec(manifest).map_err(|_| Error::Content)?,
            )
            .map_err(|cause| Error::Content.context("spec::prepare", cause))?;
            (
                resource::Platform::Windows,
                m.package().to_owned(),
                m.version().to_owned(),
                rel::Digest::of(m.bytes()),
                format!("{}/{}", m.package(), m.version()),
            )
        }
        ExportDocument::Brew { recipe } => {
            let ExportProtocol::Brew { tap, .. } = &sources.bindings[0].protocol else {
                return Err(Error::Unsupported);
            };
            let rendered = recipe.render(sources.tenant, tap)?;
            for binding in &sources.bindings {
                let ExportProtocol::Brew { tap, .. } = &binding.protocol else {
                    return Err(Error::Unsupported);
                };
                if recipe.render(sources.tenant, tap)?.bytes() != rendered.bytes() {
                    return Err(Error::Content);
                }
            }
            (
                resource::Platform::MacOS,
                recipe.package.clone(),
                recipe.version.clone(),
                rel::Digest::of(rendered.bytes()),
                format!("{}/{}", rendered.path(), recipe.version),
            )
        }
    };
    let mut unique = BTreeMap::new();
    let mut variants = Vec::new();
    for variant in version.variants() {
        if variant.platform() != platform {
            return Err(Error::Unsupported);
        }
        let mut files = Vec::new();
        for selected in std::iter::once(version).chain(dependencies.iter()) {
            for v in selected
                .variants()
                .iter()
                .filter(|v| v.platform() == platform && v.architecture() == variant.architecture())
            {
                let resource::Declaration::Software { definition } = v.declaration() else {
                    return Err(Error::Content);
                };
                for a in definition.spec().artifacts.values() {
                    let key = format!("content.{}", super::hex(&a.sha256));
                    let file = exported
                        .iter()
                        .find(|file| file.sha256 == a.sha256 && file.length == a.length)
                        .ok_or(Error::Content)?
                        .clone();
                    super::artifact::checked_url(&file.url)?;
                    if unique
                        .insert(key.clone(), file.clone())
                        .is_some_and(|old| old.length != file.length || old.sha256 != file.sha256)
                    {
                        return Err(Error::Content);
                    }
                    files.push(release_artifact(&file)?);
                }
            }
        }
        files.sort_by(|a, b| a.key().cmp(b.key()));
        files.dedup();
        variants.push(
            rel::VariantContent::new(
                architecture(variant.architecture()),
                variant.key().as_str(),
                files,
            )
            .map_err(|cause| Error::Content.context("spec::prepare", cause))?,
        );
    }
    let description = rel::Digest::of(
        &serde_json::to_vec(&serde_json::json!([
            version.digest().bytes(),
            dependencies
                .iter()
                .map(|v| v.digest().bytes())
                .collect::<Vec<_>>(),
            document
        ]))
        .map_err(|_| Error::Content)?,
    );
    let content = rel::Content::new(
        rel::SoftwareIdentity::new(rel::SoftwareIdentityFields {
            source: sources.logical.clone(),
            package,
            version: package_version,
            platform: if platform == resource::Platform::Windows {
                "windows"
            } else {
                "macos"
            }
            .into(),
        })
        .map_err(|_| Error::Content)?,
        description,
        rel::Digest::from_bytes(sources.digest),
        manifest,
        variants,
    )
    .map_err(|_| Error::Content)?;
    Ok(PreparedContent {
        resources: std::iter::once(version.clone())
            .chain(dependencies.iter().cloned())
            .collect(),
        content,
        artifacts: unique.into_values().collect(),
        coordinate,
        document,
    })
}
fn release_artifact(a: &PublicArtifact) -> Result<rel::Artifact> {
    rel::Artifact::new(&a.key, rel::Digest::from_bytes(a.sha256))
        .map_err(|cause| Error::Content.context("spec::release_artifact", cause))
}
impl BrewRecipe {
    pub(super) fn documents(
        &self,
        tenant: rss_request_context::TenantId,
        tap: &str,
    ) -> Result<Vec<brew::Document>> {
        let mut pending = vec![(self, 0usize)];
        let mut documents = BTreeMap::new();
        while let Some((recipe, depth)) = pending.pop() {
            if depth > 32 || documents.len() >= 256 {
                return Err(Error::Content);
            }
            let document = recipe.render(tenant, tap)?;
            if documents
                .get(document.path())
                .is_some_and(|old: &brew::Document| old.bytes() != document.bytes())
            {
                return Err(Error::Content);
            }
            let fresh = !documents.contains_key(document.path());
            documents.insert(document.path().to_owned(), document);
            if fresh && let BrewPayload::Formula { dependencies, .. } = &recipe.payload {
                pending.extend(dependencies.iter().map(|d| (d.recipe.as_ref(), depth + 1)));
            }
        }
        Ok(documents.into_values().collect())
    }
    pub(super) fn render(
        &self,
        tenant: rss_request_context::TenantId,
        tap: &str,
    ) -> Result<brew::Document> {
        let key = brew::PackageKey::new(tenant, tap, &self.package)
            .map_err(|cause| Error::Content.context("spec::render", cause))?;
        let document = match &self.payload {
            BrewPayload::Cask { artifacts, install } => {
                let files = artifacts
                    .iter()
                    .map(|a| {
                        Ok((
                            brew_architecture(&a.architecture)?,
                            brew::Artifact::new(&a.artifact.url, a.artifact.sha256)
                                .map_err(|cause| Error::Content.context("spec::render", cause))?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let install = match install {
                    CaskInstall::App { path } => brew::CaskArtifact::App(path.clone()),
                    CaskInstall::Pkg { path, receipts } => brew::CaskArtifact::Pkg {
                        path: path.clone(),
                        receipts: receipts.clone(),
                    },
                };
                brew::Cask::new(
                    key,
                    &self.version,
                    &self.name,
                    &self.description,
                    &self.homepage,
                    files,
                    install,
                )
                .map_err(|cause| Error::Content.context("spec::render", cause))?
                .render()
            }
            BrewPayload::Formula {
                revision,
                rebuild,
                source,
                executable,
                bottles,
                dependencies,
            } => {
                let bottles = bottles
                    .iter()
                    .map(|b| {
                        let (tag, _) = bottle_tag(&b.tag)?;
                        let root = super::artifact::checked_url(&b.root_url)?;
                        let filename = format!(
                            "{}-{}{}.{}.bottle{}.tar.gz",
                            self.package,
                            self.version,
                            if *revision == 0 {
                                String::new()
                            } else {
                                format!("_{revision}")
                            },
                            b.tag,
                            if *rebuild == 0 {
                                String::new()
                            } else {
                                format!(".{rebuild}")
                            }
                        );
                        let encoded: String =
                            url::form_urlencoded::byte_serialize(filename.as_bytes()).collect();
                        let expected =
                            format!("{}/{}", root.as_str().trim_end_matches('/'), encoded);
                        if expected != b.artifact.url {
                            return Err(Error::Content);
                        }
                        brew::Bottle::new(
                            tag,
                            &b.root_url,
                            b.artifact.sha256,
                            match b.cellar.as_str() {
                                "any" => brew::Cellar::Any,
                                "any_skip_relocation" => brew::Cellar::AnySkipRelocation,
                                _ => return Err(Error::Unsupported),
                            },
                        )
                        .map_err(|cause| Error::Content.context("spec::render", cause))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let deps = dependencies
                    .iter()
                    .map(|d| {
                        brew::PackageKey::new(tenant, &d.tap, &d.name)
                            .map_err(|cause| Error::Content.context("spec::render", cause))
                    })
                    .collect::<Result<Vec<_>>>()?;
                brew::Formula::new(
                    key,
                    &self.version,
                    brew::BottleLayout {
                        revision: *revision,
                        rebuild: *rebuild,
                    },
                    &self.description,
                    &self.homepage,
                    brew::Artifact::new(&source.url, source.sha256)
                        .map_err(|cause| Error::Content.context("spec::render", cause))?,
                    executable,
                    bottles,
                    deps,
                )
                .map_err(|cause| Error::Content.context("spec::render", cause))?
                .render()
            }
        };
        document.map_err(|cause| Error::Content.context("spec::render", cause))
    }
}

fn brew_architecture(a: &str) -> Result<brew::Architecture> {
    match a {
        "aarch64" => Ok(brew::Architecture::Arm64),
        "x86_64" => Ok(brew::Architecture::Intel),
        _ => Err(Error::Content),
    }
}
fn bottle_tag(tag: &str) -> Result<(brew::BottleTag, &'static str)> {
    match tag {
        "arm64_sonoma" => Ok((brew::BottleTag::Arm64Sonoma, "aarch64")),
        "sonoma" => Ok((brew::BottleTag::Sonoma, "x86_64")),
        _ => Err(Error::Content),
    }
}
