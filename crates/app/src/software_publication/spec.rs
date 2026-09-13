//! Product mappings own Resource ↔ platform ↔ release correspondence.
use super::{
    Error, Result,
    config::{Driver, Sources},
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
    pub tag: String,
    pub root_url: String,
    pub artifact: PublicArtifact,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrewDependency {
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
pub enum Submission {
    Winget { manifest: serde_json::Value },
    Brew { recipe: Box<BrewRecipe> },
}
pub(super) struct PreparedContent {
    pub content: rel::Content,
    pub artifacts: Vec<PublicArtifact>,
    pub coordinate: String,
    pub submission: Submission,
}
/// Resource keys retain type, scope and optional installer identity without ambiguity.
pub fn winget_variant(q: &winget::Query) -> String {
    format!(
        "{}.{}.{}",
        q.installer_type().as_str(),
        q.scope().as_str(),
        q.installer_id()
            .map_or_else(|| "no-id".into(), |id| format!("id-{id}"))
    )
}
fn architecture(a: resource::Architecture) -> &'static str {
    match a {
        resource::Architecture::X86_64 => "x86_64",
        resource::Architecture::Aarch64 => "aarch64",
    }
}
fn primary<'a>(
    version: &'a resource::Version,
    platform: resource::Platform,
    arch: &str,
    variant: &str,
    source: &str,
    package: &str,
    package_version: &str,
) -> Result<&'a resource::Artifact> {
    let v = version
        .variants()
        .iter()
        .find(|v| {
            v.platform() == platform
                && architecture(v.architecture()) == arch
                && v.key().as_str() == variant
        })
        .ok_or(Error::Content)?;
    let resource::Declaration::Software {
        package: p,
        artifact,
        ..
    } = v.declaration()
    else {
        return Err(Error::Content);
    };
    if p.source().as_str() != source
        || p.package().as_str() != package
        || p.version().as_str() != package_version
    {
        return Err(Error::Content);
    }
    Ok(artifact)
}
fn matches_primary(primary: &resource::Artifact, artifact: &PublicArtifact) -> Result<()> {
    if primary.reference().as_str() != artifact.key
        || primary.length() != artifact.length
        || primary.digest().bytes() != artifact.sha256
    {
        return Err(Error::Content);
    }
    Ok(())
}
pub(super) fn prepare(
    sources: &Sources,
    version: &resource::Version,
    submission: &Submission,
) -> Result<PreparedContent> {
    if version.tenant() != sources.tenant || version.kind() != resource::Kind::Software {
        return Err(Error::Content);
    }
    let (platform, package, package_version, manifest, variants, artifacts, coordinate, submission) =
        match submission {
            Submission::Winget { manifest } => {
                if !matches!(sources.bindings[0].driver, Driver::Winget { .. }) {
                    return Err(Error::Content);
                }
                let m = winget::VersionManifest::parse(
                    sources.tenant,
                    &sources.logical,
                    &serde_json::to_vec(manifest).map_err(|_| Error::Input)?,
                )
                .map_err(|_| Error::Content)?;
                let mut variants = Vec::new();
                let mut artifacts = Vec::new();
                for item in m.installers() {
                    let q = item.query();
                    let arch = match q.architecture() {
                        winget::Architecture::X64 => "x86_64",
                        winget::Architecture::Arm64 => "aarch64",
                    };
                    let key = winget_variant(q);
                    let a = primary(
                        version,
                        resource::Platform::Windows,
                        arch,
                        &key,
                        &sources.logical,
                        m.package(),
                        m.version(),
                    )?;
                    if a.digest().bytes() != item.sha256() {
                        return Err(Error::Content);
                    }
                    let file = PublicArtifact {
                        key: a.reference().as_str().into(),
                        url: item.artifact_url().into(),
                        length: a.length(),
                        sha256: item.sha256(),
                    };
                    variants.push(
                        rel::VariantContent::new(arch, key, vec![release_artifact(&file)?])
                            .map_err(|_| Error::Content)?,
                    );
                    artifacts.push(file);
                }
                let canonical = Submission::Winget {
                    manifest: serde_json::from_slice(m.bytes()).map_err(|_| Error::Content)?,
                };
                (
                    resource::Platform::Windows,
                    m.package().to_owned(),
                    m.version().to_owned(),
                    rel::Digest::of(m.bytes()),
                    variants,
                    artifacts,
                    format!("{}/{}", m.package(), m.version()),
                    canonical,
                )
            }
            Submission::Brew { recipe } => {
                let Driver::Brew { tap, .. } = &sources.bindings[0].driver else {
                    return Err(Error::Content);
                };
                let document = recipe.render(sources.tenant, tap)?;
                // All rings must publish identical bytes; only their dedicated Tap identities differ.
                for binding in &sources.bindings {
                    let Driver::Brew { tap, .. } = &binding.driver else {
                        return Err(Error::Content);
                    };
                    if recipe.render(sources.tenant, tap)?.bytes() != document.bytes() {
                        return Err(Error::Content);
                    }
                }
                let (primaries, extra) = recipe.artifacts()?;
                let mut variants = Vec::new();
                let mut files = extra.clone();
                for (arch, kind, file) in primaries {
                    matches_primary(
                        primary(
                            version,
                            resource::Platform::MacOS,
                            &arch,
                            &kind,
                            &sources.logical,
                            &recipe.package,
                            &recipe.version,
                        )?,
                        &file,
                    )?;
                    let mut artifacts = vec![release_artifact(&file)?];
                    for extra in &extra {
                        artifacts.push(release_artifact(extra)?);
                    }
                    variants.push(
                        rel::VariantContent::new(arch, kind, artifacts)
                            .map_err(|_| Error::Content)?,
                    );
                    files.push(file);
                }
                (
                    resource::Platform::MacOS,
                    recipe.package.clone(),
                    recipe.version.clone(),
                    rel::Digest::of(document.bytes()),
                    variants,
                    files,
                    document.path().into(),
                    submission.clone(),
                )
            }
        };
    if version
        .variants()
        .iter()
        .filter(|v| v.platform() == platform)
        .count()
        != variants.len()
    {
        return Err(Error::Content);
    }
    let mut unique = BTreeMap::new();
    for a in artifacts {
        super::artifact::checked_url(&a.url)?;
        if a.length == 0 {
            return Err(Error::Content);
        }
        if unique
            .insert(a.key.clone(), a.clone())
            .is_some_and(|old| old != a)
        {
            return Err(Error::Content);
        }
    }
    let input = serde_json::to_vec(&submission).map_err(|_| Error::Content)?;
    let description = rel::Digest::of(
        &serde_json::to_vec(&serde_json::json!([version.digest().bytes(), input]))
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
        content,
        artifacts: unique.into_values().collect(),
        coordinate,
        submission,
    })
}
fn release_artifact(a: &PublicArtifact) -> Result<rel::Artifact> {
    rel::Artifact::new(&a.key, rel::Digest::from_bytes(a.sha256)).map_err(|_| Error::Content)
}
type PrimaryArtifact = (String, String, PublicArtifact);
type ArtifactSet = (Vec<PrimaryArtifact>, Vec<PublicArtifact>);
impl BrewRecipe {
    pub(super) fn render(
        &self,
        tenant: rss_request_context::TenantId,
        tap: &str,
    ) -> Result<brew::Document> {
        let key = brew::PackageKey::new(tenant, tap, &self.package).map_err(|_| Error::Content)?;
        let document = match &self.payload {
            BrewPayload::Cask { artifacts, install } => {
                let files = artifacts
                    .iter()
                    .map(|a| {
                        Ok((
                            brew_architecture(&a.architecture)?,
                            brew::Artifact::new(&a.artifact.url, a.artifact.sha256)
                                .map_err(|_| Error::Content)?,
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
                .map_err(|_| Error::Content)?
                .render()
            }
            BrewPayload::Formula {
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
                        let filename =
                            format!("{}-{}.{}.bottle.tar.gz", self.package, self.version, b.tag);
                        let encoded: String =
                            url::form_urlencoded::byte_serialize(filename.as_bytes()).collect();
                        let expected =
                            format!("{}/{}", root.as_str().trim_end_matches('/'), encoded);
                        if expected != b.artifact.url {
                            return Err(Error::Content);
                        }
                        brew::Bottle::new(tag, &b.root_url, b.artifact.sha256)
                            .map_err(|_| Error::Content)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let deps = dependencies
                    .iter()
                    .map(|d| {
                        brew::PackageKey::new(tenant, &d.tap, &d.name).map_err(|_| Error::Content)
                    })
                    .collect::<Result<Vec<_>>>()?;
                brew::Formula::new(
                    key,
                    &self.version,
                    &self.description,
                    &self.homepage,
                    brew::Artifact::new(&source.url, source.sha256).map_err(|_| Error::Content)?,
                    executable,
                    bottles,
                    deps,
                )
                .map_err(|_| Error::Content)?
                .render()
            }
        };
        document.map_err(|_| Error::Content)
    }
    fn artifacts(&self) -> Result<ArtifactSet> {
        match &self.payload {
            BrewPayload::Cask { artifacts, .. } => Ok((
                artifacts
                    .iter()
                    .map(|a| (a.architecture.clone(), "cask".into(), a.artifact.clone()))
                    .collect(),
                vec![],
            )),
            BrewPayload::Formula {
                source,
                bottles,
                dependencies,
                ..
            } => {
                let mut extra = vec![source.clone()];
                for d in dependencies {
                    if d.artifacts.is_empty() || d.snapshot == [0; 32] {
                        return Err(Error::Content);
                    }
                    extra.extend(d.artifacts.clone());
                }
                let primary = bottles
                    .iter()
                    .map(|b| {
                        let (_, arch) = bottle_tag(&b.tag)?;
                        Ok((arch.into(), "bottle".into(), b.artifact.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((primary, extra))
            }
        }
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
