//! Selected source conversion into the sole Resource-owned software definition.
//! Host source reads and content staging precede the borrowed admission transaction.
pub mod fetch;
use crate::catalog::{Error, Result, SourceDefinition, SourceProtocol};
use rss_mdm_resource as r;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Only selected coordinates and explicit enterprise behavior, never a submitted final Recipe.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportRequest {
    pub as_of_unix_seconds: i64,
    pub source: r::SoftwareSource,
    pub resource: String,
    pub resource_version: String,
    pub package: String,
    pub package_version: String,
    pub platform: r::Platform,
    pub architecture: r::Architecture,
    pub variant: String,
    pub selection: ImportSelection,
    pub behavior: r::SoftwareBehavior,
    pub installer_length: u64,
    pub additional_artifacts: BTreeMap<String, r::SoftwareArtifact>,
    pub dependencies: Vec<ImportDependency>,
    pub signatures: Vec<r::SoftwareSignature>,
    pub reboot: r::SoftwareReboot,
    pub downgrade: r::SoftwareDowngrade,
    pub ownership: r::SoftwareOwnership,
    pub native_export: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportDependency {
    pub package: String,
    pub package_version: String,
    pub resource: String,
    pub version: String,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ImportSelection {
    Winget {
        installer_type: String,
        scope: String,
        installer_id: Option<String>,
        files: Vec<String>,
    },
    Brew {
        path: String,
        bottle_tag: String,
        source_length: Option<u64>,
    },
}
/// Exact fetched original byte set; fetching authority is supplied by the host, not this parser.
pub type SourceDocuments = BTreeMap<String, Vec<u8>>;
pub struct PreparedImport {
    pub version: r::Version,
    pub originals: Vec<(r::SoftwareArtifact, Vec<u8>)>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn content(path: &str, bytes: &[u8]) -> r::SoftwareSourceFile {
    let sha = r::Digest::of(bytes).bytes();
    r::SoftwareSourceFile {
        path: path.into(),
        content: r::SoftwareArtifact {
            reference: format!("source.{}", hex(&sha)),
            origin: None,
            length: bytes.len() as u64,
            sha256: sha,
        },
    }
}
pub fn prepare(
    tenant: TenantId,
    source: &SourceDefinition,
    input: &ImportRequest,
    documents: &SourceDocuments,
) -> Result<PreparedImport> {
    if source.snapshot()? != input.source
        || input.installer_length == 0
        || input.dependencies.len() > 32
    {
        return Err(Error::Input);
    }
    validate_documents(input, documents)?;
    let (artifact, export, snapshot, converter) = match &source.protocol {
        SourceProtocol::WingetRest { .. } | SourceProtocol::WingetCommunity { .. } => {
            winget(tenant, source, input, documents)?
        }
        SourceProtocol::BrewTap { commit, .. } => {
            let (artifact, export) = brew(tenant, source, input, documents)?;
            (artifact, export, commit.clone(), "rss-brew-static/1")
        }
        SourceProtocol::Private => return Err(Error::Unsupported),
    };
    let mut artifacts = input.additional_artifacts.clone();
    if artifacts
        .insert(input.behavior.installer().to_owned(), artifact)
        .is_some()
    {
        return Err(Error::Input);
    }
    let mut originals = Vec::new();
    let mut files = Vec::new();
    for (path, bytes) in documents {
        let file = content(path, bytes);
        originals.push((file.content.clone(), bytes.clone()));
        files.push(file);
    }
    let definition = r::SoftwareDefinition::new(r::SoftwareSpec {
        source: source.snapshot()?,
        package: input.package.clone(),
        version: input.package_version.clone(),
        provenance: r::SoftwareProvenance::Imported {
            snapshot,
            converter: converter.into(),
            files,
        },
        artifacts,
        behavior: input.behavior.clone(),
        signatures: input.signatures.clone(),
        reboot: input.reboot,
        downgrade: input.downgrade,
        ownership: input.ownership,
        dependencies: input
            .dependencies
            .iter()
            .map(|d| r::SoftwareDependency {
                resource: d.resource.clone(),
                version: d.version.clone(),
                sha256: d.sha256,
            })
            .collect(),
        export,
    })
    .map_err(|_| Error::Input)?;
    let version = r::Version::new(
        tenant,
        r::Id::new(&input.resource).map_err(|_| Error::Input)?,
        r::Id::new(&input.resource_version).map_err(|_| Error::Input)?,
        r::Kind::Software,
        vec![r::Variant::new(
            input.platform,
            input.architecture,
            r::Id::new(&input.variant).map_err(|_| Error::Input)?,
            r::Declaration::Software { definition },
        )],
    )
    .map_err(|_| Error::Input)?;
    Ok(PreparedImport { version, originals })
}
fn query(
    tenant: TenantId,
    source: &SourceDefinition,
    input: &ImportRequest,
) -> Result<rss_mdm_winget_source::Query> {
    use rss_mdm_winget_source as w;
    let ImportSelection::Winget {
        installer_type,
        scope,
        installer_id,
        ..
    } = &input.selection
    else {
        return Err(Error::Input);
    };
    let kind = match installer_type.as_str() {
        "msi" => w::InstallerType::Msi,
        "exe" => w::InstallerType::Exe,
        _ => return Err(Error::Unsupported),
    };
    let arch = match input.architecture {
        r::Architecture::X86_64 => w::Architecture::X64,
        r::Architecture::Aarch64 => w::Architecture::Arm64,
    };
    let scope = match scope.as_str() {
        "machine" => w::Scope::Machine,
        "user" => w::Scope::User,
        "unspecified" => w::Scope::Unspecified,
        _ => return Err(Error::Unsupported),
    };
    let mut q = w::Query::new(
        tenant,
        &source.id,
        &input.package,
        &input.package_version,
        arch,
        kind,
        scope,
    )
    .map_err(|_| Error::Input)?;
    if let Some(id) = installer_id {
        q = q.with_installer_id(id).map_err(|_| Error::Input)?;
    }
    Ok(q)
}
fn winget(
    tenant: TenantId,
    source: &SourceDefinition,
    input: &ImportRequest,
    documents: &SourceDocuments,
) -> Result<(r::SoftwareArtifact, r::SoftwareExport, String, &'static str)> {
    let q = query(tenant, source, input)?;
    let (manifest, snapshot, converter) = match &source.protocol {
        SourceProtocol::WingetRest { .. } => {
            if documents.len() != 1 {
                return Err(Error::Input);
            }
            let bytes = documents.values().next().ok_or(Error::Input)?;
            let m =
                rss_mdm_winget_source::parse_manifest(&q, bytes).map_err(|_| Error::Unsupported)?;
            (
                m,
                format!("sha256.{}", hex(&r::Digest::of(bytes).bytes())),
                "rss-winget-rest/1",
            )
        }
        SourceProtocol::WingetCommunity { commit, .. } => {
            let selected: Vec<_> = documents
                .iter()
                .map(|(p, b)| (p.clone(), b.clone()))
                .collect();
            let m = rss_mdm_winget_source::CommunityManifest::parse(&q, &selected)
                .map_err(|_| Error::Unsupported)?;
            (
                m.manifest().clone(),
                commit.clone(),
                "rss-winget-community/1",
            )
        }
        _ => return Err(Error::Unsupported),
    };
    validate_winget_behavior(input, &manifest)?;
    let metadata = manifest.locale_metadata();
    let string = |key: &str| {
        metadata[key]
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::Input)
    };
    let export = if input.native_export {
        r::SoftwareExport::Winget {
            locale: string("PackageLocale")?,
            name: string("PackageName")?,
            publisher: string("Publisher")?,
            description: string("ShortDescription")?,
            license: string("License")?,
        }
    } else {
        r::SoftwareExport::Disabled
    };
    let artifact = r::SoftwareArtifact {
        reference: format!("installer.{}", hex(&manifest.sha256())),
        origin: Some(manifest.artifact_url().into()),
        length: input.installer_length,
        sha256: manifest.sha256(),
    };
    Ok((artifact, export, snapshot, converter))
}
fn validate_winget_behavior(
    input: &ImportRequest,
    manifest: &rss_mdm_winget_source::Manifest,
) -> Result<()> {
    use rss_mdm_winget_source::{InstallerType, Scope};
    let (scope, invocation, upgrade) = match (&input.behavior, manifest.query().installer_type()) {
        (r::SoftwareBehavior::Msi(n), InstallerType::Msi)
        | (r::SoftwareBehavior::Winget(n), InstallerType::Msi) => {
            (n.scope, &n.install, &n.upgrade_invocation)
        }
        (r::SoftwareBehavior::Exe(n), InstallerType::Exe) => {
            (n.scope, &n.install, &n.upgrade_invocation)
        }
        _ => return Err(Error::Unsupported),
    };
    match (scope, manifest.query().scope()) {
        (r::SoftwareScope::System, Scope::Machine) | (r::SoftwareScope::User, Scope::User) => {}
        // Explicit authoring supplies the otherwise unspecified scope, never an implicit promotion.
        (_, Scope::Unspecified) => {}
        _ => return Err(Error::Input),
    }
    let metadata = manifest.installer_metadata();
    for (field, actual) in [
        ("Silent", &invocation.arguments),
        ("Upgrade", &upgrade.arguments),
    ] {
        if let Some(value) = metadata["InstallerSwitches"].get(field) {
            let literal = value.as_str().ok_or(Error::Input)?;
            // This finite sublanguage does not guess quoting or evaluate shell/installation expressions.
            if literal.contains(['"', '\'', '{', '}', '\r', '\n']) {
                return Err(Error::Unsupported);
            }
            let expected: Vec<_> = literal
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect();
            if actual != &expected {
                return Err(Error::Input);
            }
        }
    }
    if metadata["InstallerSwitches"].get("Custom").is_some()
        || metadata["InstallerSwitches"]
            .get("SilentWithProgress")
            .is_some()
    {
        return Err(Error::Unsupported);
    }
    if metadata.get("MinimumOSVersion").is_some() {
        return Err(Error::Unsupported);
    }
    if let Some(policy) = metadata.get("UpgradeBehavior") {
        let actual = match &input.behavior {
            r::SoftwareBehavior::Msi(n) | r::SoftwareBehavior::Winget(n) => n.upgrade,
            r::SoftwareBehavior::Exe(n) => n.upgrade,
            _ => return Err(Error::Unsupported),
        };
        let expected = match policy.as_str() {
            Some("install") => r::SoftwareUpgrade::InPlace,
            Some("uninstallPrevious") => r::SoftwareUpgrade::UninstallThenInstall,
            Some("deny") => r::SoftwareUpgrade::Deny,
            _ => return Err(Error::Unsupported),
        };
        if actual != expected {
            return Err(Error::Input);
        }
    }
    if let Some(product) = metadata.get("ProductCode") {
        let detect = match &input.behavior {
            r::SoftwareBehavior::Msi(n) | r::SoftwareBehavior::Winget(n) => &n.detect,
            r::SoftwareBehavior::Exe(n) => &n.detect,
            _ => return Err(Error::Unsupported),
        };
        if !matches!(detect,r::SoftwareDetection::MsiProduct{product_code,version} if Some(product_code.as_str())==product.as_str() && version==&input.package_version)
        {
            return Err(Error::Unsupported);
        }
    }
    if let Some(codes) = metadata.get("InstallerSuccessCodes") {
        for code in codes.as_array().ok_or(Error::Input)? {
            let code = code
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(Error::Input)?;
            if !invocation.exit_codes.success.contains(&code)
                || !upgrade.exit_codes.success.contains(&code)
            {
                return Err(Error::Input);
            }
        }
    }
    let deps = metadata["Dependencies"]["PackageDependencies"].as_array();
    if deps.map_or(0, Vec::len) != input.dependencies.len() {
        return Err(Error::Dependency);
    }
    for dependency in deps.into_iter().flatten() {
        let name = dependency["PackageIdentifier"]
            .as_str()
            .ok_or(Error::Dependency)?;
        let selected = input
            .dependencies
            .iter()
            .find(|d| d.package == name)
            .ok_or(Error::Dependency)?;
        if dependency
            .get("MinimumVersion")
            .is_some_and(|v| v.as_str() != Some(selected.package_version.as_str()))
        {
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}
fn brew(
    tenant: TenantId,
    source: &SourceDefinition,
    input: &ImportRequest,
    documents: &SourceDocuments,
) -> Result<(r::SoftwareArtifact, r::SoftwareExport)> {
    use rss_mdm_brew_source as b;
    let SourceProtocol::BrewTap { tap, .. } = &source.protocol else {
        return Err(Error::Input);
    };
    let ImportSelection::Brew {
        path,
        bottle_tag,
        source_length,
    } = &input.selection
    else {
        return Err(Error::Input);
    };
    if documents.len() != 1 {
        return Err(Error::Input);
    }
    let tag = match bottle_tag.as_str() {
        "arm64_sonoma" => b::BottleTag::Arm64Sonoma,
        "sonoma" => b::BottleTag::Sonoma,
        _ => return Err(Error::Unsupported),
    };
    let key = b::PackageKey::new(tenant, tap, &input.package).map_err(|_| Error::Input)?;
    let parsed = b::TapImport::parse(
        &key,
        &input.package_version,
        tag,
        documents.get(path).ok_or(Error::Input)?,
    )
    .map_err(|_| Error::Unsupported)?;
    if parsed.dependencies().len() != input.dependencies.len() {
        return Err(Error::Dependency);
    }
    for dependency in parsed.dependencies() {
        let qualified = format!("{}/{}", dependency.tap(), dependency.name());
        if !input.dependencies.iter().any(|d| d.package == qualified) {
            return Err(Error::Dependency);
        }
    }
    let (file, payload) = match parsed.payload() {
        b::TapPayload::Cask { artifact, install } => {
            let (path, receipts) = match install {
                b::CaskArtifact::App(p) => (p.clone(), vec![]),
                b::CaskArtifact::Pkg { path, receipts } => (path.clone(), receipts.clone()),
            };
            validate_cask_behavior(&input.behavior, &path)?;
            (
                r::SoftwareArtifact {
                    reference: format!("installer.{}", hex(&artifact.sha256())),
                    origin: Some(artifact.url().into()),
                    length: input.installer_length,
                    sha256: artifact.sha256(),
                },
                r::BrewExport::Cask { path, receipts },
            )
        }
        b::TapPayload::Bottle {
            source,
            bottle,
            tag,
            cellar,
            revision,
            rebuild,
            executable,
        } => {
            if !matches!(input.behavior, r::SoftwareBehavior::Brew(_))
                || source_length.is_none_or(|n| n == 0)
            {
                return Err(Error::Unsupported);
            }
            let evidence = input
                .additional_artifacts
                .get("source")
                .ok_or(Error::Input)?;
            if evidence.sha256 != source.sha256()
                || evidence.length != source_length.ok_or(Error::Input)?
                || evidence.origin.as_deref() != Some(source.url())
            {
                return Err(Error::Input);
            }
            (
                r::SoftwareArtifact {
                    reference: format!("bottle.{}", hex(&bottle.sha256())),
                    origin: Some(bottle.url().into()),
                    length: input.installer_length,
                    sha256: bottle.sha256(),
                },
                r::BrewExport::Bottle {
                    artifact: input.behavior.installer().into(),
                    source: "source".into(),
                    tag: tag.as_str().into(),
                    cellar: cellar.clone(),
                    revision: *revision,
                    rebuild: *rebuild,
                    executable: executable.clone(),
                },
            )
        }
    };
    let export = if input.native_export {
        r::SoftwareExport::Brew {
            name: parsed.name().into(),
            description: parsed.description().into(),
            homepage: parsed.homepage().into(),
            payload,
        }
    } else {
        r::SoftwareExport::Disabled
    };
    Ok((file, export))
}
fn validate_cask_behavior(behavior: &r::SoftwareBehavior, path: &str) -> Result<()> {
    match behavior {
        r::SoftwareBehavior::Dmg(d) => {
            let selected = match &d.payload {
                r::DmgPayload::AppCopy { application, .. } => &application.path,
                r::DmgPayload::ContainedPkg { path, .. } => path,
            };
            if selected != path {
                return Err(Error::Input);
            }
            Ok(())
        }
        r::SoftwareBehavior::Pkg(_) if path.ends_with(".pkg") => Ok(()),
        _ => Err(Error::Unsupported),
    }
}

fn validate_documents(input: &ImportRequest, documents: &SourceDocuments) -> Result<()> {
    use std::collections::BTreeSet;
    if documents.is_empty()
        || documents.len() > 8
        || documents
            .values()
            .any(|b| b.is_empty() || b.len() > 4 * 1024 * 1024)
    {
        return Err(Error::Input);
    }
    let paths: Vec<&str> = match &input.selection {
        ImportSelection::Winget { files, .. } => files.iter().map(String::as_str).collect(),
        ImportSelection::Brew { path, .. } => vec![path],
    };
    let selected: BTreeSet<_> = paths.iter().copied().collect();
    if selected.len() != paths.len()
        || selected != documents.keys().map(String::as_str).collect()
        || paths.iter().any(|p| {
            p.len() > 512
                || p.starts_with('/')
                || p.split('/').any(|s| s.is_empty() || s == "." || s == "..")
                || p.contains(['\\', '?', '#', '\r', '\n'])
        })
    {
        return Err(Error::Input);
    }
    let unique: BTreeSet<_> = input
        .dependencies
        .iter()
        .map(|d| (&d.package, &d.resource, &d.version))
        .collect();
    if unique.len() != input.dependencies.len() {
        return Err(Error::Dependency);
    }
    Ok(())
}
