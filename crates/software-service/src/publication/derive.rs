//! Native descriptions are projections of frozen Resource material, never writable input.
use super::{Error, Result, spec::*};
use rss_mdm_resource as r;
use serde_json::json;
use std::collections::BTreeSet;
fn unsupported() -> Error {
    Error::Unsupported
}
struct ExportContext {
    prefix: String,
    tap: String,
}
impl ExportContext {
    fn new(root: &r::Version, base: &str) -> Result<Self> {
        let mut url = super::artifact::checked_url(base)?;
        if !url.path().ends_with('/') {
            return Err(Error::Input);
        }
        url.path_segments_mut()
            .map_err(|_| Error::Input)?
            .pop_if_empty()
            .push(root.resource().as_str())
            .push(root.label().as_str())
            .push(&hex(&root.digest().bytes()));
        Ok(Self {
            prefix: format!("{}/", url.as_str().trim_end_matches('/')),
            tap: format!("rss/{}", hex(&root.digest().bytes())),
        })
    }
}
fn filename(variant: &r::Variant, d: &r::SoftwareDefinition, key: &str) -> Result<String> {
    let a = d.spec().artifacts.get(key).ok_or(Error::Content)?;
    let digest = hex(&a.sha256);
    if let r::SoftwareExport::Brew {
        payload:
            r::BrewExport::Bottle {
                artifact,
                source,
                tag,
                revision,
                rebuild,
                ..
            },
        ..
    } = &d.spec().export
    {
        if key == source {
            return Ok(format!("{digest}.source.tar.gz"));
        }
        if key == artifact {
            return Ok(format!(
                "{}-{}{}.{}.bottle{}.tar.gz",
                d.spec().package,
                d.spec().version,
                if *revision == 0 {
                    String::new()
                } else {
                    format!("_{revision}")
                },
                tag,
                if *rebuild == 0 {
                    String::new()
                } else {
                    format!(".{rebuild}")
                }
            ));
        }
    }
    if key != d.spec().behavior.installer() {
        return Err(Error::Unsupported);
    }
    match &d.spec().behavior {
        r::SoftwareBehavior::Msi(_) | r::SoftwareBehavior::Winget(_) => Ok(format!("{digest}.msi")),
        r::SoftwareBehavior::Exe(_) => Ok(format!("{digest}.exe")),
        r::SoftwareBehavior::Dmg(_) => Ok(format!("{digest}.dmg")),
        r::SoftwareBehavior::Pkg(_) => {
            let r::SoftwareExport::Brew {
                payload: r::BrewExport::Cask { path, .. },
                ..
            } = &d.spec().export
            else {
                return Err(Error::Unsupported);
            };
            Ok(format!(
                "{digest}/{}/{path}",
                match variant.architecture() {
                    r::Architecture::X86_64 => "x64",
                    r::Architecture::Aarch64 => "arm64",
                }
            ))
        }
        _ => Err(Error::Unsupported),
    }
}
fn artifact(
    ctx: &ExportContext,
    variant: &r::Variant,
    definition: &r::SoftwareDefinition,
    key: &str,
) -> Result<PublicArtifact> {
    let a = definition.spec().artifacts.get(key).ok_or(Error::Content)?;
    let path = filename(variant, definition, key)?;
    let encoded = path
        .split('/')
        .map(|s| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>())
        .collect::<Vec<_>>()
        .join("/");
    Ok(PublicArtifact {
        key: format!("content.{}", hex(&a.sha256)),
        url: format!("{}{encoded}", ctx.prefix),
        length: a.length,
        sha256: a.sha256,
    })
}
pub(super) fn exported_materials(
    root: &r::Version,
    dependencies: &[r::Version],
    base: &str,
) -> Result<Vec<PublicArtifact>> {
    let ctx = ExportContext::new(root, base)?;
    let mut files = std::collections::BTreeMap::new();
    for version in std::iter::once(root).chain(dependencies.iter()) {
        if version.tenant() != root.tenant() {
            return Err(Error::Identity);
        }
        for variant in version.variants() {
            let r::Declaration::Software { definition } = variant.declaration() else {
                return Err(Error::Content);
            };
            for key in definition.spec().artifacts.keys() {
                let a = artifact(&ctx, variant, definition, key)?;
                if files
                    .insert(a.url.clone(), a.clone())
                    .is_some_and(|old| old != a)
                {
                    return Err(Error::Unsupported);
                }
            }
        }
    }
    Ok(files.into_values().collect())
}
fn arguments(v: &r::NativeInvocation) -> Result<String> {
    if !v.environment.is_empty()
        || v.arguments
            .iter()
            .any(|a| a.is_empty() || a.contains([' ', '\t', '\r', '\n', '"', '\'', '{', '}']))
    {
        return Err(unsupported());
    }
    Ok(v.arguments.join(" "))
}
fn dependency<'a>(
    selected: &r::SoftwareDependency,
    versions: &'a [r::Version],
) -> Result<&'a r::Version> {
    versions
        .iter()
        .find(|v| {
            v.resource().as_str() == selected.resource
                && v.label().as_str() == selected.version
                && v.digest().bytes() == selected.sha256
        })
        .ok_or(Error::Content)
}
/// Complete native document from an exact definition and exact dependency versions.
pub fn derive_document(
    version: &r::Version,
    dependencies: &[r::Version],
    artifact_base: &str,
) -> Result<ExportDocument> {
    let ctx = ExportContext::new(version, artifact_base)?;
    derive_in(version, dependencies, &ctx, 0)
}
pub(super) fn dependency_documents(
    root: &r::Version,
    dependencies: &[r::Version],
    artifact_base: &str,
) -> Result<Vec<ExportDocument>> {
    let ctx = ExportContext::new(root, artifact_base)?;
    dependencies
        .iter()
        .map(|v| derive_in(v, dependencies, &ctx, 0))
        .collect()
}
fn derive_in(
    version: &r::Version,
    dependencies: &[r::Version],
    ctx: &ExportContext,
    depth: usize,
) -> Result<ExportDocument> {
    if depth > 32 {
        return Err(Error::Content);
    }
    if version.kind() != r::Kind::Software || dependencies.len() > 256 {
        return Err(Error::Content);
    }
    if dependencies.iter().any(|d| d.tenant() != version.tenant()) {
        return Err(Error::Identity);
    }
    let mut definitions = Vec::new();
    for variant in version.variants() {
        let r::Declaration::Software { definition } = variant.declaration() else {
            return Err(Error::Content);
        };
        if !definition.spec().signatures.is_empty() {
            return Err(unsupported());
        }
        definitions.push((variant, definition));
    }
    let (_, first) = definitions.first().ok_or(Error::Content)?;
    if definitions.iter().any(|(_, d)| {
        d.spec().package != first.spec().package || d.spec().version != first.spec().version
    }) {
        return Err(Error::Content);
    }
    match &first.spec().export {
        r::SoftwareExport::Winget { .. } => winget(&definitions, dependencies, ctx),
        r::SoftwareExport::Brew { .. } => brew(&definitions, dependencies, ctx, depth),
        r::SoftwareExport::Disabled => Err(unsupported()),
    }
}
fn winget(
    definitions: &[(&r::Variant, &r::SoftwareDefinition)],
    dependencies: &[r::Version],
    ctx: &ExportContext,
) -> Result<ExportDocument> {
    let first = definitions[0].1;
    let r::SoftwareExport::Winget {
        locale,
        name,
        publisher,
        description,
        license,
    } = &first.spec().export
    else {
        return Err(unsupported());
    };
    let mut installers = Vec::new();
    let mut coordinates = BTreeSet::new();
    for (variant, d) in definitions {
        if variant.platform() != r::Platform::Windows || d.spec().export != first.spec().export {
            return Err(unsupported());
        }
        let (kind, scope, install, upgrade, upgrade_policy, uninstall, detect) =
            match &d.spec().behavior {
                r::SoftwareBehavior::Msi(n) | r::SoftwareBehavior::Winget(n) => (
                    "msi",
                    n.scope,
                    &n.install,
                    &n.upgrade_invocation,
                    n.upgrade,
                    &n.uninstall,
                    &n.detect,
                ),
                r::SoftwareBehavior::Exe(n)
                    if n.layout.len() == 1 && n.layout.values().next() == Some(&n.installer) =>
                {
                    (
                        "exe",
                        n.scope,
                        &n.install,
                        &n.upgrade_invocation,
                        n.upgrade,
                        &n.uninstall,
                        &n.detect,
                    )
                }
                _ => return Err(unsupported()),
            };
        if upgrade_policy != r::SoftwareUpgrade::InPlace || uninstall.is_some() {
            return Err(unsupported());
        }
        let r::SoftwareDetection::MsiProduct {
            product_code,
            version: detected_version,
        } = detect
        else {
            return Err(unsupported());
        };
        if detected_version != &d.spec().version {
            return Err(Error::Content);
        }
        let arch = match variant.architecture() {
            r::Architecture::X86_64 => "x64",
            r::Architecture::Aarch64 => "arm64",
        };
        let scope = match scope {
            r::SoftwareScope::System => "machine",
            r::SoftwareScope::User => "user",
        };
        if !coordinates.insert((arch, kind, scope)) {
            return Err(unsupported());
        }
        let a = artifact(ctx, variant, d, d.spec().behavior.installer())?;
        let native_dependencies=d.spec().dependencies.iter().map(|selected| {
            let child=dependency(selected,dependencies)?;
            let selected=child.variants().iter().find(|v|v.platform()==variant.platform()&&v.architecture()==variant.architecture()).ok_or(Error::Content)?;
            let r::Declaration::Software{definition}=selected.declaration() else{return Err(Error::Content);};
            if !matches!(definition.spec().export,r::SoftwareExport::Winget{..}){return Err(unsupported());}
            Ok(json!({"PackageIdentifier":definition.spec().package,"MinimumVersion":definition.spec().version}))
        }).collect::<Result<Vec<_>>>()?;
        let silent = arguments(install)?;
        let upgrade_arguments = arguments(upgrade)?;
        if kind == "exe" && silent.is_empty() {
            return Err(unsupported());
        }
        let mut switches = serde_json::Map::new();
        if !silent.is_empty() {
            switches.insert("Silent".into(), json!(silent));
        }
        if !upgrade_arguments.is_empty() {
            switches.insert("Upgrade".into(), json!(upgrade_arguments));
        }
        let mut installer = json!({"Architecture":arch,"InstallerType":kind,"Scope":scope,"InstallerUrl":a.url,"InstallerSha256":hex(&a.sha256),"InstallerSwitches":switches,"ProductCode":product_code,"InstallerSuccessCodes":install.exit_codes.success});
        // REST 1.0 represents successful installer codes; reboot classifications outside
        // WinGet's native MSI/EXE codes cannot be truthfully exported.
        if install.exit_codes != upgrade.exit_codes
            || install
                .exit_codes
                .reboot
                .iter()
                .any(|c| !matches!(c, 1641 | 3010))
        {
            return Err(unsupported());
        }
        if !native_dependencies.is_empty() {
            installer["Dependencies"] = json!({"PackageDependencies":native_dependencies});
        }
        installers.push(installer);
    }
    Ok(ExportDocument::Winget {
        manifest: json!({"PackageIdentifier":first.spec().package,"Versions":[{"PackageVersion":first.spec().version,"DefaultLocale":{"PackageLocale":locale,"Publisher":publisher,"PackageName":name,"License":license,"ShortDescription":description},"Installers":installers}]}),
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn brew(
    definitions: &[(&r::Variant, &r::SoftwareDefinition)],
    dependencies: &[r::Version],
    ctx: &ExportContext,
    depth: usize,
) -> Result<ExportDocument> {
    let first = definitions[0].1;
    let r::SoftwareExport::Brew {
        name,
        description,
        homepage,
        payload: first_payload,
    } = &first.spec().export
    else {
        return Err(unsupported());
    };
    let mut files = Vec::new();
    let mut bottles = Vec::new();
    let mut source_artifact = None;
    let mut executable_value = None;
    let mut bottle_layout = None;
    let mut install = None;
    for (variant, d) in definitions {
        if variant.platform() != r::Platform::MacOS {
            return Err(unsupported());
        }
        let r::SoftwareExport::Brew {
            name: n,
            description: desc,
            homepage: home,
            payload,
        } = &d.spec().export
        else {
            return Err(unsupported());
        };
        if (n, desc, home) != (name, description, homepage) {
            return Err(Error::Content);
        }
        match payload {
            r::BrewExport::Cask { path, receipts } => {
                if !matches!(first_payload, r::BrewExport::Cask { .. })
                    || !d.spec().dependencies.is_empty()
                {
                    return Err(unsupported());
                }
                let selected = match &d.spec().behavior {
                    r::SoftwareBehavior::Dmg(dmg)
                        if dmg.scope == r::SoftwareScope::System
                            && dmg.upgrade == r::SoftwareUpgrade::InPlace
                            && dmg.invocation.arguments.is_empty() =>
                    {
                        match &dmg.payload {
                            r::DmgPayload::AppCopy { application, .. }
                                if application.path == *path
                                    && receipts.is_empty()
                                    && application.target_name
                                        == path.rsplit('/').next().ok_or(Error::Content)? =>
                            {
                                CaskInstall::App { path: path.clone() }
                            }
                            r::DmgPayload::ContainedPkg {
                                path: p, receipt, ..
                            } if p == path && receipts == std::slice::from_ref(receipt) => {
                                CaskInstall::Pkg {
                                    path: path.clone(),
                                    receipts: receipts.clone(),
                                }
                            }
                            _ => return Err(unsupported()),
                        }
                    }
                    r::SoftwareBehavior::Pkg(n) if n.upgrade == r::SoftwareUpgrade::InPlace => {
                        if !matches!(&n.detect,r::SoftwareDetection::PkgReceipt{receipt,..} if receipts==std::slice::from_ref(receipt))
                        {
                            return Err(unsupported());
                        }
                        CaskInstall::Pkg {
                            path: path.clone(),
                            receipts: receipts.clone(),
                        }
                    }
                    _ => return Err(unsupported()),
                };
                if install.as_ref().is_some_and(|old: &CaskInstall| {
                    serde_json::to_value(old).ok() != serde_json::to_value(&selected).ok()
                }) {
                    return Err(unsupported());
                }
                install = Some(selected);
                files.push(BrewArtifact {
                    architecture: match variant.architecture() {
                        r::Architecture::X86_64 => "x86_64",
                        r::Architecture::Aarch64 => "aarch64",
                    }
                    .into(),
                    artifact: artifact(ctx, variant, d, d.spec().behavior.installer())?,
                });
            }
            r::BrewExport::Bottle {
                artifact: key,
                source,
                tag,
                cellar,
                revision,
                rebuild,
                executable,
            } => {
                if !matches!(d.spec().behavior, r::SoftwareBehavior::Brew(_))
                    || !matches!(first_payload, r::BrewExport::Bottle { .. })
                    || !matches!(cellar.as_str(), "any" | "any_skip_relocation")
                {
                    return Err(unsupported());
                }
                if bottle_layout.is_some_and(|old| old != (*revision, *rebuild)) {
                    return Err(Error::Content);
                }
                bottle_layout = Some((*revision, *rebuild));
                let expected = match variant.architecture() {
                    r::Architecture::X86_64 => "sonoma",
                    r::Architecture::Aarch64 => "arm64_sonoma",
                };
                if tag != expected {
                    return Err(Error::Content);
                }
                let a = artifact(ctx, variant, d, key)?;
                let original = artifact(ctx, variant, d, source)?;
                if source_artifact.as_ref().is_some_and(|old| old != &original)
                    || executable_value
                        .as_ref()
                        .is_some_and(|old| old != executable)
                {
                    return Err(unsupported());
                }
                source_artifact = Some(original);
                executable_value = Some(executable.clone());
                let mut root = url::Url::parse(&a.url).map_err(|_| Error::Content)?;
                root.path_segments_mut().map_err(|_| Error::Content)?.pop();
                bottles.push(BottleInput {
                    cellar: cellar.clone(),
                    tag: tag.clone(),
                    root_url: root.into(),
                    artifact: a,
                });
            }
        }
    }
    let payload = if let Some(install) = install {
        BrewPayload::Cask {
            artifacts: files,
            install,
        }
    } else {
        // Exact dependency documents/coordinates are required rather than public names.
        let mut deps = Vec::new();
        for selected in &first.spec().dependencies {
            let child = dependency(selected, dependencies)?;
            let doc = derive_in(child, dependencies, ctx, depth + 1)?;
            let ExportDocument::Brew { recipe } = &doc else {
                return Err(unsupported());
            };
            deps.push(BrewDependency {
                recipe: recipe.clone(),
                tap: ctx.tap.clone(),
                name: recipe.package.clone(),
                snapshot: child.digest().bytes(),
                artifacts: child
                    .variants()
                    .iter()
                    .flat_map(|v| match v.declaration() {
                        r::Declaration::Software { definition } => definition
                            .spec()
                            .artifacts
                            .keys()
                            .map(|k| artifact(ctx, v, definition, k))
                            .collect::<Vec<_>>(),
                        _ => vec![Err(Error::Content)],
                    })
                    .collect::<Result<_>>()?,
            });
        }
        BrewPayload::Formula {
            revision: bottle_layout.ok_or(Error::Content)?.0,
            rebuild: bottle_layout.ok_or(Error::Content)?.1,
            source: source_artifact.ok_or(Error::Content)?,
            executable: executable_value.ok_or(Error::Content)?,
            bottles,
            dependencies: deps,
        }
    };
    Ok(ExportDocument::Brew {
        recipe: Box::new(BrewRecipe {
            package: first.spec().package.clone(),
            version: first.spec().version.clone(),
            name: name.clone(),
            description: description.clone(),
            homepage: homepage.clone(),
            payload,
        }),
    })
}
