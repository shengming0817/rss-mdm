//! Structural material checks, without fetching bytes or asserting platform trust.
use super::*;

fn checked(value: &str, max: usize, kind: Validation) -> Result<(), Error> {
    text(value, max).map_err(|_| invalid(kind))
}
fn reference(spec: &SoftwareSpec, key: &str) -> Result<(), Error> {
    spec.artifacts
        .get(key)
        .ok_or(invalid(Validation::Artifact))?
        .artifact()?;
    Ok(())
}
/// Portable relative material path, with Unicode preserved for DMG payload names.
pub(super) fn relative(path: &str) -> Result<(), Error> {
    checked(path, 1024, Validation::Artifact)?;
    if path.contains(['\\', ':', '\0'])
        || path
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == ".." || v.ends_with([' ', '.']))
    {
        return Err(invalid(Validation::Artifact));
    }
    Ok(())
}
fn artifact(a: &SoftwareArtifact) -> Result<(), Error> {
    a.artifact()?;
    if let Some(origin) = &a.origin {
        checked(origin, 2048, Validation::Artifact)?;
        if !origin.starts_with("https://") || origin.contains(['?', '#', '@']) {
            return Err(invalid(Validation::Artifact));
        }
    }
    Ok(())
}
pub(super) fn validate(spec: &mut SoftwareSpec) -> Result<(), Error> {
    Id::new(&spec.source.id).map_err(|_| invalid(Validation::Source))?;
    Id::new(&spec.source.revision).map_err(|_| invalid(Validation::Source))?;
    checked(&spec.package, 1024, Validation::Identity)?;
    checked(&spec.version, 1024, Validation::Identity)?;
    materials(spec)?;
    dependencies(spec)?;
    behavior(spec)?;
    signatures(spec)?;
    export(spec)?;
    let bytes = serde_json::to_vec(spec).map_err(|_| invalid(Validation::Budget))?;
    if bytes.len() > 1_048_576 {
        return Err(invalid(Validation::Budget));
    }
    Ok(())
}
fn materials(spec: &SoftwareSpec) -> Result<(), Error> {
    if spec.artifacts.is_empty() {
        return Err(invalid(Validation::Artifact));
    }
    if spec.artifacts.len() > 64 {
        return Err(invalid(Validation::Budget));
    }
    let mut references = BTreeSet::new();
    for (key, value) in &spec.artifacts {
        Id::new(key).map_err(|_| invalid(Validation::Artifact))?;
        artifact(value)?;
        if !references.insert(&value.reference) {
            return Err(invalid(Validation::Artifact));
        }
    }
    reference(spec, spec.behavior.installer())?;
    provenance(&spec.provenance)
}
fn provenance(value: &SoftwareProvenance) -> Result<(), Error> {
    let SoftwareProvenance::Imported {
        snapshot,
        converter,
        files,
    } = value
    else {
        return Ok(());
    };
    checked(snapshot, 128, Validation::Source)?;
    checked(converter, 128, Validation::Source)?;
    if files.is_empty() || files.len() > 32 {
        return Err(invalid(Validation::Budget));
    }
    let mut names = BTreeSet::new();
    for file in files {
        relative(&file.path)?;
        artifact(&file.content)?;
        if !names.insert(file.path.to_lowercase()) {
            return Err(invalid(Validation::Source));
        }
    }
    Ok(())
}
fn dependencies(spec: &mut SoftwareSpec) -> Result<(), Error> {
    if spec.dependencies.len() > 32 {
        return Err(invalid(Validation::Budget));
    }
    spec.dependencies
        .sort_by(|a, b| (&a.resource, &a.version).cmp(&(&b.resource, &b.version)));
    let mut seen = BTreeSet::new();
    for dep in &spec.dependencies {
        Id::new(&dep.resource).map_err(|_| invalid(Validation::Dependency))?;
        Id::new(&dep.version).map_err(|_| invalid(Validation::Dependency))?;
        if !seen.insert(&dep.resource) {
            return Err(invalid(Validation::Dependency));
        }
    }
    Ok(())
}
fn invocation(value: &NativeInvocation) -> Result<(), Error> {
    if !(1..=86400).contains(&value.timeout_seconds)
        || !(1..=1_048_576).contains(&value.output_bytes)
        || value.arguments.len() > 128
        || value.environment.len() > 32
    {
        return Err(invalid(Validation::Command));
    }
    if value
        .arguments
        .iter()
        .any(|v| v.len() > 4096 || v.contains('\0'))
    {
        return Err(invalid(Validation::Command));
    }
    for (key, v) in &value.environment {
        if !key.starts_with("RSS_PARAM_")
            || key.len() > 128
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || v.len() > 4096
            || v.contains('\0')
        {
            return Err(invalid(Validation::Command));
        }
    }
    let codes = &value.exit_codes;
    if codes.success.is_empty()
        || codes.success.len() + codes.reboot.len() > 32
        || !codes.success.is_disjoint(&codes.reboot)
    {
        return Err(invalid(Validation::Command));
    }
    Ok(())
}
fn scope(scope: SoftwareScope, invocation: &NativeInvocation) -> Result<(), Error> {
    if scope == SoftwareScope::System && invocation.run_as != RunAs::System {
        return Err(invalid(Validation::Command));
    }
    if scope == SoftwareScope::User && invocation.run_as != RunAs::LoggedInUser {
        return Err(invalid(Validation::Command));
    }
    Ok(())
}
fn removal(spec: &SoftwareSpec, value: &Option<NativeRemoval>) -> Result<(), Error> {
    if let Some(v) = value {
        reference(spec, &v.installer)?;
        invocation(&v.invocation)?;
    }
    Ok(())
}
fn native(spec: &SoftwareSpec, value: &NativeSoftware) -> Result<(), Error> {
    reference(spec, &value.installer)?;
    invocation(&value.install)?;
    invocation(&value.upgrade_invocation)?;
    scope(value.scope, &value.install)?;
    scope(value.scope, &value.upgrade_invocation)?;
    upgrade(value.upgrade, value.uninstall.is_some())?;
    removal(spec, &value.uninstall)?;
    if let Some(removal) = &value.uninstall {
        scope(value.scope, &removal.invocation)?;
    }
    detection(spec, &value.detect)?;
    detector_scope(&value.detect, value.scope)?;
    Ok(())
}
fn exe(spec: &SoftwareSpec, value: &ExeSoftware) -> Result<(), Error> {
    invocation(&value.install)?;
    invocation(&value.upgrade_invocation)?;
    scope(value.scope, &value.install)?;
    scope(value.scope, &value.upgrade_invocation)?;
    upgrade(value.upgrade, value.uninstall.is_some())?;
    removal(spec, &value.uninstall)?;
    if let Some(removal) = &value.uninstall {
        scope(value.scope, &removal.invocation)?;
    }
    detection(spec, &value.detect)?;
    detector_scope(&value.detect, value.scope)?;
    if value.layout.is_empty() || value.layout.len() > 64 {
        return Err(invalid(Validation::Artifact));
    }
    let mut paths = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (path, key) in &value.layout {
        bundle_path(path).map_err(|_| invalid(Validation::Artifact))?;
        reference(spec, key)?;
        if !paths.insert(path.to_ascii_lowercase()) || !keys.insert(key) {
            return Err(invalid(Validation::Artifact));
        }
    }
    if keys.len() != spec.artifacts.len() || !keys.contains(&value.installer) {
        return Err(invalid(Validation::Artifact));
    }
    Ok(())
}

fn upgrade(policy: SoftwareUpgrade, removal: bool) -> Result<(), Error> {
    if policy == SoftwareUpgrade::UninstallThenInstall && !removal {
        return Err(invalid(Validation::Command));
    }
    Ok(())
}
fn script(
    spec: &SoftwareSpec,
    value: &SoftwareScript,
    manifest: Option<&BundleManifest>,
) -> Result<(), Error> {
    invocation(&value.invocation)?;
    if let Some(m) = manifest {
        bundle_path(&value.entry)?;
        if !m.entries.contains_key(&value.entry) {
            return Err(invalid(Validation::Command));
        }
    } else {
        reference(spec, &value.entry)?;
    }
    Ok(())
}
fn bundle(spec: &SoftwareSpec, value: &BundleSoftware) -> Result<(), Error> {
    let m = &value.manifest;
    if m.schema != 1 || m.entries.is_empty() || m.entries.len() > 4096 || spec.artifacts.len() != 1
    {
        return Err(invalid(Validation::Bundle));
    }
    let mut names = BTreeSet::new();
    for path in m.entries.keys() {
        bundle_path(path)?;
        if path.eq_ignore_ascii_case("manifest.json") || !names.insert(path.to_ascii_lowercase()) {
            return Err(invalid(Validation::Bundle));
        }
    }
    script(spec, &value.install, Some(m))?;
    let ext = if m.platform == Platform::Windows {
        "ps1"
    } else {
        "sh"
    };
    if value.install.entry != format!("install.{ext}") {
        return Err(invalid(Validation::Bundle));
    }
    if let Some(u) = &value.uninstall {
        script(spec, u, Some(m))?;
        if u.entry != format!("uninstall.{ext}")
            || u.invocation.run_as != value.install.invocation.run_as
        {
            return Err(invalid(Validation::Bundle));
        }
    }
    detection(spec, &value.detect)
}
fn dmg(spec: &SoftwareSpec, value: &DmgSoftware) -> Result<(), Error> {
    checked(&value.volume, 255, Validation::Identity)?;
    invocation(&value.invocation)?;
    scope(value.scope, &value.invocation)?;
    if !value.invocation.arguments.is_empty() || !value.invocation.environment.is_empty() {
        return Err(invalid(Validation::Command));
    }
    match &value.payload {
        DmgPayload::AppCopy { application, .. } => {
            relative(&application.path)?;
            relative(&application.target_name)?;
            checked(&application.bundle_id, 255, Validation::Identity)?;
            if !application.path.ends_with(".app")
                || !application.target_name.ends_with(".app")
                || application.target_name.contains('/')
                || application.version != spec.version
                || application.material_sha256 == [0; 32]
            {
                return Err(invalid(Validation::Identity));
            }
        }
        DmgPayload::ContainedPkg {
            path,
            length,
            sha256,
            receipt,
            uninstall,
        } => {
            relative(path)?;
            checked(receipt, 255, Validation::Detection)?;
            if !path.ends_with(".pkg")
                || *length == 0
                || *sha256 == [0; 32]
                || value.scope != SoftwareScope::System
            {
                return Err(invalid(Validation::Artifact));
            }
            removal(spec, uninstall)?;
        }
    }
    Ok(())
}
fn msix_identity(identity: &MsixIdentity) -> Result<(), Error> {
    checked(&identity.name, 255, Validation::Identity)?;
    checked(&identity.publisher, 1024, Validation::Identity)?;
    if identity.name.contains(['/', '\\', ' '])
        || identity.resource_id.len() > 255
        || identity.resource_id.chars().any(char::is_control)
    {
        return Err(invalid(Validation::Identity));
    }
    Ok(())
}
fn msix(spec: &SoftwareSpec, value: &MsixSoftware) -> Result<(), Error> {
    msix_identity(&value.identity)?;
    invocation(&value.invocation)?;
    if !value.invocation.arguments.is_empty()
        || !value.invocation.environment.is_empty()
        || !value.identity.resource_id.is_empty()
    {
        return Err(invalid(Validation::Command));
    }
    let version = value
        .identity
        .version
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(".");
    if version != spec.version || value.dependencies.len() != spec.dependencies.len() {
        return Err(invalid(Validation::Dependency));
    }
    msix_members(value)?;
    for dependency in &value.dependencies {
        msix_identity(dependency)?;
    }
    match &value.deployment {
        MsixDeployment::DeviceProvisioning => {
            if value.invocation.run_as != RunAs::System || value.allow_unsigned {
                return Err(invalid(Validation::Command));
            }
        }
        MsixDeployment::TargetUserRegistration { target } => {
            if value.invocation.run_as != RunAs::LoggedInUser {
                return Err(invalid(Validation::Command));
            }
            if let SoftwareUser::Exact { identity } = target {
                checked(identity, 255, Validation::Target)?;
            }
        }
    }
    Ok(())
}
fn msix_members(value: &MsixSoftware) -> Result<(), Error> {
    let MsixContainer::Bundle { members, .. } = &value.container else {
        return Ok(());
    };
    if members.is_empty() || members.len() > 64 {
        return Err(invalid(Validation::Budget));
    }
    let mut names = BTreeSet::new();
    let mut applications = 0;
    for member in members {
        relative(&member.path)?;
        msix_identity(&member.identity)?;
        if member.length == 0
            || member.sha256 == [0; 32]
            || !names.insert(member.path.to_lowercase())
        {
            return Err(invalid(Validation::Artifact));
        }
        if member.identity.name != value.identity.name
            || member.identity.publisher != value.identity.publisher
            || member.identity.version != value.identity.version
        {
            return Err(invalid(Validation::Identity));
        }
        if member.identity.resource_id.is_empty() {
            applications += 1;
            if member.identity != value.identity {
                return Err(invalid(Validation::Identity));
            }
        }
    }
    if applications != 1 {
        return Err(invalid(Validation::Artifact));
    }
    Ok(())
}
fn behavior(spec: &SoftwareSpec) -> Result<(), Error> {
    match &spec.behavior {
        SoftwareBehavior::Msi(n)
        | SoftwareBehavior::Pkg(n)
        | SoftwareBehavior::Winget(n)
        | SoftwareBehavior::Brew(n) => native(spec, n),
        SoftwareBehavior::Exe(n) => exe(spec, n),
        SoftwareBehavior::Bundle(b) => bundle(spec, b),
        SoftwareBehavior::Dmg(d) => dmg(spec, d),
        SoftwareBehavior::Msix(m) => msix(spec, m),
    }
}
fn detector_scope(value: &SoftwareDetection, actual: SoftwareScope) -> Result<(), Error> {
    if let SoftwareDetection::Registry { scope, .. } | SoftwareDetection::File { scope, .. } = value
        && *scope != actual
    {
        return Err(invalid(Validation::Detection));
    }
    Ok(())
}
fn detection(spec: &SoftwareSpec, value: &SoftwareDetection) -> Result<(), Error> {
    match value {
        SoftwareDetection::MsiProduct {
            product_code,
            version,
        } => {
            let b = product_code.as_bytes();
            if b.len() != 38
                || b[0] != b'{'
                || b[37] != b'}'
                || !b[1..37].iter().enumerate().all(|(i, c)| {
                    if [8, 13, 18, 23].contains(&i) {
                        *c == b'-'
                    } else {
                        c.is_ascii_hexdigit()
                    }
                })
            {
                return Err(invalid(Validation::Detection));
            }
            checked(version, 1024, Validation::Detection)
        }
        SoftwareDetection::PkgReceipt { receipt, version } => {
            checked(receipt, 255, Validation::Detection)?;
            checked(version, 1024, Validation::Detection)
        }
        SoftwareDetection::Registry {
            key,
            value,
            version,
            ..
        } => {
            checked(key, 1024, Validation::Detection)?;
            checked(value, 255, Validation::Detection)?;
            if key.starts_with('\\') || key.contains("..") {
                return Err(invalid(Validation::Detection));
            }
            checked(version, 1024, Validation::Detection)
        }
        SoftwareDetection::File {
            path,
            version,
            sha256,
            ..
        } => {
            relative(path).map_err(|_| invalid(Validation::Detection))?;
            if *sha256 == [0; 32] {
                return Err(invalid(Validation::Detection));
            }
            checked(version, 1024, Validation::Detection)
        }
        SoftwareDetection::Script { command } => script(spec, command, spec.behavior.bundle()),
    }
}
fn signatures(spec: &SoftwareSpec) -> Result<(), Error> {
    if spec.signatures.len() > 64 {
        return Err(invalid(Validation::Budget));
    }
    let mut seen = BTreeSet::new();
    for signature in &spec.signatures {
        reference(spec, &signature.artifact)?;
        checked(&signature.publisher, 1024, Validation::Identity)?;
        if !seen.insert((&signature.artifact, signature.mechanism as u8)) {
            return Err(invalid(Validation::Identity));
        }
    }
    Ok(())
}
fn export(spec: &SoftwareSpec) -> Result<(), Error> {
    match &spec.export {
        SoftwareExport::Disabled => Ok(()),
        SoftwareExport::Winget {
            locale,
            name,
            publisher,
            description,
            license,
        } => {
            for value in [locale, name, publisher, description, license] {
                checked(value, 4096, Validation::Identity)?;
            }
            if !matches!(
                spec.behavior,
                SoftwareBehavior::Msi(_) | SoftwareBehavior::Winget(_) | SoftwareBehavior::Exe(_)
            ) {
                return Err(invalid(Validation::Target));
            }
            Ok(())
        }
        SoftwareExport::Brew {
            name,
            description,
            homepage,
            payload,
        } => {
            for value in [name, description, homepage] {
                checked(value, 4096, Validation::Identity)?;
            }
            if !homepage.starts_with("https://")
                || !matches!(
                    spec.behavior,
                    SoftwareBehavior::Brew(_) | SoftwareBehavior::Dmg(_) | SoftwareBehavior::Pkg(_)
                )
            {
                return Err(invalid(Validation::Target));
            }
            match payload {
                BrewExport::Cask { path, receipts } => {
                    relative(path)?;
                    if receipts.len() > 32 {
                        return Err(invalid(Validation::Budget));
                    }
                }
                BrewExport::Bottle {
                    artifact: key,
                    source,
                    tag,
                    cellar,
                    executable,
                    ..
                } => {
                    reference(spec, key)?;
                    reference(spec, source)?;
                    for value in [tag, cellar, executable] {
                        checked(value, 255, Validation::Identity)?;
                    }
                }
            }
            Ok(())
        }
    }
}
pub(super) fn target(
    spec: &SoftwareSpec,
    platform: Platform,
    architecture: Architecture,
) -> Result<(), Error> {
    let expected = match &spec.behavior {
        SoftwareBehavior::Msi(_)
        | SoftwareBehavior::Winget(_)
        | SoftwareBehavior::Exe(_)
        | SoftwareBehavior::Msix(_) => Platform::Windows,
        SoftwareBehavior::Pkg(_) | SoftwareBehavior::Brew(_) | SoftwareBehavior::Dmg(_) => {
            Platform::MacOS
        }
        SoftwareBehavior::Bundle(b) => {
            if b.manifest.architecture != architecture {
                return Err(invalid(Validation::Target));
            }
            b.manifest.platform
        }
    };
    if platform != expected {
        return Err(invalid(Validation::Target));
    }
    for requirement in &spec.signatures {
        let supported = match requirement.mechanism {
            SignatureMechanism::AppleDeveloperId => platform == Platform::MacOS,
            SignatureMechanism::Authenticode => platform == Platform::Windows,
            SignatureMechanism::Msix => {
                platform == Platform::Windows
                    && matches!(&spec.behavior, SoftwareBehavior::Msix(_))
                    && spec.behavior.installer() == requirement.artifact
            }
        };
        if !supported {
            return Err(invalid(Validation::Target));
        }
    }
    if let SoftwareBehavior::Msix(m) = &spec.behavior
        && (!m.identity.architecture.matches(architecture)
            || m.dependencies
                .iter()
                .any(|d| !d.architecture.matches(architecture))
            || matches!(&m.container,MsixContainer::Bundle{members,..} if members.iter().any(|member|!member.identity.architecture.matches(architecture))))
    {
        return Err(invalid(Validation::Target));
    }
    if let SoftwareBehavior::Brew(b) = &spec.behavior
        && b.scope != SoftwareScope::User
    {
        return Err(invalid(Validation::Target));
    }
    let detector = match &spec.behavior {
        SoftwareBehavior::Msi(n)
        | SoftwareBehavior::Pkg(n)
        | SoftwareBehavior::Winget(n)
        | SoftwareBehavior::Brew(n) => Some(&n.detect),
        SoftwareBehavior::Exe(n) => Some(&n.detect),
        SoftwareBehavior::Bundle(b) => Some(&b.detect),
        _ => None,
    };
    if let Some(d) = detector {
        detector_target(d, platform)?;
    }
    if let SoftwareBehavior::Bundle(b) = &spec.behavior {
        script_target(&b.install, platform)?;
        if let Some(u) = &b.uninstall {
            script_target(u, platform)?;
        }
    }
    Ok(())
}
fn script_target(value: &SoftwareScript, platform: Platform) -> Result<(), Error> {
    let valid = match platform {
        Platform::Windows => value.interpreter == SoftwareInterpreter::PowerShell7,
        Platform::MacOS => matches!(
            value.interpreter,
            SoftwareInterpreter::PosixSh | SoftwareInterpreter::Bash
        ),
    };
    if !valid {
        return Err(invalid(Validation::Target));
    }
    Ok(())
}
fn detector_target(value: &SoftwareDetection, platform: Platform) -> Result<(), Error> {
    match value {
        SoftwareDetection::MsiProduct { .. } | SoftwareDetection::Registry { .. }
            if platform != Platform::Windows =>
        {
            Err(invalid(Validation::Target))
        }
        SoftwareDetection::PkgReceipt { .. } if platform != Platform::MacOS => {
            Err(invalid(Validation::Target))
        }
        SoftwareDetection::Script { command } => script_target(command, platform),
        _ => Ok(()),
    }
}
