//! Current executable software values. No source/catalog/approval models or compatibility shapes.
use super::{ExecutionIdentity, SoftwareTaskBundle, TaskArchitecture, TaskPlatform, WireError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Install scope is separate from the process identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskScope {
    /// Organization device installation.
    System,
    /// One authenticated interactive user.
    User,
}
/// Approved upgrade mechanism; no mutable command discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskUpgrade {
    /// The exact installer performs replacement.
    InPlace,
    /// The frozen removal and install plans run in order.
    UninstallThenInstall,
    /// Only a previously absent installation is permitted.
    Deny,
}
/// Disjoint explicitly accepted return codes. All others are failures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskExitCodes {
    /// Process success, still requiring independent effect detection.
    pub success: BTreeSet<i32>,
    /// Successful process completion requiring reboot.
    pub reboot: BTreeSet<i32>,
}
/// Literal invocation of the native installer chosen by the enclosing behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskInvocation {
    /// Process identity, never inferred from installation scope.
    pub run_as: ExecutionIdentity,
    /// Literal arguments; no shell or mutable registry command.
    pub arguments: Vec<String>,
    /// Product-prefixed environment values.
    pub environment: BTreeMap<String, String>,
    /// Wall-time ceiling.
    pub timeout_seconds: u32,
    /// Combined output ceiling.
    pub output_bytes: u32,
    /// Explicit return-code classification.
    pub exit_codes: SoftwareTaskExitCodes,
}
/// Script implementations only appear in declared Bundle entries or detectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskInterpreter {
    /// PowerShell 7.
    PowerShell7,
    /// POSIX shell.
    PosixSh,
    /// Bash.
    Bash,
}
/// Approved bounded script, with a declared immutable entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskScript {
    /// Finite interpreter.
    pub interpreter: SoftwareTaskInterpreter,
    /// Artifact key or Bundle member.
    pub entry: String,
    /// Literal bounded invocation.
    pub invocation: SoftwareTaskInvocation,
}
/// Native removal executes an explicitly approved artifact, never a discovered path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskRemoval {
    /// Artifact key of the approved removal installer.
    pub installer: String,
    /// Removal-specific literal parameters and return codes.
    pub invocation: SoftwareTaskInvocation,
}
/// Native installer material shared only where its values have identical meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskNative {
    /// Installer artifact key.
    pub installer: String,
    /// Actual installation scope.
    pub scope: SoftwareTaskScope,
    /// Unattended installation invocation.
    pub install: SoftwareTaskInvocation,
    /// Separately approved upgrade invocation and return-code policy.
    pub upgrade_invocation: SoftwareTaskInvocation,
    /// Explicit upgrade policy.
    pub upgrade: SoftwareTaskUpgrade,
    /// Absent means removal is unsupported, never guessed.
    #[serde(deserialize_with = "super::required_option")]
    pub uninstall: Option<SoftwareTaskRemoval>,
    /// Independent observation of effect.
    pub detect: SoftwareTaskDetection,
}
/// Complete offline EXE layout, including companion payload files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskExe {
    /// Approved EXE installer key.
    pub installer: String,
    /// Explicit system/user installation scope.
    pub scope: SoftwareTaskScope,
    /// Unattended installation; no default /S or /silent.
    pub install: SoftwareTaskInvocation,
    /// Separately approved upgrade invocation and return-code policy.
    pub upgrade_invocation: SoftwareTaskInvocation,
    /// Approved replacement sequence.
    pub upgrade: SoftwareTaskUpgrade,
    /// Explicit removal installer and invocation.
    #[serde(deserialize_with = "super::required_option")]
    pub uninstall: Option<SoftwareTaskRemoval>,
    /// Staging relative path to artifact key; no runtime downloads are authorized.
    pub layout: BTreeMap<String, String>,
    /// Independent identity/version detector.
    pub detect: SoftwareTaskDetection,
}
/// RSS ZIP with approved finite script entries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskBundleBehavior {
    /// ZIP artifact key.
    pub archive: String,
    /// Exact complete manifest.
    pub manifest: SoftwareTaskBundle,
    /// Frozen install entry.
    pub install: SoftwareTaskScript,
    /// Frozen removal entry, when supported.
    #[serde(deserialize_with = "super::required_option")]
    pub uninstall: Option<SoftwareTaskScript>,
    /// Independent effect observation.
    pub detect: SoftwareTaskDetection,
}
/// Exact application identity retained independently of image identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskMacApplication {
    /// Exact payload relative path within the selected image volume.
    pub path: String,
    /// Bundle identifier.
    pub bundle_id: String,
    /// Exact bundle version.
    pub version: String,
    /// Exact .app basename in the selected Applications directory.
    pub target_name: String,
}
/// DMG inner payload; no first-candidate discovery or automatic scripts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareTaskDmgPayload {
    /// Copy/replace one declared application; removal requires the declared exact target.
    AppCopy {
        /// Full declared app material.
        application: SoftwareTaskMacApplication,
        /// Whether an authorized task may remove the declared exact target.
        uninstall: bool,
    },
    /// Select one PKG and reuse PackageInstaller semantics.
    ContainedPkg {
        /// Exact image-relative PKG path.
        path: String,
        /// Full inner PKG byte length.
        length: u64,
        /// Inner PKG content digest.
        sha256: [u8; 32],
        /// Exact receipt identity.
        receipt: String,
        /// Explicit bounded removal PKG artifact, never receipt-forget.
        #[serde(deserialize_with = "super::required_option")]
        uninstall: Option<SoftwareTaskRemoval>,
    },
}
/// One selected volume and payload in an immutable disk image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskDmg {
    /// Image artifact key.
    pub image: String,
    /// Exact selected volume label; ambiguous multi-volume images are unsupported.
    pub volume: String,
    /// System or target user's Applications directory.
    pub scope: SoftwareTaskScope,
    /// Approved operation identity and budgets.
    pub invocation: SoftwareTaskInvocation,
    /// Explicit replacement policy.
    pub upgrade: SoftwareTaskUpgrade,
    /// Exact selected payload.
    pub payload: SoftwareTaskDmgPayload,
}
/// MSIX material architecture, distinct from the device processor architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskMsixArchitecture {
    /// Native x64 application or resource material.
    X86_64,
    /// Native ARM64 application or resource material.
    Aarch64,
    /// Architecture-independent MSIX material, including language/resource packages.
    Neutral,
}
impl SoftwareTaskMsixArchitecture {
    /// Whether this material can execute on the exact selected hardware profile.
    pub fn matches(self, architecture: TaskArchitecture) -> bool {
        self == Self::Neutral
            || matches!(
                (self, architecture),
                (Self::X86_64, TaskArchitecture::X86_64)
                    | (Self::Aarch64, TaskArchitecture::Aarch64)
            )
    }
}
/// MSIX identity uses Windows' own version and Publisher semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskMsixIdentity {
    /// Manifest Name.
    pub name: String,
    /// Exact manifest Publisher DN; not a generic display publisher.
    pub publisher: String,
    /// Exact four-part package version.
    pub version: [u16; 4],
    /// Selected processor architecture.
    pub architecture: SoftwareTaskMsixArchitecture,
    /// Exact resource identity; empty denotes the application package.
    pub resource_id: String,
}
/// Frozen .msixbundle member and its complete bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskMsixMember {
    /// Exact relative container member path.
    pub path: String,
    /// Exact package identity.
    pub identity: SoftwareTaskMsixIdentity,
    /// Member byte length.
    pub length: u64,
    /// Member digest.
    pub sha256: [u8; 32],
}
/// One MSIX or a precisely selected application/resource bundle member set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareTaskMsixContainer {
    /// Single application package.
    Package {
        /// Artifact key.
        installer: String,
    },
    /// One application member and explicit applicable resources.
    Bundle {
        /// Bundle artifact key.
        installer: String,
        /// Precisely selected members, including one application.
        members: Vec<SoftwareTaskMsixMember>,
    },
}
/// Approved target selector; actual user identity is frozen into a device task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareTaskUser {
    /// Only a unique interactive user; missing/multiple sessions block execution.
    ActiveInteractive,
    /// One exact local Windows SID or macOS uid, rechecked by the Agent.
    Exact {
        /// TaskPlatform-local stable identity.
        identity: String,
    },
}
/// Registration and provisioning are different effects, including on removal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareTaskMsixDeployment {
    /// Install/register and remove for one exact user.
    TargetUserRegistration {
        /// Approved user selection.
        target: SoftwareTaskUser,
    },
    /// Provision/deprovision the device's future-user package set.
    DeviceProvisioning,
}
/// Complete MSIX execution prerequisites and precise package identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskMsix {
    /// Frozen package/container bytes.
    pub container: SoftwareTaskMsixContainer,
    /// Expected application identity.
    pub identity: SoftwareTaskMsixIdentity,
    /// Exact installed/provisioned dependency identities; matched to catalog dependencies.
    pub dependencies: Vec<SoftwareTaskMsixIdentity>,
    /// Windows package target effect.
    pub deployment: SoftwareTaskMsixDeployment,
    /// Minimum Windows OS version.
    pub minimum_os: [u16; 4],
    /// Sideloading must already be permitted; tasks do not enable it.
    pub require_sideload: bool,
    /// Hash-only content still needs explicit native unsigned API support if unsigned.
    pub allow_unsigned: bool,
    /// Whether exact removal/deprovisioning is supported.
    pub uninstall: bool,
    /// Frozen runtime identity and budgets; deployment does not accept arbitrary switches.
    pub invocation: SoftwareTaskInvocation,
    /// Approved update sequence.
    pub upgrade: SoftwareTaskUpgrade,
}
/// Independent finite detector; an exit code is never a detector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareTaskDetection {
    /// One exact MSI product and version.
    MsiProduct {
        /// Canonical braced product GUID.
        product_code: String,
        /// Exact observed version.
        version: String,
    },
    /// Exact installer receipt and version; deleting it does not prove removal.
    PkgReceipt {
        /// Receipt identifier.
        receipt: String,
        /// Exact receipt version.
        version: String,
    },
    /// One literal registry value in the declared scope.
    Registry {
        /// Native hive scope.
        scope: SoftwareTaskScope,
        /// Relative registry key, never an uninstall command.
        key: String,
        /// Exact value name.
        value: String,
        /// Expected ecosystem version.
        version: String,
    },
    /// One approved protected file and its expected version/hash.
    File {
        /// Scope of the protected target.
        scope: SoftwareTaskScope,
        /// Exact target path under the controlled install scope.
        path: String,
        /// Expected version.
        version: String,
        /// Expected complete file digest.
        sha256: [u8; 32],
    },
    /// Explicit approved bounded detection script.
    Script {
        /// Frozen script and artifact reference.
        command: SoftwareTaskScript,
    },
}
/// Single source of native dispatch and format-specific fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareTaskBehavior {
    /// Windows Installer.
    Msi(SoftwareTaskNative),
    /// macOS PackageInstaller.
    Pkg(SoftwareTaskNative),
    /// RSS approved script bundle.
    Bundle(SoftwareTaskBundleBehavior),
    /// Exact WinGet consumer behavior.
    Winget(SoftwareTaskNative),
    /// Exact Homebrew consumer behavior, always under a user.
    Brew(SoftwareTaskNative),
    /// Private full offline executable.
    Exe(SoftwareTaskExe),
    /// Precisely selected disk image payload.
    Dmg(SoftwareTaskDmg),
    /// Native Windows package deployment.
    Msix(SoftwareTaskMsix),
}
impl SoftwareTaskBehavior {
    /// Derived stable display identity, not an independent persisted format.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Msi(_) => "msi",
            Self::Pkg(_) => "pkg",
            Self::Bundle(_) => "bundle",
            Self::Winget(_) => "winget",
            Self::Brew(_) => "brew",
            Self::Exe(_) => "exe",
            Self::Dmg(_) => "dmg",
            Self::Msix(_) => "msix",
        }
    }
    /// Primary runtime artifact key is owned by the selected behavior.
    pub fn installer(&self) -> &str {
        match self {
            Self::Msi(n) | Self::Pkg(n) | Self::Winget(n) | Self::Brew(n) => &n.installer,
            Self::Exe(n) => &n.installer,
            Self::Bundle(b) => &b.archive,
            Self::Dmg(d) => &d.image,
            Self::Msix(m) => match &m.container {
                SoftwareTaskMsixContainer::Package { installer }
                | SoftwareTaskMsixContainer::Bundle { installer, .. } => installer,
            },
        }
    }
    /// Bundle metadata is only available from a Bundle behavior.
    pub fn bundle(&self) -> Option<&SoftwareTaskBundle> {
        if let Self::Bundle(b) = self {
            Some(&b.manifest)
        } else {
            None
        }
    }
    /// Required bounded installation invocation.
    pub fn invocation(&self) -> &SoftwareTaskInvocation {
        match self {
            Self::Msi(n) | Self::Pkg(n) | Self::Winget(n) | Self::Brew(n) => &n.install,
            Self::Exe(n) => &n.install,
            Self::Bundle(b) => &b.install.invocation,
            Self::Dmg(d) => &d.invocation,
            Self::Msix(m) => &m.invocation,
        }
    }
    /// Whether a complete explicit removal plan exists.
    pub fn supports_removal(&self) -> bool {
        match self {
            Self::Msi(n) | Self::Pkg(n) | Self::Winget(n) | Self::Brew(n) => n.uninstall.is_some(),
            Self::Exe(n) => n.uninstall.is_some(),
            Self::Bundle(b) => b.uninstall.is_some(),
            Self::Dmg(d) => match &d.payload {
                SoftwareTaskDmgPayload::AppCopy { uninstall, .. } => *uninstall,
                SoftwareTaskDmgPayload::ContainedPkg { uninstall, .. } => uninstall.is_some(),
            },
            Self::Msix(m) => m.uninstall,
        }
    }
}

/// Signature checks are opt-in and bound to complete approved material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskSignature {
    /// Runtime artifact key to which the check applies.
    pub artifact: String,
    /// Required platform trust mechanism.
    pub mechanism: SoftwareTaskSignatureMechanism,
    /// Exact Publisher/Team ID policy value.
    pub publisher: String,
}
/// Platform signature requirement; never an automatic enterprise approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskSignatureMechanism {
    /// Windows Authenticode policy.
    Authenticode,
    /// Apple Developer ID / system assessment.
    AppleDeveloperId,
    /// Windows package signature and certificate policy.
    Msix,
}

fn invalid() -> WireError {
    WireError::InvalidValue
}
fn text(s: &str, n: usize) -> Result<(), WireError> {
    if s.is_empty() || s.len() > n || s.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn relative(s: &str) -> Result<(), WireError> {
    text(s, 1024)?;
    if s.contains(['\\', ':'])
        || s.split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with([' ', '.']))
    {
        return Err(invalid());
    }
    Ok(())
}
fn invocation(v: &SoftwareTaskInvocation) -> Result<(), WireError> {
    if !(1..=86400).contains(&v.timeout_seconds)
        || !(1..=1_048_576).contains(&v.output_bytes)
        || v.arguments.len() > 128
        || v.environment.len() > 32
    {
        return Err(invalid());
    }
    if v.arguments
        .iter()
        .any(|a| a.len() > 4096 || a.contains('\0'))
        || v.exit_codes.success.is_empty()
        || v.exit_codes.success.len() + v.exit_codes.reboot.len() > 32
        || !v.exit_codes.success.is_disjoint(&v.exit_codes.reboot)
    {
        return Err(invalid());
    }
    if v.environment.iter().any(|(k, v)| {
        !k.starts_with("RSS_PARAM_")
            || k.len() > 128
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || v.len() > 4096
            || v.contains('\0')
    }) {
        return Err(invalid());
    }
    Ok(())
}
fn script(v: &SoftwareTaskScript) -> Result<(), WireError> {
    relative(&v.entry)?;
    invocation(&v.invocation)
}
fn detection(v: &SoftwareTaskDetection) -> Result<(), WireError> {
    match v {
        SoftwareTaskDetection::MsiProduct {
            product_code,
            version,
        } => {
            text(product_code, 38)?;
            text(version, 1024)
        }
        SoftwareTaskDetection::PkgReceipt { receipt, version } => {
            text(receipt, 255)?;
            text(version, 1024)
        }
        SoftwareTaskDetection::Registry {
            key,
            value,
            version,
            ..
        } => {
            text(key, 1024)?;
            text(value, 255)?;
            text(version, 1024)
        }
        SoftwareTaskDetection::File {
            path,
            version,
            sha256,
            ..
        } => {
            relative(path)?;
            text(version, 1024)?;
            if *sha256 == [0; 32] {
                return Err(invalid());
            }
            Ok(())
        }
        SoftwareTaskDetection::Script { command } => script(command),
    }
}
fn removal(v: &Option<SoftwareTaskRemoval>) -> Result<(), WireError> {
    if let Some(v) = v {
        text(&v.installer, 128)?;
        invocation(&v.invocation)?;
    }
    Ok(())
}
fn native_scope(
    scope: SoftwareTaskScope,
    install: &SoftwareTaskInvocation,
    upgrade: &SoftwareTaskInvocation,
    uninstall: &Option<SoftwareTaskRemoval>,
    policy: SoftwareTaskUpgrade,
) -> Result<(), WireError> {
    let run_as = match scope {
        SoftwareTaskScope::System => ExecutionIdentity::System,
        SoftwareTaskScope::User => ExecutionIdentity::LoggedInUser,
    };
    if install.run_as != run_as
        || upgrade.run_as != run_as
        || uninstall
            .as_ref()
            .is_some_and(|u| u.invocation.run_as != run_as)
        || policy == SoftwareTaskUpgrade::UninstallThenInstall && uninstall.is_none()
    {
        return Err(invalid());
    }
    Ok(())
}
fn identity(v: &SoftwareTaskMsixIdentity) -> Result<(), WireError> {
    text(&v.name, 255)?;
    text(&v.publisher, 1024)?;
    if v.resource_id.len() > 255 {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn validate_action(v: &super::SoftwareTaskAction) -> Result<(), WireError> {
    text(&v.package, 1024)?;
    text(&v.version, 1024)?;
    text(v.behavior.installer(), 128)?;
    invocation(v.behavior.invocation())?;
    if v.signatures.len() > 64 {
        return Err(invalid());
    }
    for s in &v.signatures {
        text(&s.artifact, 128)?;
        text(&s.publisher, 1024)?;
    }
    match &v.behavior {
        SoftwareTaskBehavior::Msi(n)
        | SoftwareTaskBehavior::Pkg(n)
        | SoftwareTaskBehavior::Winget(n)
        | SoftwareTaskBehavior::Brew(n) => {
            invocation(&n.upgrade_invocation)?;
            native_scope(
                n.scope,
                &n.install,
                &n.upgrade_invocation,
                &n.uninstall,
                n.upgrade,
            )?;
            detection(&n.detect)?;
            removal(&n.uninstall)
        }
        SoftwareTaskBehavior::Exe(n) => {
            invocation(&n.upgrade_invocation)?;
            native_scope(
                n.scope,
                &n.install,
                &n.upgrade_invocation,
                &n.uninstall,
                n.upgrade,
            )?;
            detection(&n.detect)?;
            removal(&n.uninstall)?;
            if n.layout.is_empty() || n.layout.len() > 64 {
                return Err(invalid());
            }
            for (path, key) in &n.layout {
                relative(path)?;
                text(key, 128)?;
            }
            Ok(())
        }
        SoftwareTaskBehavior::Bundle(b) => {
            if b.manifest.schema != 1
                || b.manifest.entries.is_empty()
                || b.manifest.entries.len() > 4096
            {
                return Err(invalid());
            }
            for path in b.manifest.entries.keys() {
                relative(path)?;
            }
            script(&b.install)?;
            if let Some(u) = &b.uninstall {
                script(u)?;
                if u.invocation.run_as != b.install.invocation.run_as {
                    return Err(invalid());
                }
            }
            detection(&b.detect)
        }
        SoftwareTaskBehavior::Dmg(d) => {
            text(&d.volume, 255)?;
            match &d.payload {
                SoftwareTaskDmgPayload::AppCopy { application, .. } => {
                    relative(&application.path)?;
                    relative(&application.target_name)?;
                    text(&application.bundle_id, 255)?;
                    text(&application.version, 1024)
                }
                SoftwareTaskDmgPayload::ContainedPkg {
                    path,
                    length,
                    sha256,
                    receipt,
                    uninstall,
                } => {
                    relative(path)?;
                    text(receipt, 255)?;
                    if *length == 0 || *sha256 == [0; 32] {
                        return Err(invalid());
                    }
                    if uninstall
                        .as_ref()
                        .is_some_and(|removal| removal.invocation.run_as != d.invocation.run_as)
                    {
                        return Err(invalid());
                    }
                    removal(uninstall)
                }
            }
        }
        SoftwareTaskBehavior::Msix(m) => {
            identity(&m.identity)?;
            if !m.invocation.arguments.is_empty()
                || !m.invocation.environment.is_empty()
                || !m.identity.resource_id.is_empty()
                || m.identity
                    .version
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(".")
                    != v.version
            {
                return Err(invalid());
            }
            match &m.deployment {
                SoftwareTaskMsixDeployment::DeviceProvisioning
                    if m.invocation.run_as != ExecutionIdentity::System || m.allow_unsigned =>
                {
                    return Err(invalid());
                }
                SoftwareTaskMsixDeployment::TargetUserRegistration { .. }
                    if m.invocation.run_as != ExecutionIdentity::LoggedInUser =>
                {
                    return Err(invalid());
                }
                _ => (),
            }
            if m.dependencies.len() > 32 {
                return Err(invalid());
            }
            for d in &m.dependencies {
                identity(d)?;
            }
            if let SoftwareTaskMsixContainer::Bundle { members, .. } = &m.container {
                if members.is_empty() || members.len() > 64 {
                    return Err(invalid());
                }
                for x in members {
                    relative(&x.path)?;
                    identity(&x.identity)?;
                    if x.length == 0 || x.sha256 == [0; 32] {
                        return Err(invalid());
                    }
                }
            }
            Ok(())
        }
    }
}

fn collect_detector<'a>(
    detector: &'a SoftwareTaskDetection,
    keys: &mut Vec<&'a str>,
    bundle: bool,
) {
    if let SoftwareTaskDetection::Script { command } = detector
        && !bundle
    {
        keys.push(&command.entry);
    }
}
fn collect_removal<'a>(value: &'a Option<SoftwareTaskRemoval>, keys: &mut Vec<&'a str>) {
    if let Some(r) = value {
        keys.push(&r.installer);
    }
}
/// Check every material reference within its own step, plus the real target platform.
pub(super) fn validate_step(
    step: &super::SoftwareTaskStep,
    index: usize,
    platform: TaskPlatform,
    arch: TaskArchitecture,
) -> Result<(), WireError> {
    let b = &step.action.behavior;
    let prefix = format!("{index}/");
    let available: BTreeSet<&str> = step
        .artifacts
        .iter()
        .map(|a| a.key.strip_prefix(&prefix).ok_or_else(invalid))
        .collect::<Result<_, _>>()?;
    let mut required = vec![b.installer()];
    for signature in &step.action.signatures {
        let supported = match signature.mechanism {
            SoftwareTaskSignatureMechanism::AppleDeveloperId => platform == TaskPlatform::Macos,
            SoftwareTaskSignatureMechanism::Authenticode => platform == TaskPlatform::Windows,
            SoftwareTaskSignatureMechanism::Msix => {
                platform == TaskPlatform::Windows
                    && matches!(b, SoftwareTaskBehavior::Msix(_))
                    && signature.artifact == b.installer()
            }
        };
        if !supported {
            return Err(invalid());
        }
        required.push(&signature.artifact);
    }
    let expected = match b {
        SoftwareTaskBehavior::Msi(n) | SoftwareTaskBehavior::Winget(n) => {
            collect_removal(&n.uninstall, &mut required);
            collect_detector(&n.detect, &mut required, false);
            TaskPlatform::Windows
        }
        SoftwareTaskBehavior::Pkg(n) | SoftwareTaskBehavior::Brew(n) => {
            collect_removal(&n.uninstall, &mut required);
            collect_detector(&n.detect, &mut required, false);
            TaskPlatform::Macos
        }
        SoftwareTaskBehavior::Exe(n) => {
            collect_removal(&n.uninstall, &mut required);
            collect_detector(&n.detect, &mut required, false);
            for value in n.layout.values() {
                required.push(value);
            }
            if n.layout.len() != available.len()
                || n.layout.values().collect::<BTreeSet<_>>().len() != n.layout.len()
            {
                return Err(invalid());
            }
            TaskPlatform::Windows
        }
        SoftwareTaskBehavior::Dmg(d) => {
            if let SoftwareTaskDmgPayload::ContainedPkg { uninstall, .. } = &d.payload {
                collect_removal(uninstall, &mut required);
            }
            TaskPlatform::Macos
        }
        SoftwareTaskBehavior::Msix(m) => {
            if !m.identity.architecture.matches(arch)
                || m.dependencies.iter().any(|d| !d.architecture.matches(arch))
                || matches!(&m.container,SoftwareTaskMsixContainer::Bundle{members,..} if members.iter().any(|member|!member.identity.architecture.matches(arch)))
            {
                return Err(invalid());
            }
            if let SoftwareTaskMsixContainer::Bundle { members, .. } = &m.container {
                let mut application = 0;
                let mut paths = BTreeSet::new();
                for member in members {
                    if !paths.insert(&member.path) {
                        return Err(invalid());
                    }
                    if member.identity.name != m.identity.name
                        || member.identity.publisher != m.identity.publisher
                        || member.identity.version != m.identity.version
                    {
                        return Err(invalid());
                    }
                    if member.identity.resource_id.is_empty() {
                        application += 1;
                        if member.identity != m.identity {
                            return Err(invalid());
                        }
                    }
                }
                if application != 1 {
                    return Err(invalid());
                }
            }
            TaskPlatform::Windows
        }
        SoftwareTaskBehavior::Bundle(bundle) => {
            if bundle.manifest.architecture != arch || available.len() != 1 {
                return Err(invalid());
            }
            if !bundle.manifest.entries.contains_key(&bundle.install.entry) {
                return Err(invalid());
            }
            if bundle
                .uninstall
                .as_ref()
                .is_some_and(|r| !bundle.manifest.entries.contains_key(&r.entry))
            {
                return Err(invalid());
            }
            bundle.manifest.platform
        }
    };
    if expected != platform || required.into_iter().any(|key| !available.contains(key)) {
        return Err(invalid());
    }
    Ok(())
}
