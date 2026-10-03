//! Finite behavior values; native executors are derived, never separately selectable.
use super::*;

/// Install scope is separate from the process identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareScope {
    /// Organization device installation.
    System,
    /// One authenticated interactive user.
    User,
}
/// Approved upgrade mechanism; no mutable command discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareUpgrade {
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
pub struct ExitCodePolicy {
    /// Process success, still requiring independent effect detection.
    pub success: BTreeSet<i32>,
    /// Successful process completion requiring reboot.
    pub reboot: BTreeSet<i32>,
}
/// Literal invocation of the native installer chosen by the enclosing behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeInvocation {
    /// Process identity, never inferred from installation scope.
    pub run_as: RunAs,
    /// Literal arguments; no shell or mutable registry command.
    pub arguments: Vec<String>,
    /// Product-prefixed environment values.
    pub environment: BTreeMap<String, String>,
    /// Wall-time ceiling.
    pub timeout_seconds: u32,
    /// Combined output ceiling.
    pub output_bytes: u32,
    /// Explicit return-code classification.
    pub exit_codes: ExitCodePolicy,
}
/// Script implementations only appear in declared Bundle entries or detectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareInterpreter {
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
pub struct SoftwareScript {
    /// Finite interpreter.
    pub interpreter: SoftwareInterpreter,
    /// Artifact key or Bundle member.
    pub entry: String,
    /// Literal bounded invocation.
    pub invocation: NativeInvocation,
}
/// Native removal executes an explicitly approved artifact, never a discovered path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemoval {
    /// Artifact key of the approved removal installer.
    pub installer: String,
    /// Removal-specific literal parameters and return codes.
    pub invocation: NativeInvocation,
}
/// Native installer material shared only where its values have identical meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSoftware {
    /// Installer artifact key.
    pub installer: String,
    /// Actual installation scope.
    pub scope: SoftwareScope,
    /// Unattended installation invocation.
    pub install: NativeInvocation,
    /// Separately approved upgrade invocation and return-code policy.
    pub upgrade_invocation: NativeInvocation,
    /// Explicit upgrade policy.
    pub upgrade: SoftwareUpgrade,
    /// Absent means removal is unsupported, never guessed.
    #[serde(deserialize_with = "required_removal")]
    pub uninstall: Option<NativeRemoval>,
    /// Independent observation of effect.
    pub detect: SoftwareDetection,
}
/// Complete offline EXE layout, including companion payload files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExeSoftware {
    /// Approved EXE installer key.
    pub installer: String,
    /// Explicit system/user installation scope.
    pub scope: SoftwareScope,
    /// Unattended installation; no default /S or /silent.
    pub install: NativeInvocation,
    /// Separately approved upgrade invocation and return-code policy.
    pub upgrade_invocation: NativeInvocation,
    /// Approved replacement sequence.
    pub upgrade: SoftwareUpgrade,
    /// Explicit removal installer and invocation.
    #[serde(deserialize_with = "required_removal")]
    pub uninstall: Option<NativeRemoval>,
    /// Staging relative path to artifact key; no runtime downloads are authorized.
    pub layout: BTreeMap<String, String>,
    /// Independent identity/version detector.
    pub detect: SoftwareDetection,
}
/// RSS ZIP with approved finite script entries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSoftware {
    /// ZIP artifact key.
    pub archive: String,
    /// Exact complete manifest.
    pub manifest: BundleManifest,
    /// Frozen install entry.
    pub install: SoftwareScript,
    /// Frozen removal entry, when supported.
    #[serde(deserialize_with = "required_removal")]
    pub uninstall: Option<SoftwareScript>,
    /// Independent effect observation.
    pub detect: SoftwareDetection,
}
/// Exact application identity retained independently of image identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacApplication {
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
pub enum DmgPayload {
    /// Copy/replace one declared application; removal requires the declared exact target.
    AppCopy {
        /// Full declared app material.
        application: MacApplication,
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
        #[serde(deserialize_with = "required_removal")]
        uninstall: Option<NativeRemoval>,
    },
}
/// One selected volume and payload in an immutable disk image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DmgSoftware {
    /// Image artifact key.
    pub image: String,
    /// Exact selected volume label; ambiguous multi-volume images are unsupported.
    pub volume: String,
    /// System or target user's Applications directory.
    pub scope: SoftwareScope,
    /// Approved operation identity and budgets.
    pub invocation: NativeInvocation,
    /// Explicit replacement policy.
    pub upgrade: SoftwareUpgrade,
    /// Exact selected payload.
    pub payload: DmgPayload,
}
/// MSIX material architecture, distinct from the device processor architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsixArchitecture {
    /// Native x64 application or resource material.
    X86_64,
    /// Native ARM64 application or resource material.
    Aarch64,
    /// Architecture-independent MSIX material, including language/resource packages.
    Neutral,
}
impl MsixArchitecture {
    /// Whether this material can execute on the exact selected hardware profile.
    pub fn matches(self, architecture: Architecture) -> bool {
        self == Self::Neutral
            || matches!(
                (self, architecture),
                (Self::X86_64, Architecture::X86_64) | (Self::Aarch64, Architecture::Aarch64)
            )
    }
}
/// MSIX identity uses Windows' own version and Publisher semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsixIdentity {
    /// Manifest Name.
    pub name: String,
    /// Exact manifest Publisher DN; not a generic display publisher.
    pub publisher: String,
    /// Exact four-part package version.
    pub version: [u16; 4],
    /// Selected processor architecture.
    pub architecture: MsixArchitecture,
    /// Exact resource identity; empty denotes the application package.
    pub resource_id: String,
}
/// Frozen .msixbundle member and its complete bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsixMember {
    /// Exact relative container member path.
    pub path: String,
    /// Exact package identity.
    pub identity: MsixIdentity,
    /// Member byte length.
    pub length: u64,
    /// Member digest.
    pub sha256: [u8; 32],
}
/// One MSIX or a precisely selected application/resource bundle member set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MsixContainer {
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
        members: Vec<MsixMember>,
    },
}
/// Approved target selector; actual user identity is frozen into a device task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareUser {
    /// Only a unique interactive user; missing/multiple sessions block execution.
    ActiveInteractive,
    /// One exact local Windows SID or macOS uid, rechecked by the Agent.
    Exact {
        /// Platform-local stable identity.
        identity: String,
    },
}
/// Registration and provisioning are different effects, including on removal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MsixDeployment {
    /// Install/register and remove for one exact user.
    TargetUserRegistration {
        /// Approved user selection.
        target: SoftwareUser,
    },
    /// Provision/deprovision the device's future-user package set.
    DeviceProvisioning,
}
/// Complete MSIX execution prerequisites and precise package identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsixSoftware {
    /// Frozen package/container bytes.
    pub container: MsixContainer,
    /// Expected application identity.
    pub identity: MsixIdentity,
    /// Exact installed/provisioned dependency identities; matched to catalog dependencies.
    pub dependencies: Vec<MsixIdentity>,
    /// Windows package target effect.
    pub deployment: MsixDeployment,
    /// Minimum Windows OS version.
    pub minimum_os: [u16; 4],
    /// Sideloading must already be permitted; tasks do not enable it.
    pub require_sideload: bool,
    /// Hash-only content still needs explicit native unsigned API support if unsigned.
    pub allow_unsigned: bool,
    /// Whether exact removal/deprovisioning is supported.
    pub uninstall: bool,
    /// Frozen runtime identity and budgets; deployment does not accept arbitrary switches.
    pub invocation: NativeInvocation,
    /// Approved update sequence.
    pub upgrade: SoftwareUpgrade,
}
/// Independent finite detector; an exit code is never a detector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareDetection {
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
        scope: SoftwareScope,
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
        scope: SoftwareScope,
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
        command: SoftwareScript,
    },
}
/// Single source of native dispatch and format-specific fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareBehavior {
    /// Windows Installer.
    Msi(NativeSoftware),
    /// macOS PackageInstaller.
    Pkg(NativeSoftware),
    /// RSS approved script bundle.
    Bundle(BundleSoftware),
    /// Exact WinGet consumer behavior.
    Winget(NativeSoftware),
    /// Exact Homebrew consumer behavior, always under a user.
    Brew(NativeSoftware),
    /// Private full offline executable.
    Exe(ExeSoftware),
    /// Precisely selected disk image payload.
    Dmg(DmgSoftware),
    /// Native Windows package deployment.
    Msix(MsixSoftware),
}
impl SoftwareBehavior {
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
                MsixContainer::Package { installer } | MsixContainer::Bundle { installer, .. } => {
                    installer
                }
            },
        }
    }
    /// Bundle metadata is only available from a Bundle behavior.
    pub fn bundle(&self) -> Option<&BundleManifest> {
        if let Self::Bundle(b) = self {
            Some(&b.manifest)
        } else {
            None
        }
    }
    /// Required bounded installation invocation.
    pub fn invocation(&self) -> &NativeInvocation {
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
                DmgPayload::AppCopy { uninstall, .. } => *uninstall,
                DmgPayload::ContainedPkg { uninstall, .. } => uninstall.is_some(),
            },
            Self::Msix(m) => m.uninstall,
        }
    }
}
/// Raw material retained by the existing content owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSourceFile {
    /// Exact source-relative path.
    pub path: String,
    /// Complete immutable bytes; not part of the runtime artifact set.
    pub content: SoftwareArtifact,
}
/// Imported evidence is part of the definition, never a mutable second catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareProvenance {
    /// Private authoring with explicit immutable behavior.
    Private,
    /// Exact source material and implementation version.
    Imported {
        /// Fixed commit or digest-qualified REST snapshot.
        snapshot: String,
        /// Exact converter identity/version.
        converter: String,
        /// Full original selected manifest file set.
        files: Vec<SoftwareSourceFile>,
    },
}
/// Signature checks are opt-in and bound to complete approved material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareSignature {
    /// Runtime artifact key to which the check applies.
    pub artifact: String,
    /// Required platform trust mechanism.
    pub mechanism: SignatureMechanism,
    /// Exact Publisher/Team ID policy value.
    pub publisher: String,
}
/// Platform signature requirement; never an automatic enterprise approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureMechanism {
    /// Windows Authenticode policy.
    Authenticode,
    /// Apple Developer ID / system assessment.
    AppleDeveloperId,
    /// Windows package signature and certificate policy.
    Msix,
}
/// Only metadata needed to derive an optional native document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareExport {
    /// Internal enterprise software with no native publication.
    Disabled,
    /// WinGet metadata; installer semantics come from behavior.
    Winget {
        /// Default package locale.
        locale: String,
        /// Display name.
        name: String,
        /// Display publisher, distinct from signature policy.
        publisher: String,
        /// Short description.
        description: String,
        /// License text/identifier.
        license: String,
    },
    /// Brew metadata and exact bottle/Cask export coordinates.
    Brew {
        /// Display name.
        name: String,
        /// Description.
        description: String,
        /// Approved homepage.
        homepage: String,
        /// Precisely declared native view details.
        payload: BrewExport,
    },
}
/// Bottle/Cask parameters belong to the frozen definition, not a second editable Recipe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BrewExport {
    /// Exact app or PKG Cask payload path.
    Cask {
        /// Selected image/archive-relative payload.
        path: String,
        /// Exact receipt identities for PKG; empty for AppCopy.
        receipts: Vec<String>,
    },
    /// Approved bottle, never a source build fallback.
    Bottle {
        /// Runtime bottle artifact key.
        artifact: String,
        /// Original source archive key, retained as material but never built.
        source: String,
        /// Exact Homebrew platform tag.
        tag: String,
        /// Original bottle cellar policy.
        cellar: String,
        /// Formula revision.
        revision: u32,
        /// Bottle rebuild.
        rebuild: u32,
        /// Exact prebuilt executable name.
        executable: String,
    },
}

fn required_removal<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
