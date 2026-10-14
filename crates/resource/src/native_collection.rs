//! Published native read templates; channel adapters alone construct protocol commands.
//! ref: apple/device-management mdm/commands/information.device.yaml, application.installed.list.yaml.
//! ref: Microsoft Learn windows/client-management/mdm/devdetail-csp.
use crate::{Error, Platform};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Read-only protocol adapter, never an arbitrary native command name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAdapter {
    /// SyncML Get over an explicit device CSP URI.
    WindowsRead,
    /// Apple DeviceInformation with an explicit query list.
    AppleDeviceInformation,
    /// Apple InstalledApplicationList with typed item projection.
    AppleInstalledApplications,
    /// Read-only security facts, with secrets removed at the protocol boundary.
    AppleSecurity,
    /// Profile metadata in the exact managed-only namespace.
    AppleProfiles,
    /// Certificate metadata in the exact managed-only namespace.
    AppleCertificates,
    /// Active account metadata; supported only on supervised device channels.
    AppleUsers,
}
/// Platform-owned query. Apple keys retain their protocol meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NativeQuery {
    /// Explicit typed Windows read; strings are never accepted as Windows queries.
    Windows(WindowsRead),
    /// Apple command query key.
    Apple(String),
}
/// Closed Windows collection operations; all protocol commands are Get.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsRead {
    /// One explicitly named scalar leaf.
    Scalar {
        /// Exact readable leaf URI.
        uri: String,
    },
    /// Identifier from the authenticated management provider.
    EnrollmentId,
    /// Registration type from the authenticated management provider.
    EnrollmentType,
    /// One complete native namespace with a fixed, bounded traversal recipe.
    Inventory {
        /// Exact native namespace to enumerate.
        inventory: WindowsInventory,
    },
}
/// Independently complete native namespaces, never a claim of all installed software.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsInventory {
    /// Win32InstalledProgram records.
    Win32,
    /// Store packages.
    Store,
    /// Non-Store packages.
    NonStore,
    /// System packages.
    System,
    /// DeviceStatus network identifiers.
    Network,
    /// Installed update identities.
    InstalledUpdates,
    /// Applicable uninstalled update identities.
    InstallableUpdates,
    /// Failed update identities and native failure codes.
    FailedUpdates,
    /// Updates awaiting reboot.
    PendingRebootUpdates,
}
impl NativeQuery {
    /// Apple query identity, unavailable for Windows declarations.
    pub fn apple_key(&self) -> Option<&str> {
        match self {
            Self::Apple(key) => Some(key),
            Self::Windows(_) => None,
        }
    }
}
/// One native response extraction; list columns map canonical properties to item JSON pointers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMapping {
    /// CSP URI or DeviceInformation query key; empty for InstalledApplicationList.
    pub query: NativeQuery,
    /// Shared typed extraction and conversion.
    pub mapping: crate::ValueMapping,
}
/// Complete native collection interface, owned by the same Resource version lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCollectionSpec {
    /// Exact immutable collection namespace.
    pub scope: crate::TemplateScope,
    /// Exact additional endpoint prerequisites.
    pub applicability: crate::Applicability,
    /// Closed native read protocol.
    pub adapter: NativeAdapter,
    /// Inventory field identities and response mappings, frozen at publication.
    pub mappings: BTreeMap<String, NativeMapping>,
    /// Current run deadline in seconds.
    pub timeout_seconds: u32,
    /// Maximum accepted aggregate result bytes.
    pub output_bytes: u32,
}
/// Validated, immutable native template; it carries neither actor authority nor approval state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NativeCollectionSpec", into = "NativeCollectionSpec")]
pub struct NativeCollectionDefinition(NativeCollectionSpec);
impl From<NativeCollectionDefinition> for NativeCollectionSpec {
    fn from(v: NativeCollectionDefinition) -> Self {
        v.0
    }
}
impl TryFrom<NativeCollectionSpec> for NativeCollectionDefinition {
    type Error = Error;
    fn try_from(v: NativeCollectionSpec) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl NativeCollectionDefinition {
    /// Reject unbounded mappings and unsupported native queries before publication.
    pub fn new(spec: NativeCollectionSpec) -> Result<Self, Error> {
        spec.applicability.validate()?;
        spec.scope
            .validate_executable()
            .map_err(|_| Error::InvalidInput)?;
        if spec.mappings.is_empty()
            || spec.mappings.len() > 64
            || !(1..=3600).contains(&spec.timeout_seconds)
            || !(1..=16_777_216).contains(&spec.output_bytes)
        {
            return Err(Error::InvalidInput);
        }
        if matches!(spec.scope, crate::TemplateScope::User { .. })
            && matches!(
                spec.adapter,
                NativeAdapter::WindowsRead | NativeAdapter::AppleUsers
            )
        {
            return Err(Error::InvalidInput);
        }
        for (field, mapping) in &spec.mappings {
            if field.len() > 128
                || !["device.", "custom.", "channel."]
                    .iter()
                    .any(|p| field.starts_with(p))
                || !field.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.')
                })
                || mapping.mapping.validate().is_err()
                || mapping.mapping.columns.len() > 64
            {
                return Err(Error::InvalidInput);
            }
            match spec.adapter {
                NativeAdapter::WindowsRead => {
                    let NativeQuery::Windows(read) = &mapping.query else {
                        return Err(Error::InvalidInput);
                    };
                    if let WindowsRead::Scalar { uri } = read
                        && (uri.contains("/DMClient/")
                            || uri.len() > 1024
                            || ![
                                "./DevInfo/",
                                "./DevDetail/",
                                "./Vendor/MSFT/",
                                "./Device/Vendor/MSFT/",
                            ]
                            .iter()
                            .any(|p| uri.starts_with(p))
                            || uri.split('/').any(|p| p.is_empty() || p == "..")
                            || !uri.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'-')
                            }))
                    {
                        return Err(Error::InvalidInput);
                    }
                }
                NativeAdapter::AppleDeviceInformation => {
                    if !matches!(
                        mapping.query.apple_key().ok_or(Error::InvalidInput)?,
                        "Model"
                            | "ModelName"
                            | "ModelNumber"
                            | "ProductName"
                            | "OSVersion"
                            | "BuildVersion"
                            | "DeviceName"
                            | "SerialNumber"
                            | "IsAppleSilicon"
                            | "DeviceCapacity"
                            | "AvailableDeviceCapacity"
                            | "WiFiMAC"
                            | "EthernetMACs"
                            | "HostName"
                            | "LocalHostName"
                            | "SystemIntegrityProtectionEnabled"
                            | "IsActivationLockEnabled"
                            | "IsDeviceLocatorServiceEnabled"
                            | "BatteryLevel"
                            | "IsSupervised"
                            | "IsMDMLostModeEnabled"
                            | "AwaitingConfiguration"
                            | "SupplementalBuildVersion"
                            | "SupplementalOSVersionExtra"
                    ) {
                        return Err(Error::InvalidInput);
                    }
                }
                NativeAdapter::AppleSecurity => {
                    if !matches!(
                        mapping.query.apple_key(),
                        Some(
                            "FDE_Enabled"
                                | "FDE_HasPersonalRecoveryKey"
                                | "FDE_HasInstitutionalRecoveryKey"
                                | "SystemIntegrityProtectionEnabled"
                                | "FirewallSettings"
                                | "SecureBoot"
                                | "ManagementStatus"
                                | "FirmwarePasswordStatus"
                                | "IsRecoveryLockEnabled"
                                | "BootstrapTokenAllowedForAuthentication"
                                | "BootstrapTokenRequiredForSoftwareUpdate"
                                | "BootstrapTokenRequiredForKernelExtensionApproval"
                        )
                    ) {
                        return Err(Error::InvalidInput);
                    }
                }
                NativeAdapter::AppleInstalledApplications
                | NativeAdapter::AppleProfiles
                | NativeAdapter::AppleCertificates
                | NativeAdapter::AppleUsers => {
                    if mapping.query.apple_key() != Some("")
                        || mapping.mapping.pointer != "/items"
                        || !mapping.mapping.columns.is_empty()
                    {
                        return Err(Error::InvalidInput);
                    }
                }
            }
        }
        if serde_json::to_vec(&spec)
            .map_err(|_| Error::InvalidInput)?
            .len()
            > 65536
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self(spec))
    }
    /// Borrow the exact validated declaration.
    pub fn spec(&self) -> &NativeCollectionSpec {
        &self.0
    }
    /// Bind the native protocol to its actual supported operating system.
    pub fn validate_platform(&self, platform: Platform) -> Result<(), Error> {
        if matches!(
            (self.0.adapter, platform),
            (NativeAdapter::WindowsRead, Platform::Windows)
                | (
                    NativeAdapter::AppleDeviceInformation
                        | NativeAdapter::AppleInstalledApplications
                        | NativeAdapter::AppleSecurity
                        | NativeAdapter::AppleProfiles
                        | NativeAdapter::AppleCertificates
                        | NativeAdapter::AppleUsers,
                    Platform::MacOS
                )
        ) {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
    /// Canonical artifact content for immutable template publication.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("closed template")
    }
}

impl NativeAdapter {
    /// Exact native command identity; arbitrary commands cannot enter collection templates.
    pub fn apple_command(self) -> Option<&'static str> {
        Some(match self {
            Self::WindowsRead => return None,
            Self::AppleDeviceInformation => "DeviceInformation",
            Self::AppleInstalledApplications => "InstalledApplicationList",
            Self::AppleSecurity => "SecurityInfo",
            Self::AppleProfiles => "ProfileList",
            Self::AppleCertificates => "CertificateList",
            Self::AppleUsers => "UserList",
        })
    }
    /// Envelope rights; query-specific and field conditions are also checked by native schema.
    pub fn apple_rights(self) -> Option<i32> {
        Some(match self {
            Self::WindowsRead => return None,
            Self::AppleDeviceInformation => 16,
            Self::AppleInstalledApplications => 256,
            Self::AppleSecurity => 1024,
            Self::AppleProfiles | Self::AppleCertificates => 1,
            Self::AppleUsers => 0,
        })
    }
    /// Stable capability exposed to template applicability.
    pub fn capability(self) -> &'static str {
        match self {
            Self::WindowsRead => "windows_read",
            Self::AppleDeviceInformation => "apple_device_information",
            Self::AppleInstalledApplications => "apple_installed_applications",
            Self::AppleSecurity => "apple_security",
            Self::AppleProfiles => "apple_profiles",
            Self::AppleCertificates => "apple_certificates",
            Self::AppleUsers => "apple_users",
        }
    }
}
