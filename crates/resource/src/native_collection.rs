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
    WindowsCsp,
    /// Apple DeviceInformation with an explicit query list.
    AppleDeviceInformation,
    /// Apple InstalledApplicationList with typed item projection.
    AppleInstalledApplications,
}
/// One native response extraction; list columns map canonical properties to item JSON pointers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMapping {
    /// CSP URI or DeviceInformation query key; empty for InstalledApplicationList.
    pub query: String,
    /// JSON pointer relative to the query result, or command response for application lists.
    pub pointer: String,
    /// Empty for direct values; otherwise each selected array item becomes this closed object.
    pub columns: BTreeMap<String, String>,
}
/// Complete native collection interface, owned by the same Resource version lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCollectionSpec {
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
fn pointer(value: &str) -> bool {
    if value.len() > 4096
        || (!value.is_empty() && !value.starts_with('/'))
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}
impl NativeCollectionDefinition {
    /// Reject unbounded mappings and unsupported native queries before publication.
    pub fn new(spec: NativeCollectionSpec) -> Result<Self, Error> {
        if spec.mappings.is_empty()
            || spec.mappings.len() > 64
            || !(1..=3600).contains(&spec.timeout_seconds)
            || !(1..=16_777_216).contains(&spec.output_bytes)
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
                || !pointer(&mapping.pointer)
                || mapping.columns.len() > 64
            {
                return Err(Error::InvalidInput);
            }
            for (key, path) in &mapping.columns {
                if key.is_empty()
                    || key.len() > 64
                    || !key.as_bytes()[0].is_ascii_lowercase()
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    || !pointer(path)
                {
                    return Err(Error::InvalidInput);
                }
            }
            match spec.adapter {
                NativeAdapter::WindowsCsp => {
                    if mapping.query.len() > 1024
                        || !["./DevInfo/", "./DevDetail/", "./Vendor/MSFT/"]
                            .iter()
                            .any(|p| mapping.query.starts_with(p))
                        || mapping.query.split('/').any(|p| p.is_empty() || p == "..")
                        || !mapping.query.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'-')
                        })
                    {
                        return Err(Error::InvalidInput);
                    }
                }
                NativeAdapter::AppleDeviceInformation => {
                    if !matches!(
                        mapping.query.as_str(),
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
                    ) {
                        return Err(Error::InvalidInput);
                    }
                }
                NativeAdapter::AppleInstalledApplications => {
                    if !mapping.query.is_empty()
                        || mapping.pointer != "/InstalledApplicationList"
                        || mapping.columns.is_empty()
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
            (NativeAdapter::WindowsCsp, Platform::Windows)
                | (
                    NativeAdapter::AppleDeviceInformation
                        | NativeAdapter::AppleInstalledApplications,
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
