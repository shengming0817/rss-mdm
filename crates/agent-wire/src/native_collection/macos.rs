//! Closed macOS read recipes; execution and OS APIs belong to the independent Agent.
//! ref: osquery/osquery specs/darwin/{apps,package_receipts}.table@5.23.1
//! ref: Homebrew/brew Library/Homebrew/cmd/info.rb@7cce6eac8d897b0b8440e16f33dbcb21770da7cf
use super::{NativeCardinality, NativeType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One fixed hardware section; never a program name or system_profiler argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MacosHardwareSection {
    /// Hardware UUID, serial and model.
    Identity,
    /// OS name, version, build and native architecture.
    Os,
    /// Chip model and physical/logical cores.
    Cpu,
    /// Installed memory in bytes.
    Memory,
    /// Firmware version; unavailable versions are Missing.
    Firmware,
    /// Physical disks, counted independently of logical volumes.
    Disks,
    /// APFS capacity belongs to each container once, not to each sharing volume.
    ApfsContainers,
    /// Logical volumes and their container association; capacities are not additive.
    Volumes,
    /// Network interfaces and addresses; no location or traffic collection.
    Network,
    /// Battery charge percentage; no battery is Missing, never a fabricated zero.
    Battery,
}
impl MacosHardwareSection {
    /// Fixed row shape for this section.
    pub fn properties(self) -> BTreeMap<String, NativeType> {
        use NativeType::*;
        let fields = match self {
            Self::Identity => vec![
                ("hardware_uuid", String),
                ("serial", String),
                ("model", String),
            ],
            Self::Os => vec![
                ("name", String),
                ("version", String),
                ("build", String),
                ("architecture", String),
            ],
            Self::Cpu => vec![
                ("model", String),
                ("physical_cores", Integer),
                ("logical_cores", Integer),
            ],
            Self::Memory => vec![("total_bytes", UInt64)],
            Self::Firmware => vec![("version", String)],
            Self::Disks => vec![("id", String), ("model", String), ("size_bytes", UInt64)],
            Self::ApfsContainers => vec![
                ("id", String),
                ("size_bytes", UInt64),
                ("free_bytes", UInt64),
            ],
            Self::Volumes => vec![
                ("id", String),
                ("name", String),
                ("filesystem", String),
                ("container_id", String),
                ("size_bytes", UInt64),
                ("free_bytes", UInt64),
                ("system_volume", Boolean),
            ],
            Self::Network => vec![
                ("id", String),
                ("name", String),
                (
                    "addresses",
                    Array {
                        items: Box::new(String),
                    },
                ),
            ],
            Self::Battery => vec![("charge_percent", Number)],
        };
        fields.into_iter().map(|(k, v)| (k.into(), v)).collect()
    }
    /// Whether the section is a singleton or a complete bounded enumeration.
    pub fn cardinality(self) -> NativeCardinality {
        match self {
            Self::Disks | Self::ApfsContainers | Self::Volumes | Self::Network => {
                NativeCardinality::List
            }
            _ => NativeCardinality::ExactlyOne,
        }
    }
    pub(super) fn accepts_row(self, row: &BTreeMap<String, serde_json::Value>) -> bool {
        match self {
            Self::Cpu => ["physical_cores", "logical_cores"].iter().all(|key| {
                row.get(*key)
                    .is_some_and(|v| v.as_i64().is_some_and(|n| n > 0))
            }),
            Self::Battery => row
                .get("charge_percent")
                .is_some_and(|v| v.as_f64().is_some_and(|n| (0.0..=100.0).contains(&n))),
            Self::Os => row
                .get("architecture")
                .is_none_or(|v| matches!(v.as_str(), Some("x86_64" | "aarch64"))),
            Self::ApfsContainers => {
                let bytes = |key| {
                    row.get(key)
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                };
                matches!((bytes("size_bytes"), bytes("free_bytes")), (Some(size), Some(free)) if free <= size)
            }
            _ => true,
        }
    }
}

/// Approved application root. Resolve the user's home through the bound live identity.
/// Never traverse symlinks outside the root or recurse into discovered .app bundles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MacosApplicationRoot {
    /// /Applications.
    LocalApplications,
    /// /System/Applications.
    SystemApplications,
    /// Applications below the explicitly bound user's home.
    UserApplications,
}
/// Distinct installed Homebrew record kinds; casks do not prove an application exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MacosBrewPackage {
    /// Installed formula records.
    Formula,
    /// Installed cask records.
    Cask,
}
/// Lexical identity of an approved data root, not executable discovery or authority.
/// The Agent must separately verify the actual root and its trusted execution identity.
pub(super) fn absolute_data_root(path: &str) -> bool {
    path.len() <= 4096
        && path.starts_with('/')
        && !path.chars().any(char::is_control)
        && path[1..]
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
pub(super) fn tap_valid(tap: &str) -> bool {
    tap.len() <= 255
        && tap.split('/').count() == 2
        && tap.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}

// These columns map onto the existing Inventory software fields; extra native evidence
// remains a separately authorized query result, not a second asset model.
pub(super) fn software_properties(extra: &[(&str, NativeType)]) -> BTreeMap<String, NativeType> {
    [
        "id",
        "native_id",
        "name",
        "version",
        "publisher",
        "scope",
        "owner",
        "origin",
        "location",
    ]
    .into_iter()
    .map(|key| (key.into(), NativeType::String))
    .chain(extra.iter().map(|(key, ty)| ((*key).into(), ty.clone())))
    .collect()
}
