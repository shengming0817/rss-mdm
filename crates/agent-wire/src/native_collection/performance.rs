//! Closed native performance observations; platform execution belongs to the Agent.
//! ref: GuillaumeGomez/sysinfo src/unix/apple/cpu.rs@v0.37.2
//! ref: GuillaumeGomez/sysinfo src/windows/cpu.rs@v0.37.2
use super::{NativeCardinality, NativeType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum monotonic interval between the two CPU reads within one query.
/// The executor waits this fixed interval; scheduling may make it longer, within the query budget.
/// No caller-supplied sampling window, API name, executable or counter path is accepted.
pub const PERFORMANCE_CPU_SAMPLE_MILLIS: u64 = 250;

/// Fixed performance sections shared by platform-specific native engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceSection {
    /// Device-wide busy percentage: 100 * delta busy / delta total, normalized across CPUs.
    /// Read twice within one query, at least PERFORMANCE_CPU_SAMPLE_MILLIS apart.
    /// A changed boot/counter domain, regressing counters, zero total delta or busy delta
    /// above total is Missing, never a fabricated zero or a clamped percentage.
    Cpu,
    /// Physical total and currently available memory in bytes; available does not exceed total.
    Memory,
    /// Complete bounded filesystem enumeration, not physical disks or additive APFS capacity.
    /// Preserve the provider's stable volume identity; never use enumeration position.
    /// Shared-container capacities are observations per filesystem and must not be summed.
    FileSystems,
    /// Complete bounded interface enumeration with cumulative received/sent byte counters.
    /// Preserve stable native interface identities; never use enumeration position or counters
    /// as identity. Counters may reset on reboot/interface recreation; they are not byte rates.
    Network,
}
impl PerformanceSection {
    /// Canonical row properties. Every declared property is required for a usable row.
    pub fn properties(self) -> BTreeMap<String, NativeType> {
        use NativeType::*;
        let fields = match self {
            Self::Cpu => vec![("busy_percent", Number)],
            Self::Memory => vec![("total_bytes", UInt64), ("available_bytes", UInt64)],
            Self::FileSystems => vec![
                ("id", String),
                ("total_bytes", UInt64),
                ("free_bytes", UInt64),
            ],
            Self::Network => vec![
                ("id", String),
                ("received_bytes", UInt64),
                ("sent_bytes", UInt64),
            ],
        };
        fields.into_iter().map(|(k, v)| (k.into(), v)).collect()
    }

    /// Single device observation or independently keyed complete enumeration.
    pub fn cardinality(self) -> NativeCardinality {
        match self {
            Self::Cpu | Self::Memory => NativeCardinality::ExactlyOne,
            Self::FileSystems | Self::Network => NativeCardinality::List,
        }
    }

    pub(super) fn instance_keys_match(self, keys: &[String]) -> bool {
        match self.cardinality() {
            NativeCardinality::ExactlyOne => keys.is_empty(),
            NativeCardinality::List => keys.len() == 1 && keys[0] == "id",
        }
    }

    pub(super) fn accepts_row(self, row: &BTreeMap<String, serde_json::Value>) -> bool {
        if !self
            .properties()
            .iter()
            .all(|(key, ty)| row.get(key).is_some_and(|value| ty.accepts(value)))
        {
            return false;
        }
        let bytes = |key| {
            row.get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
        };
        let valid_id = || {
            row.get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| !id.is_empty() && !id.chars().any(char::is_control))
        };
        match self {
            Self::Cpu => row["busy_percent"]
                .as_f64()
                .is_some_and(|v| (0.0..=100.0).contains(&v)),
            Self::Memory => matches!(
                (bytes("total_bytes"), bytes("available_bytes")),
                (Some(total), Some(available)) if total > 0 && available <= total
            ),
            Self::FileSystems => {
                valid_id()
                    && matches!(
                        (bytes("total_bytes"), bytes("free_bytes")),
                        (Some(total), Some(free)) if free <= total
                    )
            }
            Self::Network => valid_id(),
        }
    }
}
