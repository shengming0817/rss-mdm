//! Inventory-owned history binding and immutable metric semantics.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
/// Numeric interpretation is immutable for a field identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryKind {
    /// Instantaneous numeric observation.
    Gauge,
    /// Nonnegative value since an explicit reset boundary.
    CumulativeCounter,
    /// Nonnegative contribution over an explicit interval.
    DeltaCounter,
    /// Boolean or declared finite string vocabulary.
    State,
}
/// Operations are selected explicitly; missing data is never filled implicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryAggregation {
    /// Minimum numeric reading.
    Min,
    /// Maximum numeric reading.
    Max,
    /// Sum of Gauge readings or Delta contributions.
    Sum,
    /// Number of known readings.
    Count,
    /// Numeric arithmetic mean.
    Mean,
    /// Cumulative increase between compatible boundaries.
    Increase,
    /// Contribution divided by its actual duration.
    Rate,
    /// Finite state intervals.
    Timeline,
    /// State changes.
    Transitions,
    /// Explicitly covered duration.
    Coverage,
}
/// One bounded dimension extracted from a declared object property path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryDimension {
    /// Literal property names relative to each selected item, not executable expressions.
    pub path: Vec<String>,
    /// Closed admitted vocabulary, including numeric dimensions rendered canonically.
    pub values: BTreeSet<String>,
}
/// Product retention policy identity; duration is owned by its immutable policy version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionReference {
    /// Tenant-local policy key.
    pub key: String,
    /// Exact policy revision.
    pub revision: u64,
}
/// A field's optional history capability, validated against the Inventory catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeSeriesBinding {
    /// Numeric or finite-state interpretation.
    pub kind: TelemetryKind,
    /// Scalar property path; an array root is expanded using the field's stable item key.
    pub value_path: Vec<String>,
    /// Counter start in UTC microseconds, extracted per item for structured counters.
    pub interval_start_path: Option<Vec<String>>,
    /// Closed dimensions. Device/resource/source identities are not arbitrary dimensions.
    pub dimensions: BTreeMap<String, TelemetryDimension>,
    /// Explicit operations permitted for this field.
    pub aggregations: BTreeSet<TelemetryAggregation>,
    /// Versioned product policy, never an asset TTL.
    pub retention: RetentionReference,
    /// Maximum expanded resources per device and field.
    pub max_resources: u32,
}
fn name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.as_bytes()[0].is_ascii_lowercase()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn path(v: &[String]) -> bool {
    v.len() <= 6 && v.iter().all(|s| name(s))
}
impl TimeSeriesBinding {
    /// Validate bounded declarations; this does not grant field/source access.
    pub fn validate(&self) -> crate::Result<()> {
        use TelemetryAggregation as A;
        if !path(&self.value_path)
            || self.interval_start_path.as_ref().is_some_and(|v| {
                v.is_empty()
                    || !path(v)
                    || !matches!(
                        self.kind,
                        TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter
                    )
            })
            || self.dimensions.len() > 64
            || self.aggregations.is_empty()
            || !name(&self.retention.key)
            || self.retention.revision == 0
            || self.retention.revision > i64::MAX as u64
            || !(1..=4096).contains(&self.max_resources)
        {
            return Err(crate::Invalid::Value);
        }
        let mut combinations = u64::from(self.max_resources);
        let mut vocabulary_bytes = 0usize;
        for (key, dimension) in &self.dimensions {
            if !name(key)
                || dimension.path.is_empty()
                || !path(&dimension.path)
                || dimension.values.is_empty()
                || dimension.values.len() > 256
            {
                return Err(crate::Invalid::Value);
            }
            combinations = combinations
                .checked_mul(dimension.values.len() as u64)
                .ok_or(crate::Invalid::Value)?;
            for value in &dimension.values {
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(crate::Invalid::Value);
                }
                vocabulary_bytes += value.len();
            }
        }
        if combinations > 4096 || vocabulary_bytes > 32768 {
            return Err(crate::Invalid::Value);
        }
        if self.aggregations.iter().any(|operation| !match self.kind {
            TelemetryKind::Gauge => {
                matches!(operation, A::Min | A::Max | A::Sum | A::Count | A::Mean)
            }
            TelemetryKind::CumulativeCounter => matches!(operation, A::Increase | A::Rate),
            TelemetryKind::DeltaCounter => matches!(operation, A::Sum | A::Rate),
            TelemetryKind::State => matches!(operation, A::Timeline | A::Transitions | A::Coverage),
        }) {
            return Err(crate::Invalid::Value);
        }
        Ok(())
    }
}
