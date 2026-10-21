//! Registration-scoped loss diagnostics, never field coverage or sample authority.
use super::WireError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Complete encoded report ceiling, independent of sample batch size.
pub const TELEMETRY_GAP_MAX_BYTES: usize = 4096;
/// Fixed acceptance and idempotency window from the immutable report creation time.
pub const TELEMETRY_GAP_WINDOW_MICROS: i64 = 7 * 86400 * 1_000_000;

/// Closed loss causes; no caller-authored descriptions or sampled values.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryGapReason {
    /// Buffered observations exceeded their retention window.
    Expired,
    /// Storage or execution capacity prevented sampling or preservation.
    Capacity,
    /// The sampling lease expired.
    Lease,
    /// Local power policy suspended sampling.
    Power,
    /// Sleep or scheduling delay skipped sampling instants.
    Suspended,
    /// UTC continuity was lost.
    Clock,
    /// The collector was unavailable, unsupported or failed.
    Collection,
    /// A permanently rejected sample batch was isolated.
    Rejected,
    /// The original registration incarnation was retired.
    Registration,
    /// Configuration withdrawal or replacement interrupted sampling.
    Configuration,
}
/// A count with a time span, not a claim of continuous absence or exact field coverage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryGap {
    /// Loss category.
    pub reason: TelemetryGapReason,
    /// Missed or discarded observation count; reasons need not represent disjoint windows.
    pub count: u64,
    /// Earliest known UTC microsecond.
    pub first: i64,
    /// Latest known UTC microsecond.
    pub last: i64,
}
/// Frozen report retried byte-for-byte until its durable receipt or acceptance expiry.
/// Tenant/device come from mTLS, not this input. Registration fields prevent rebinding old loss.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryGapReport {
    /// Stable idempotency identity.
    pub report_id: uuid::Uuid,
    /// Original registration, including during credential renewal.
    pub registration_id: uuid::Uuid,
    /// Original registration generation.
    pub generation: u64,
    /// Immutable report creation UTC microsecond; never renewed on retry.
    pub created_at: i64,
    /// At most one aggregate per closed reason.
    pub gaps: Vec<TelemetryGap>,
}
impl TelemetryGapReport {
    /// Structural validation; current device authority and receiver time remain server-owned.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.report_id.is_nil()
            || self.registration_id.is_nil()
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.created_at <= 0
            || self
                .created_at
                .checked_add(TELEMETRY_GAP_WINDOW_MICROS)
                .is_none()
            || self.gaps.is_empty()
            || self.gaps.len() > 10
        {
            return Err(WireError::InvalidValue);
        }
        let mut reasons = BTreeSet::new();
        for gap in &self.gaps {
            if !reasons.insert(gap.reason)
                || gap.count == 0
                || gap.count > i64::MAX as u64
                || gap.first < 0
                || gap.last < gap.first
                || gap.last == i64::MAX
            {
                return Err(WireError::InvalidValue);
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| WireError::InvalidValue)?
            .len()
            > TELEMETRY_GAP_MAX_BYTES
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Only a committed diagnostic receipt; it does not confirm any sample or Inventory update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryGapReceipt {
    /// Original immutable report identity.
    pub report_id: uuid::Uuid,
    /// First durable receipt UTC microsecond.
    pub received_at: i64,
    /// The same report was already stored within its acceptance window.
    pub replayed: bool,
}
