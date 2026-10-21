//! Immutable history policy versions; asset values never acquire a TTL.
use crate::{Invalid, Result};
/// Product retention periods, referenced by exact key/version from a field binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionPolicy {
    /// Tenant-local stable policy key.
    pub key: String,
    /// Immutable positive version.
    pub revision: u64,
    /// Raw sample retention measured from observation time.
    pub raw_seconds: u32,
    /// Materialized summary retention; cannot be shorter than raw retention.
    pub summary_seconds: u32,
    /// Maximum recoverable deletion interval; cannot exceed raw retention.
    pub restore_seconds: u32,
}
impl RetentionPolicy {
    /// Validate closed policy parameters without consulting a database.
    pub fn validate(&self) -> Result<()> {
        if self.key.is_empty()
            || self.key.len() > 64
            || !self.key.as_bytes()[0].is_ascii_lowercase()
            || !self
                .key
                .bytes()
                .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'_')
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.raw_seconds == 0
            || self.summary_seconds < self.raw_seconds
            || self.restore_seconds > self.raw_seconds
        {
            return Err(Invalid::Value);
        }
        Ok(())
    }
}
