#![deny(missing_docs)]
//! Inventory field policy, independent of storage and fixture authorization.
//!
//! [`coverage`] identifies the fixed device-basics contract. [`validate`] checks
//! batch coverage and values without changing the batch, reading storage or
//! authenticating its producer. Observation owns stream ordering and completeness;
//! the product adapter owns trusted device/source binding and persistence.
use rss_observation::{Batch, Coverage, Error, ErrorKind, Id};

/// Observation dataset name selected by the Inventory projection.
pub const DATASET: &str = "inventory";

/// The product field catalog. Protocol adapters map URIs to these keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKey {
    /// Product model text, mapped to `device.model`.
    Model,
    /// Operating-system version text, mapped to `device.os.version`.
    OsVersion,
}
impl FieldKey {
    /// Complete supported field catalog in model/OS-version order.
    pub const ALL: [Self; 2] = [Self::Model, Self::OsVersion];
    /// Return the canonical Observation key for this field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "device.model",
            Self::OsVersion => "device.os.version",
        }
    }
    /// Accept nonblank text of at most 256 UTF-8 bytes without control characters.
    /// Does not trim or normalize the stored value; both fields use the same rules.
    pub fn validate(self, value: &str) -> bool {
        !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }
}

/// Return fixed `device-basics` / `1` / `model-os` / `utf8-v1` coverage identities.
/// Construction performs no I/O and makes no assertion about a particular report.
pub fn coverage() -> Coverage {
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(id("device-basics"), id("1"), id("model-os"), id("utf8-v1"))
}

/// Validate the fixed coverage, known field keys and present UTF-8 values.
/// Rejects unknown keys, mismatched coverage, invalid UTF-8 or values failing
/// [`FieldKey::validate`] with `rss_observation::ErrorKind::InvalidInput`.
/// Deletions carry no value to validate. Does not mutate or authenticate the batch.
pub fn validate(batch: &Batch) -> Result<(), Error> {
    if batch.coverage() != &coverage() {
        return Err(ErrorKind::InvalidInput.into());
    }
    for change in batch.body().changes() {
        let field = FieldKey::ALL
            .into_iter()
            .find(|key| key.as_str() == change.key().as_str())
            .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?;
        if let Some(value) = change.value() {
            let text =
                std::str::from_utf8(value).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
            if !field.validate(text) {
                return Err(ErrorKind::InvalidInput.into());
            }
        }
    }
    Ok(())
}
