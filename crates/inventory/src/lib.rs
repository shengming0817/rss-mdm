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

mod assets;
mod catalog;
pub use assets::{Evidence, KnownValue, ResolvedField, Scalar, SourceFact, State, resolve};
pub use catalog::{DICTIONARY, FieldDefinition, FieldKey, Kind, Operator};
/// Closed, value-free diagnostic for malformed asset input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid asset input")
    }
}
impl std::error::Error for Invalid {}
/// Product asset policy result.
pub type Result<T> = std::result::Result<T, Invalid>;

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
pub fn validate(batch: &Batch) -> std::result::Result<(), Error> {
    if batch.coverage() != &coverage() {
        return Err(ErrorKind::InvalidInput.into());
    }
    for change in batch.body().changes() {
        let field = FieldKey::observed()
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
