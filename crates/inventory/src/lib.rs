//! Inventory field policy, independent of storage and fixture authorization.
use rss_observation::{Batch, Coverage, Error, ErrorKind, Id};

pub const DATASET: &str = "inventory";

pub fn coverage() -> Coverage {
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(id("device-basics"), id("1"), id("model-os"), id("utf8-v1"))
}

pub fn validate(batch: &Batch) -> Result<(), Error> {
    if batch.coverage() != &coverage() {
        return Err(ErrorKind::InvalidInput.into());
    }
    for change in batch.body().changes() {
        if !matches!(change.key().as_str(), "device.model" | "device.os.version") {
            return Err(ErrorKind::InvalidInput.into());
        }
        if let Some(value) = change.value() {
            let text =
                std::str::from_utf8(value).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
            if text.trim().is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
                return Err(ErrorKind::InvalidInput.into());
            }
        }
    }
    Ok(())
}
