//! Inventory field policy, independent of storage and fixture authorization.
use rss_observation::{Batch, Coverage, Error, ErrorKind, Id};

pub const DATASET: &str = "inventory";

/// The product field catalog. Protocol adapters map URIs to these keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKey {
    Model,
    OsVersion,
}
impl FieldKey {
    pub const ALL: [Self; 2] = [Self::Model, Self::OsVersion];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "device.model",
            Self::OsVersion => "device.os.version",
        }
    }
    pub fn validate(self, value: &str) -> bool {
        !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }
}

pub fn coverage() -> Coverage {
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(id("device-basics"), id("1"), id("model-os"), id("utf8-v1"))
}

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
