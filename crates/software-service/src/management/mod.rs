//! Software management use cases; HTTP projection and process assembly remain outside.
pub mod catalog;
pub mod content;
pub mod directory;
pub mod installers;
pub mod publication;
pub(crate) mod transaction;
pub use transaction::Fault;
mod error;
pub use error::{Error, Failure};
pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Option<i64>;
}

#[cfg(test)]
#[path = "../../tests/management/publication.rs"]
mod publication_contract;

pub(crate) fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}

/// Stored operation/read JSON is decoded before becoming the actual HTTP response serializer.
fn projection<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::SoftwareCatalogInvariant))
}

pub mod resource;
