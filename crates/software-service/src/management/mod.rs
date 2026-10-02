//! Software management use cases; HTTP projection and process assembly remain outside.
pub mod catalog;
pub mod content;
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
