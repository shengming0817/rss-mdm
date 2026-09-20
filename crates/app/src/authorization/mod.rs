//! Persistent MDM authorization. Identity facts supply subjects, never product permissions.
mod evaluate;
mod http;
mod model;
mod store;
pub(crate) use evaluate::Snapshot;
#[cfg(test)]
use evaluate::department_matches;
pub(crate) use http::routes;
pub use model::*;
pub use store::{Initialize, initialize};
#[cfg(test)]
mod tests;
