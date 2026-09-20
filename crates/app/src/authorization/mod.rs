//! Persistent MDM authorization. Identity facts supply subjects, never product permissions.
mod evaluate;
mod http;
mod initialize;
mod model;
mod store;
pub(crate) use evaluate::Snapshot;
#[cfg(test)]
use evaluate::department_matches;
pub(crate) use http::routes;
pub use initialize::{Initialize, initialize};
pub use model::*;
#[cfg(test)]
mod tests;
