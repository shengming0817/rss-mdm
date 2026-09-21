//! Persistent MDM authorization. Identity facts supply subjects, never product permissions.
mod approval;
mod evaluate;
pub(crate) use approval::Approval;
pub(crate) use store::{lock as lock_on, snapshot_on};
mod http;
mod initialize;
mod model;
mod store;
pub(crate) use evaluate::Snapshot;
#[cfg(test)]
use evaluate::department_matches;
pub(crate) use http::routes;
#[cfg(test)]
pub(crate) use initialize::bounded as bounded_initialization;
pub use initialize::{Initialize, initialize};
pub use model::*;
#[cfg(test)]
mod tests;
