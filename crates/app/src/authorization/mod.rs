//! Persistent MDM authorization. Identity facts supply subjects, never product permissions.
pub(crate) mod admission;
mod authority;
pub(crate) mod context;
pub(crate) mod error;
mod evaluate;
pub(crate) mod identity_management;
pub(crate) use authority::ExecutionAuthority;
pub(crate) use store::{lock as lock_on, snapshot_on};
pub(crate) mod http;
mod initialize;
mod model;
pub(crate) mod store;
pub(crate) use evaluate::Snapshot;
#[cfg(test)]
use evaluate::department_matches;
pub(crate) use http::routes;
#[cfg(test)]
pub(crate) use initialize::bounded as bounded_initialization;
pub use initialize::{Initialize, initialize};
pub use model::*;
#[cfg(test)]
#[path = "../../tests/authorization/unit.rs"]
mod tests;

pub(crate) const AUTHORIZATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0010_authorization.sql");

#[cfg(test)]
#[path = "../../tests/authorization/mod.rs"]
pub(crate) mod t2;
