//! Product authorization owns grants, snapshots and durable user approval evidence.
mod authority;
pub mod context;
mod database;
pub mod error;
mod evaluate;
pub mod identity_management;
mod model;
mod operations;
pub mod store;
pub use authority::UserGrant;
pub use database::Store;
pub use error::Error;
pub use evaluate::Snapshot;
#[cfg(test)]
use evaluate::department_matches;
pub use model::*;
pub use store::{lock as lock_on, snapshot_on};
#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

pub mod session;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod initialization;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
