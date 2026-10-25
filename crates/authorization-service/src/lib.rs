//! Product authorization owns grants, snapshots and durable user authorization evidence.
mod actor;
mod authority;
pub use actor::Actor;
pub mod api_key;
pub mod api_key_store;
pub mod context;
pub mod credential;
mod database;
pub mod directory;
pub mod error;
mod evaluate;
pub mod identity_management;
mod model;
pub mod network_policy;
mod operations;
pub mod store;
pub use authority::OperationAuthority;
pub use database::Store;
pub use error::Error;
#[cfg(test)]
use evaluate::department_matches;
pub use evaluate::{Snapshot, SubjectFacts};
pub use model::*;
pub use store::{lock as lock_on, snapshot_on};
#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

pub mod session;
pub mod tenancy;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    include_str!("../schema/authority.sql")
);
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod baseline;
pub mod initialization;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub mod entra;
