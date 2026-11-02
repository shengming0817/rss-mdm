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
pub use evaluate::{EffectiveGrant, Snapshot, SubjectFacts};
pub use model::*;
pub use store::{lock as lock_on, lock_shared as lock_shared_on, snapshot_on};
#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

pub mod session;
pub mod tenancy;

/// Fresh product schema owned by this capability.
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).install
}
pub const fn authority_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).authority
}
pub const fn relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).relations
}

pub mod baseline;
pub mod initialization;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;

pub mod entra;

mod storage_authority;
pub use storage_authority::{verify_authority, verify_authority_for_host};

pub mod native;

mod storage_profile;

pub mod installation;

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).access_contract
}
