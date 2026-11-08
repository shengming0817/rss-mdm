//! Product recovery material ownership; execution and platform channels retain their lifecycles.
//! ref: rust-openssl openssl-v0.10.81 openssl/src/cms.rs.
pub mod directory;
pub mod filevault;
mod filevault_service;
pub use filevault_service::{FilevaultService, Link as FilevaultLink, filevault_operation_receipt};
mod model;
mod protection;
mod service;
pub mod storage;
pub use model::*;
pub use protection::{KeyRing, Protection, Recipient};
pub use service::{Credentials, DisclosureRequest};
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).install
}
pub const fn tasks_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).tasks
}
pub const NATIVE_SQL: &str = concat!(
    include_str!("../schema/native.sql"),
    "\n",
    include_str!("../schema/filevault.sql"),
    "\n",
    include_str!("../schema/task-relations.sql")
);
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;

pub mod cleanup;
pub mod lock_pin;
pub mod maintenance;
pub mod native;
pub mod native_receipts;
pub mod tasks;

mod storage_admission;
pub use storage_admission::{verify_agent_authority, verify_storage};

pub mod eligibility;
pub use eligibility::Custody;

mod storage_profile;

/// Product credential task relationships and retirement authority.
/// DA tasks require the product's explicit Agent delivery installation.
pub const fn task_relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    match profile {
        rss_mdm_install_support::StorageProfile::Mdm => {
            storage_profile::sql(profile).task_relations
        }
        rss_mdm_install_support::StorageProfile::Da => {
            include_str!("../schema/da-task-relations.sql")
        }
    }
}

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    match profile {
        rss_mdm_install_support::StorageProfile::Da => include_str!("../schema/da-objects.json"),
        rss_mdm_install_support::StorageProfile::Mdm => {
            storage_profile::sql(profile).object_manifest
        }
    }
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    match profile {
        rss_mdm_install_support::StorageProfile::Da => include_str!("../schema/da-access.json"),
        rss_mdm_install_support::StorageProfile::Mdm => {
            storage_profile::sql(profile).access_contract
        }
    }
}

#[cfg(unix)]
pub mod configuration;
