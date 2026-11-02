//! Channel-neutral registration identity, credential binding and retirement.
pub mod admission;
pub mod agent;
pub mod certificate_issuance;
mod database;
pub mod device;
pub mod enrollment;
mod error;
pub mod lifecycle;
pub mod operations;
pub mod quotas;
pub mod windows_entra;
pub mod windows_receipts;
pub use database::Store;
pub use device::{
    ChannelMount, DevicePrincipal, DeviceService, Purpose, VerifiedChannelCredential,
};
pub use error::Error;
pub use lifecycle::{Retirement, retire};
use rss_mdm_authorization_service as authorization;

/// Fresh product schema owned by this capability.
pub const AGENT_NATIVE_SQL: &str = include_str!("../schema/agent-native.sql");
pub const fn agent_bootstrap_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).agent_bootstrap
}
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).install
}
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const fn relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).relations
}

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;

/// Current quota schema; installation remains fresh-only.
pub const fn quotas_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).quotas
}

/// Registration settings and reusable administrator configurations.
pub const fn agent_configurations_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).agent_configurations
}

/// Windows operation receipts owned by registration; install after the Windows schema namespace.
pub const WINDOWS_RECEIPTS_SQL: &str = include_str!("../schema/windows-receipts.sql");
/// Current Entra registration policy, before native consent tables.
pub const WINDOWS_ENTRA_POLICY_SQL: &str = include_str!("../schema/windows-entra-policy.sql");

/// Dynamic new-registration admission schema.
pub const fn admission_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).admission
}

mod webhook;
pub use webhook::{EventSink, WebhookEvents};

/// Fixed read relation used by authorized same-database directory queries.
pub const fn directory_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).directory
}

mod storage_authority;
pub use storage_authority::{verify_authority, verify_common_authority};

pub mod command_authority;
pub const COMMAND_AUTHORITIES_SQL: &str = include_str!("../schema/command-authorities.sql");

pub mod installation;

pub const NATIVE_TASKS_SQL: &str = include_str!("../schema/tasks/installation.sql");
pub const TASKS_RELATIONS_SQL: &str = include_str!("../schema/tasks/relations.sql");

pub mod participants;

mod storage_profile;

pub const fn enrollment_tasks_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).enrollment_tasks
}

/// Shared Agent task relationships and retirement fence.
pub const fn task_relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).task_relations
}
pub const fn enrollment_retirement_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).enrollment_retirement
}

pub const fn member_authority_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).member_authority
}

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).access_contract
}
pub const fn enrollment_access_contract(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).enrollment_access_contract
}

/// Core identity objects installed independently of Agent/native execution participants.
pub const fn identity_object_manifest(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).identity_object_manifest
}

/// Privileges of the core identity install without optional execution owners.
pub const fn identity_access_contract(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).identity_access_contract
}

pub const DA_IDENTITY_PROJECTION_MANIFEST: &str =
    r#"{"tables":[],"functions":["rss_da.current_da_registration"],"views":[]}"#;
