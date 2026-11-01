//! Inventory application ownership: durable intake, observations, assets.
pub mod collection;
mod database;
mod error;
pub mod inventory_runtime;
mod operations;
mod wake;
mod worker_health;
pub use database::Store;
pub use error::{Error, Failure};
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::device;
pub use worker_health::{WorkerAttempt, WorkerScan, WorkerStatus};

pub mod assets;
pub mod clock;
pub mod operation;
pub mod tasks;
pub mod transaction;

pub mod objects;

pub mod apple_collection;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/collection-tasks.sql"),
    "\n",
    include_str!("../schema/task-retirement.sql")
);
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = concat!(
    include_str!("../schema/relations.sql"),
    "\n",
    include_str!("../schema/collection-task-relations.sql")
);

/// Verify the inventory storage contracts on the caller's transaction.
pub async fn admit_storage_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    _tenant: rss_request_context::TenantId,
) -> Result<(), sqlx::Error> {
    verify_authority(profile, c).await?;
    rss_mdm_inventory_postgres::verify_collections(c)
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("collection storage admission: {error}")))?;
    rss_mdm_inventory_postgres::verify_asset_history(c).await?;
    if !sqlx::query_scalar::<_, bool>(assets::ADMISSION_SQL)
        .fetch_one(c)
        .await?
    {
        return Err(sqlx::Error::Protocol(
            "inventory asset storage admission".into(),
        ));
    }
    Ok(())
}

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;

/// Current scalar sources and hardware-key qualification used by association writers.
pub const SOURCE_FACTS_SQL: &str = include_str!("../schema/source-facts.sql");

/// Current scalar directory fields resolved before search and pagination.
pub const DIRECTORY_SQL: &str = include_str!("../schema/directory.sql");
pub const fn read_snapshot_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).read_snapshot_install
}

pub(crate) fn query_error(error: rss_mdm_query::Error) -> Error {
    match error {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}

mod storage_authority;
pub use storage_authority::verify_authority;

#[cfg(test)]
#[path = "../tests/collection_templates.rs"]
mod collection_templates_tests;

mod storage_profile;

/// Shared durable collection intake, independently installed from the MDM asset query application.
pub const fn collection_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).collection
}
pub const fn collection_metadata_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).collection_metadata
}
pub const fn collection_relations_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).collection_relations
}

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).access_contract
}

pub const fn ingestion_grants_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).ingestion_grants
}
