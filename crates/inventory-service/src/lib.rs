//! Inventory application ownership: durable intake, observations, assets and assessments.
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
pub mod compliance;
pub mod operation;
pub mod tasks;
pub mod transaction;

pub mod groups;
pub mod objects;

pub mod apple_collection;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = concat!(
    include_str!("../schema/install.sql"),
    "\n",
    include_str!("../schema/collection-metadata.sql")
);
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

/// Verify the inventory and compliance storage contracts on the caller's transaction.
pub async fn admit_storage_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
) -> Result<(), sqlx::Error> {
    verify_authority(c).await?;
    rss_mdm_inventory_postgres::verify_collections(c)
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("collection storage admission: {error}")))?;
    rss_mdm_inventory_postgres::verify_watermark_fence(c).await?;
    rss_mdm_compliance_postgres::admit(c, tenant).await?;
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
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub const GROUP_SELECTIONS_SQL: &str = include_str!("../schema/group-selections.sql");

/// Current scalar sources and hardware-key qualification used by association writers.
pub const SOURCE_FACTS_SQL: &str = include_str!("../schema/source-facts.sql");

/// Current scalar directory fields resolved before search and pagination.
pub const DIRECTORY_SQL: &str = concat!(
    include_str!("../schema/directory.sql"),
    "\n",
    include_str!("../schema/read-snapshot.sql")
);

pub(crate) fn query_error(error: rss_mdm_query::Error) -> Error {
    match error {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}

mod storage_authority;
pub use storage_authority::verify_authority;
