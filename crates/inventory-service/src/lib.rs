//! Inventory application ownership: durable intake, observations, assets and assessments.
pub mod collection;
pub mod collection_service;
mod database;
mod error;
pub mod inventory_runtime;
mod operations;
mod wake;
pub use database::Store;
pub use error::{Error, Failure};
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::device;

pub mod assets;
pub mod clock;
pub mod compliance;
pub mod operation;
pub mod tasks;
pub mod transaction;

pub mod groups;

pub mod apple_collection;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

/// Verify the inventory and compliance storage contracts on the caller's transaction.
pub async fn admit_storage_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
) -> Result<(), sqlx::Error> {
    rss_mdm_inventory_postgres::verify_watermark_fence(c).await?;
    rss_mdm_compliance_postgres::admit(c, tenant).await
}
