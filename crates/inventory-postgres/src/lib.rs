#![deny(missing_docs)]
//! PostgreSQL Inventory projection, schema and runtime privilege checks.
//!
//! Install the component migrations through the product migration owner, then
//! [`verify_admission`] before accepting projection work. [`Inventory`] applies
//! validated Observation facts inside the projection owner's transaction; it does
//! not commit. [`InventoryReader`] owns its pool and read transactions, while
//! [`read_in`] borrows the host's tenant transaction. Resource authorization,
//! scheduling, migration execution and recovery policy remain with the product.
mod admission;
mod cut;
pub use cut::{ASSET_CUT_SQL, capture_asset_cut, capture_asset_cut_on_read, verify_asset_history};
pub mod arrays;
mod inventory;
pub use admission::{verify as verify_admission, verify_collections};
pub use inventory::{Inventory, definition, projection_scope};
/// Owner-executed Inventory table, identity and tenant-isolation migration SQL.
/// Embedding the SQL does not apply it; runtime credentials must not own the schema.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/install.sql"),
    include_str!("../migrations/arrays.sql"),
    include_str!("../migrations/asset-cuts.sql")
);

mod reader;
pub use reader::{InventoryFacts, InventoryField, InventoryReader, read_in};
/// Return only presence for selected current scopes and manual device facts.
/// The product caller supplies the authoritative registration/source mapping.
pub async fn directory_presence_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    scopes: Vec<String>,
    devices: Vec<String>,
) -> Result<(Vec<String>, Vec<String>), sqlx::Error> {
    let projection = projection_scope(tenant);
    let row: (Vec<String>, Vec<String>) = sqlx::query_as("SELECT ARRAY(SELECT DISTINCT scope FROM mdm.inventory WHERE tenant_id=$1::uuid AND journal=$4 AND generation=$5 AND field_scope='{\"kind\":\"device\"}' AND scope=ANY($2)), ARRAY(SELECT DISTINCT device FROM mdm.manual_assignments WHERE tenant_id=$1::uuid AND device=ANY($3))")
        .bind(tenant.to_string()).bind(scopes).bind(devices)
        .bind(projection.source().source()).bind(projection.generation()).fetch_one(c).await?;
    Ok(row)
}
/// Owner-executed migration defining the restricted Inventory API reader role.
pub const READER_MIGRATION_SQL: &str = include_str!("../migrations/reader.sql");

mod manual;
pub use manual::{Assignment, assign_in};
mod history;
pub use history::{manual_scalars_at_in, read_scalars_at_in};

mod catalog;
pub use catalog::{
    catalog_at_in, catalog_in, collection_in, collection_version_in, datasets_in, field_version_in,
    historical_field_in, initialize_fields_in, lock_catalog_read_in, lock_catalog_write_in,
    publish_field_in, register_collection_in, retire_field_in, tenant_seed_sql,
    time_series_versions_in,
};

mod results;
pub use results::{CollectionCompletion, collection_result_in, seal_collection_in};

pub use catalog::admit_time_series_fields_in;

mod retention;
pub use retention::{publish_retention_policy_in, retention_policy_in};

pub use retention::minimum_restore_seconds_in;

pub mod snapshot;
mod snapshot_record;
