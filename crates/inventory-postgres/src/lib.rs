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
mod inventory;
pub use admission::verify as verify_admission;
pub use inventory::{Inventory, definition, projection_scope};
/// Owner-executed Inventory table, identity and tenant-isolation migration SQL.
/// Embedding the SQL does not apply it; runtime credentials must not own the schema.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_inventory.sql");

mod reader;
pub use reader::{InventoryField, InventoryReader, read_in};
/// Owner-executed migration defining the restricted Inventory API reader role.
pub const READER_MIGRATION_SQL: &str = include_str!("../migrations/0002_inventory_api_reader.sql");

/// Fresh-install asset schema, applied after the original Inventory units.
pub const ASSETS_MIGRATION_SQL: &str = include_str!("../migrations/0003_assets.sql");
/// Atomic asset history and durable input records; no scheduling or lease ownership.
pub const HISTORY_MIGRATION_SQL: &str = include_str!("../migrations/0004_history.sql");
mod manual;
pub use manual::{Assignment, assign_in, manual_in};
mod history;
pub use history::{manual_at_in, read_at_in, watermark_in};

/// Fixed enterprise task field catalog and typed storage bounds.
pub const ENTERPRISE_MIGRATION_SQL: &str = include_str!("../migrations/0005_enterprise.sql");

/// Consumer publication fencing; grants no ability to change canonical facts.
pub const WATERMARK_FENCE_MIGRATION_SQL: &str =
    include_str!("../migrations/0006_watermark_fence.sql");
/// Lock the tenant's committed asset watermark until the caller transaction settles.
/// Must be called before consumer publication locks and input validation.
pub async fn lock_watermark_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(tenant.to_string())
        .fetch_one(c)
        .await
}
/// Verify the exact privileged fencing function and its fixed execution environment.
pub async fn verify_watermark_fence(
    c: &mut sqlx::PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    let source = WATERMARK_FENCE_MIGRATION_SQL
        .split_once("AS $$")
        .expect("fixed migration")
        .1
        .split_once("END $$;")
        .expect("fixed migration")
        .0
        .to_owned()
        + "END ";
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='mdm.lock_asset_watermark(uuid)'::regprocedure AND p.prosecdef AND p.provolatile='v' AND NOT p.proleakproof AND p.prorettype='bigint'::regtype AND p.proconfig=ARRAY['search_path=pg_catalog, mdm'] AND p.prosrc=$1 AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql') AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='mdm.asset_clock'::regclass) AND NOT pg_has_role(current_user,p.proowner,'MEMBER') AND has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR (a.is_grantable AND a.grantee<>p.proowner)))")
 .bind(source).fetch_one(c).await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "asset watermark fence contract".into(),
        ));
    }
    Ok(())
}
