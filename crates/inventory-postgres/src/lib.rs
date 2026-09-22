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
