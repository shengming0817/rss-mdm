//! PostgreSQL Inventory projection, schema and runtime privilege checks.
mod admission;
mod inventory;
pub use admission::verify as verify_admission;
pub use inventory::{Inventory, definition, projection_scope};
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_inventory.sql");

mod reader;
pub use reader::{InventoryField, InventoryReader, read_in};
pub const READER_MIGRATION_SQL: &str = include_str!("../migrations/0002_inventory_api_reader.sql");
