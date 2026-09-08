//! PostgreSQL Inventory projection, schema and runtime privilege checks.
mod admission;
mod inventory;
pub use admission::verify as verify_admission;
pub use inventory::{Inventory, definition};
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_inventory.sql");
