//! Immutable Resource versions and lifecycle over the host-owned RSS transaction.
mod codec;
mod db;
mod error;
mod event;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use rss_mdm_resource as core;
pub use store::*;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");
