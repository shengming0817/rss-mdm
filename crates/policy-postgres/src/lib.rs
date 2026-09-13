//! Policy persistence; caller-authorized snapshots, one storage CAS and no device dispatch.
mod codec;
mod db;
mod error;
mod event;
mod model;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use model::*;
pub use rss_mdm_policy as core;
pub use store::PolicyStore;
/// Bound on a single planning transaction; history is never silently truncated.
pub const MAX_FACTS: usize = 10_000;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");
