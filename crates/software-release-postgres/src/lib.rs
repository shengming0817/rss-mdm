//! Sole durable owner of software publication decisions and attempt history.
mod codec;
mod db;
mod error;
mod event;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use rss_mdm_software_release as core;
pub use store::*;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
