#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
//! Sole durable owner of software publication decisions and attempt history.
mod codec;

mod error;
mod event;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use rss_mdm_software_release as core;
pub use store::*;
/// Exact final schema migration. Execute only through the privileged host migrator after RSS messaging prerequisites.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
pub(crate) const STORAGE: BackendStorage = BackendStorage::new(BackendKind::SoftwareRelease);
pub(crate) const ADMISSION: Admission = Admission {
    tables: &["aggregates", "immutable", "requests"],
    update_columns: &[
        "aggregates.revision",
        "aggregates.document",
        "aggregates.digest",
    ],
    catalog: include_str!("catalog.json"),
};

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/0002_outbox_writer.sql");
