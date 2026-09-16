#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//! Immutable Resource versions and lifecycle over the host-owned RSS transaction.
mod codec;

mod error;
mod event;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use rss_mdm_resource as core;
pub use store::*;
/// Exact final schema migration. Execute only through the privileged host migrator after RSS messaging prerequisites.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");

use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
pub(crate) const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Resource);
pub(crate) const ADMISSION: Admission = Admission {
    tables: &["aggregates", "immutable", "requests"],
    update_columns: &[
        "aggregates.revision",
        "aggregates.document",
        "aggregates.digest",
    ],
    catalog: include_str!("catalog.json"),
};
