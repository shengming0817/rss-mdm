#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
//! Policy persistence; caller-authorized snapshots, one storage CAS and no device dispatch.
mod codec;

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
/// Exact final schema migration. Execute only through the privileged host migrator after RSS messaging prerequisites.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");

use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
pub(crate) const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Policy);
pub(crate) const ADMISSION: Admission = Admission {
    tables: &["aggregates", "facts", "immutable", "requests"],
    update_columns: &[
        "aggregates.revision",
        "aggregates.document",
        "aggregates.digest",
        "facts.document",
        "facts.digest",
    ],
    catalog: include_str!("catalog.json"),
};
