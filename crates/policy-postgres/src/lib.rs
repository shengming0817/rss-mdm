//! Unified Policy persistence. The host owns authorization, Scope, resources and delivery.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
mod error;
mod store;
pub use error::*;
pub use rss_mdm_policy as core;
pub use store::*;
/// Initialization schema for a new deployment; no old lifecycle tables are retained.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");
/// Existing RSS runtime writer capability used to bind borrowed transactions.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/0002_outbox_writer.sql");
use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Policy);
const ADMISSION: Admission = Admission {
    tables: &["policies", "requests", "triggers", "versions"],
    update_columns: &[
        "policies.revision",
        "policies.current_version",
        "policies.version_number",
        "policies.enabled",
        "policies.definition",
        "policies.author",
        "policies.updated_at",
    ],
    catalog: include_str!("catalog.json"),
};
