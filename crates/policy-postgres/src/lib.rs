#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
//! Policy persistence; caller-authorized snapshots, one storage CAS and no device dispatch.
mod codec;

mod candidates;
mod error;
mod event;
mod model;
mod pages;
pub use pages::{CandidateIntent, CandidateIntentRow, IntentKind, IntentPosition};
mod store;
pub use candidates::{Candidate, CandidatePhase, CandidateRequest};
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use model::*;
pub use rss_mdm_policy as core;
pub use store::PolicyStore;
/// Exact final schema migration. Execute only through the privileged host migrator after RSS messaging prerequisites.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001.sql");

use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
pub(crate) const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Policy);
pub(crate) const ADMISSION: Admission = Admission {
    tables: &[
        "aggregates",
        "candidate_intents",
        "candidate_pages",
        "candidate_references",
        "candidate_targets",
        "candidates",
        "current_plans",
        "facts",
        "immutable",
        "reference_heads",
        "requests",
    ],
    update_columns: &[
        "aggregates.revision",
        "aggregates.document",
        "aggregates.digest",
        "facts.document",
        "facts.digest",
        "reference_heads.revision",
        "reference_heads.required_input",
        "reference_heads.observed_input",
        "candidates.phase",
        "candidates.target_cursor",
        "candidates.fact_cursor",
        "candidates.target_count",
        "candidates.fact_count",
        "candidates.target_root",
        "candidates.fact_root",
        "candidates.plan_id",
        "current_plans.candidate",
    ],
    catalog: include_str!("catalog.json"),
};

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/0002_outbox_writer.sql");
/// Paged candidates, source tokens and normalized execution lookup keys.
pub const CANDIDATES_MIGRATION_SQL: &str = include_str!("../migrations/0003_candidates.sql");
/// Narrow tenant-scoped freshness projection for product execution admission.
pub const EXECUTION_ADMISSION_MIGRATION_SQL: &str =
    include_str!("../migrations/0004_execution_admission.sql");
