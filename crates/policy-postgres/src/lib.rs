//! Unified Policy persistence. The host owns authorization, Scope, resources and delivery.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
mod error;
mod store;
pub use error::*;
pub use rss_mdm_policy as core;
pub use store::*;
/// Initialization schema for a new deployment; no old lifecycle tables are retained.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
/// Existing RSS runtime writer capability used to bind borrowed transactions.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/outbox.sql");
use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Policy);
const ADMISSION: Admission = Admission {
    required_keys: &[
        ("schedule_scan", &["tenant_id"]),
        ("policies", &["tenant_id", "id"]),
        (
            "assignments",
            &["tenant_id", "policy", "version", "object", "channel"],
        ),
        ("event_batches", &["tenant_id", "actor", "request"]),
        ("event_members", &["tenant_id", "id"]),
        ("work", &["tenant_id", "id"]),
        ("versions", &["tenant_id", "id"]),
        ("triggers", &["tenant_id", "id"]),
        ("requests", &["tenant_id", "id"]),
    ],
    tables: &[
        "schedule_scan",
        "assignments",
        "event_batches",
        "event_members",
        "policies",
        "requests",
        "triggers",
        "versions",
        "work",
    ],
    functions: &["mdm_policy.lock_policy(uuid)"],
    update_columns: &[
        "schedule_scan.after_policy",
        "schedule_scan.next_scan_at",
        "assignments.input",
        "assignments.availability",
        "assignments.reason",
        "assignments.target",
        "assignments.scope_result",
        "assignments.entry_revision",
        "event_members.decision",
        "work.forwarded",
        "work.completed",
        "work.cursor",
        "work.replacement_task",
        "work.authority_revision",
        "work.failure",
        "work.failure_detail",
        "policies.revision",
        "policies.current_version",
        "policies.version_number",
        "policies.state",
        "policies.definition",
        "policies.author",
        "policies.updated_at",
        "policies.execution_binding",
    ],
};

/// Validated persisted prerequisites for integration consumers.
#[cfg(feature = "integration")]
pub mod fixture;

/// Current Policy reference metadata for a tenant-bound composable read ($1 is the tenant).
/// The projection exposes only Scope and rollout references, never action payloads.
pub const GROUP_REFERENCE_FACTS_SQL: &str = r#"
SELECT tenant_id,id,revision,state,jsonb_build_object('scope',definition->'scope','action',jsonb_build_object('rollout',jsonb_build_object('stages',
 coalesce((SELECT jsonb_agg(jsonb_build_object('scope',stage->'scope')) FROM jsonb_array_elements(coalesce(definition#>'{action,rollout,stages}','[]')) stage),'[]'::jsonb)))) AS definition
FROM mdm_policy.policies WHERE tenant_id=$1::uuid
"#;

/// Policy-owned cross-capability privileges, installed after all schemas.
pub const RELATIONS_SQL: &str = include_str!("../migrations/relations.sql");
mod storage_authority;
pub use storage_authority::verify_authority;
/// Exact Policy source capability consumed by native registration.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
/// Read-only Policy source admission.
pub const ACCESS_ADMISSION_SQL: &str = include_str!("access-admission.sql");

/// Policy references to Scope definitions.
pub mod scope;
/// Durable Policy work persistence.
pub mod work;

/// Policy publication reads for telemetry.
pub mod telemetry;

/// Durable event batches, members and acceptance identities.
pub mod events;

/// Policy assignment projections.
pub mod assignments;

/// Policy candidate facts for Execution consumers.
pub mod candidates;

/// Checked Policy directory projections.
pub mod directory;

/// Policy schedule data.
pub mod schedules;
