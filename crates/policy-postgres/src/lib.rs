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
        ("policies", &["tenant_id", "id"]),
        ("versions", &["tenant_id", "id"]),
        ("triggers", &["tenant_id", "id"]),
        ("requests", &["tenant_id", "id"]),
    ],
    tables: &["policies", "requests", "triggers", "versions"],
    update_columns: &[
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
