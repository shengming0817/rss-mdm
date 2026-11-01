//! Unified Policy persistence. The host owns authorization, Scope, resources and delivery.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
mod error;
mod store;
pub use error::*;
pub use rss_mdm_policy as core;
pub use store::*;
/// Initialization schema for a new deployment; no old lifecycle tables are retained.
pub const fn migration_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).migration
}
/// Existing RSS runtime writer capability used to bind borrowed transactions.
pub const fn outbox_migration_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).outbox_migration
}
use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
fn storage(profile: rss_mdm_install_support::StorageProfile) -> BackendStorage {
    BackendStorage::new(match profile {
        rss_mdm_install_support::StorageProfile::Mdm => BackendKind::Policy,
        rss_mdm_install_support::StorageProfile::Da => BackendKind::DaPolicy,
    })
}
/// Current Policy reference metadata for a tenant-bound composable read ($1 is the tenant).
/// The projection exposes only Scope and rollout references, never action payloads.
pub const fn group_reference_facts_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).group_reference_facts
}

/// Policy-owned cross-capability privileges, installed after all schemas.
pub const fn relations_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).relations
}
mod storage_authority;
pub use storage_authority::verify_authority;
/// Exact Policy source capability consumed by native registration.
pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm).access_contract;
/// Read-only Policy source admission.
pub const fn access_admission_sql(
    profile: rss_mdm_install_support::StorageProfile,
) -> &'static str {
    storage_profile::sql(profile).access_admission
}

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

macro_rules! policy_admission {
    ($assignments:literal, $event_batches:literal, $event_members:literal, $policies:literal, $requests:literal, $schedule_scan:literal, $triggers:literal, $versions:literal, $work:literal, $lock:literal) => {
        Admission {
            required_keys: &[
                ($schedule_scan, &["tenant_id"]),
                ($policies, &["tenant_id", "id"]),
                (
                    $assignments,
                    &["tenant_id", "policy", "version", "object", "channel"],
                ),
                ($event_batches, &["tenant_id", "actor", "request"]),
                ($event_members, &["tenant_id", "id"]),
                ($work, &["tenant_id", "id"]),
                ($versions, &["tenant_id", "id"]),
                ($triggers, &["tenant_id", "id"]),
                ($requests, &["tenant_id", "id"]),
            ],
            tables: &[
                $assignments,
                $event_batches,
                $event_members,
                $policies,
                $requests,
                $schedule_scan,
                $triggers,
                $versions,
                $work,
            ],
            functions: &[$lock],
            update_columns: &[
                concat!($schedule_scan, ".after_policy"),
                concat!($schedule_scan, ".next_scan_at"),
                concat!($assignments, ".input"),
                concat!($assignments, ".availability"),
                concat!($assignments, ".reason"),
                concat!($assignments, ".target"),
                concat!($assignments, ".scope_result"),
                concat!($assignments, ".entry_revision"),
                concat!($event_members, ".decision"),
                concat!($work, ".forwarded"),
                concat!($work, ".completed"),
                concat!($work, ".cursor"),
                concat!($work, ".replacement_task"),
                concat!($work, ".authority_revision"),
                concat!($work, ".failure"),
                concat!($work, ".failure_detail"),
                concat!($policies, ".revision"),
                concat!($policies, ".current_version"),
                concat!($policies, ".version_number"),
                concat!($policies, ".state"),
                concat!($policies, ".definition"),
                concat!($policies, ".author"),
                concat!($policies, ".updated_at"),
                concat!($policies, ".execution_binding"),
            ],
        }
    };
}
fn admission(profile: rss_mdm_install_support::StorageProfile) -> Admission {
    match profile {
        rss_mdm_install_support::StorageProfile::Mdm => policy_admission!(
            "assignments",
            "event_batches",
            "event_members",
            "policies",
            "requests",
            "schedule_scan",
            "triggers",
            "versions",
            "work",
            "mdm_policy.lock_policy(uuid)"
        ),
        rss_mdm_install_support::StorageProfile::Da => policy_admission!(
            "policy_assignments",
            "policy_event_batches",
            "policy_event_members",
            "policies",
            "policy_requests",
            "policy_schedule_scan",
            "policy_triggers",
            "policy_versions",
            "policy_work",
            "rss_da.lock_policy(uuid)"
        ),
    }
}

mod storage_profile;

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile).access_contract
}
