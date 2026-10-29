#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
//! Immutable Resource versions and lifecycle over the host-owned RSS transaction.
mod artifacts;
mod codec;
pub mod directory;
pub use artifacts::{artifact_referenced_in, profile_references_in};

mod error;
mod event;
mod store;
pub use error::*;
pub use event::EVENT_SCHEMA;
pub use rss_mdm_resource as core;
pub use store::*;
/// Exact final schema migration. Execute only through the privileged host migrator after RSS messaging prerequisites.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");

use rss_mdm_backend_postgres_support::{Admission, BackendKind, BackendStorage};
pub(crate) const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Resource);
pub(crate) const ADMISSION: Admission = Admission {
    functions: &[],
    required_keys: &[
        ("aggregates", &["tenant_id", "id"]),
        ("immutable", &["tenant_id", "owner", "kind", "key"]),
        ("requests", &["tenant_id", "id"]),
        (
            "artifact_refs",
            &["tenant_id", "owner", "version", "sha256", "length"],
        ),
        ("field_refs", &["tenant_id", "owner", "version", "field"]),
        (
            "profile_refs",
            &["tenant_id", "owner", "version", "target", "target_version"],
        ),
    ],
    tables: &[
        "aggregates",
        "artifact_refs",
        "field_refs",
        "immutable",
        "profile_refs",
        "requests",
    ],
    update_columns: &[
        "artifact_refs.archived",
        "field_refs.archived",
        "profile_refs.archived",
        "aggregates.revision",
        "aggregates.document",
        "aggregates.digest",
    ],
};

/// Public Outbox function permissions, installed after the immutable initial product schema.
pub const OUTBOX_MIGRATION_SQL: &str = include_str!("../migrations/outbox.sql");

/// Minimal validated resources for downstream integration prerequisites.
#[cfg(feature = "integration")]
pub mod fixture;

pub use artifacts::{field_mapping_references_in, field_reference_details_in};

mod operations;
pub use operations::{record_operation_in, replay_operation_in};

/// Resource application schema; no Flow installation is required.
pub const APPLICATION_MIGRATION_SQL: &str = include_str!("../migrations/application.sql");
/// Closed effective role and receipt contract.
pub const APPLICATION_ADMISSION_SQL: &str = include_str!("application-admission.sql");
/// Check the application contract on the initiating tenant transaction.
pub async fn admit_application_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let valid = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, bool>(APPLICATION_ADMISSION_SQL)
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    if !valid {
        return Err(STORAGE.fault("application::admission"));
    }
    Ok(())
}
