//! App composes bounded reads; preparation and result interpretation stay with each owner.
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure};
use std::sync::Arc;
mod preview;
mod snapshot;
pub(crate) struct Reads {
    pub content_available: bool,
    pub configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub software: Arc<rss_mdm_software_service::deployment::queries::Queries>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::Materials>,
    pub entries: rss_mdm_registration_service::enrollment::task::Entries,
    pub signing_enabled: bool,
    pub recovery_enabled: bool,
    pub clock: Arc<dyn rss_request_context::Clock>,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub tenant: rss_request_context::TenantId,
    pub read_pool: sqlx::PgPool,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub scripts: rss_mdm_script_service::inputs::Inputs,
    pub collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs,
    pub execution: Arc<rss_mdm_device_service::control::queries::Queries>,
}
pub(super) fn sql(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| c == "40001" || c == "40P01")
    {
        Error::QueryReadConflict
    } else {
        Error::Unavailable(Failure::Database)
    }
}
fn script(error: rss_mdm_script_service::Error) -> Error {
    use rss_mdm_script_service::Error as S;
    match error {
        S::Unsupported => Error::Unsupported,
        S::Malformed => Error::Malformed,
        S::Conflict => Error::Conflict,
        S::Forbidden => Error::Forbidden,
        S::Unauthorized => Error::Unauthorized,
        S::NotFound => Error::NotFound,
        S::CommitUnknown => Error::CommitUnknown,
        S::RollbackFailed => Error::RollbackFailed,
        S::Inventory(e) => e.into(),
        S::Content(e) => e.into(),
        S::Invariant => Error::Unavailable(Failure::CommandInvariant),
        S::Unavailable => Error::Unavailable(Failure::CommandStorage),
        S::Audit(_) => Error::Unavailable(Failure::Audit),
    }
}
pub(super) fn script_fault(error: rss_mdm_script_service::transaction::Fault) -> Error {
    use rss_mdm_script_service::transaction::Fault as F;
    match error {
        F::Request(e) => script(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}

pub(super) mod history;

mod assignments;

fn source(error: rss_mdm_scope_service::channels::SourceError) -> Error {
    use rss_mdm_scope_service::channels::SourceError as S;
    match error {
        S::Unsupported => Error::Unsupported,
        S::Capacity => Error::Unavailable(Failure::Capacity),
        S::Missing => Error::ScopeNotFound,
        S::Conflict => Error::QueryReadConflict,
        S::Invariant => Error::Unavailable(Failure::PlanningStorage),
        S::Storage(e) => sql(e),
    }
}
fn window(error: rss_mdm_scope_service::window::Error) -> Error {
    use rss_mdm_scope_service::window::Error as W;
    match error {
        W::Malformed => Error::Malformed,
        W::Conflict => Error::QueryCursorInvalidated,
        W::Source(e) => source(e),
    }
}

pub(super) fn software_fault(
    error: rss_mdm_software_service::deployment::transaction::Fault,
) -> Error {
    use rss_mdm_software_service::deployment::transaction::Fault as F;
    match error {
        F::Request(e) => super::owner_errors::software_http(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
pub(super) fn enrollment_fault(
    error: rss_mdm_registration_service::enrollment::tasks::transaction::Fault,
) -> Error {
    use rss_mdm_registration_service::enrollment::tasks::transaction::Fault as F;
    match error {
        F::Request(e) => super::owner_errors::enrollment_http(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
mod projections;

pub(super) fn access_fault(
    e: rss_mdm_device_access_postgres::device_access::execution::transaction::Fault,
) -> Error {
    use rss_mdm_device_access_postgres::device_access::execution::{
        Error as E, transaction::Fault as F,
    };
    match e {
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
        F::Request(e) => match e {
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::Conflict => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            _ => Error::Unavailable(Failure::CommandInvariant),
        },
    }
}

pub(super) fn credential_fault(
    e: rss_mdm_recovery_credentials::tasks::transaction::Fault,
) -> Error {
    use rss_mdm_recovery_credentials::tasks::{Error as E, transaction::Fault as F};
    match e {
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
        F::Request(e) => match e {
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::Conflict => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            _ => Error::Unavailable(Failure::CommandInvariant),
        },
    }
}

mod retirement;

pub(super) fn configuration_fault(e: rss_mdm_policy_service::transaction::Fault) -> Error {
    match e {
        rss_mdm_policy_service::transaction::Fault::Request(e) => e.into(),
        rss_mdm_policy_service::transaction::Fault::Sql(e) => sql(e),
        rss_mdm_policy_service::transaction::Fault::Storage(_) => {
            Error::Unavailable(Failure::Database)
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "HTTP reads compose explicit owner query ports"
)]
pub(crate) fn assemble(
    config: &crate::config::Config,
    storage: &super::host_storage::Storage,
    protection: std::sync::Arc<rss_mdm_native_protection::Protector>,
    content: Option<std::sync::Arc<rss_mdm_content_service::Store>>,
    signed: bool,
    recovery_enabled: bool,
    source: std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    configuration: std::sync::Arc<rss_mdm_policy_service::configuration::Transactions>,
    software: std::sync::Arc<rss_mdm_software_service::deployment::queries::Queries>,
    enrollment: std::sync::Arc<rss_mdm_registration_service::enrollment::tasks::Materials>,
    queries: std::sync::Arc<rss_mdm_device_service::control::queries::Queries>,
) -> std::sync::Arc<Reads> {
    Arc::new(Reads {
        content_available: config.content.is_some(),
        configuration,
        software,
        enrollment,
        entries: config.enrollment_entries.clone(),
        signing_enabled: signed,
        recovery_enabled,
        clock: Arc::new(crate::lifecycle::RuntimeTimer),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            storage.runtime.clone(),
            storage.tenant,
        ),
        tenant: storage.tenant,
        read_pool: storage.read_pool.clone(),
        source,
        scripts: rss_mdm_script_service::inputs::Inputs::bind(
            storage.runtime.clone(),
            storage.tenant,
            content.clone(),
            signed,
        ),
        collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs::bind(
            storage.runtime.clone(),
            storage.tenant,
            content.clone(),
            Arc::new(super::collection_ports::Delivery {
                protection: protection.clone(),
            }),
        ),
        execution: queries,
    })
}
