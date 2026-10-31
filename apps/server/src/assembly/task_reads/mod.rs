//! App composes bounded reads; preparation and result interpretation stay with each owner.
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error, Failure};
use std::sync::Arc;
mod preview;
mod snapshot;
pub(crate) struct Reads {
    pub signing_enabled: bool,
    pub clock: Arc<dyn rss_request_context::Clock>,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub tenant: rss_request_context::TenantId,
    pub read_pool: sqlx::PgPool,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub scripts: rss_mdm_script_service::inputs::Inputs,
    pub collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs,
    pub execution: Arc<rss_mdm_execution_service::queries::Queries>,
}
fn sql(error: sqlx::Error) -> Error {
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
fn script_fault(error: rss_mdm_script_service::transaction::Fault) -> Error {
    use rss_mdm_script_service::transaction::Fault as F;
    match error {
        F::Request(e) => script(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}

mod history;

mod assignments;

fn source(error: rss_mdm_scope_service::channels::SourceError) -> Error {
    use rss_mdm_scope_service::channels::SourceError as S;
    match error {
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
