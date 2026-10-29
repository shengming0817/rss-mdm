//! Policy management, publication, assignment and durable event applications.
#![forbid(unsafe_code)]
pub mod action_admission;
pub mod application;
pub mod clock;
mod diagnostic;
mod error;
mod error_projection;
pub mod events;
pub mod inputs;
pub mod management;
pub mod operation;
mod storage;
pub mod telemetry;
pub mod transaction;
pub mod worker;
pub mod worker_wake;
pub use diagnostic::Failure;
pub use error::Error;
use rss_mdm_authorization_service as authorization;
/// Policy application admission in an existing transaction.
pub const ADMISSION_SQL: &str = include_str!("admission.sql");
pub(crate) fn query_error(error: rss_mdm_query::Error) -> Error {
    match error {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
