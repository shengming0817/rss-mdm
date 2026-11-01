//! Closed read errors, projected to wire codes only by HTTP.
#[derive(Clone, Copy, Debug)]
pub enum Missing {
    Policy,
    Inventory,
    Resource,
    Operation,
    Task,
}
#[derive(Clone, Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid query")]
    Malformed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("query input conflicts with current facts")]
    Conflict,
    #[error("read authority changed during the request")]
    ReadConflict,
    #[error("query continuation does not match the current context")]
    CursorInvalidated,
    #[error("Windows declared enrollment is not ready")]
    WindowsDeclaredEnrollmentNotReady,
    #[error("read target not found: {0:?}")]
    Missing(Missing),
    #[error("query prerequisite unavailable")]
    Unsupported,
    #[error("read dependency unavailable: {0:?}")]
    Unavailable(crate::control::Failure),
    #[error("read audit commit outcome unknown")]
    CommitUnknown,
    #[error("read audit rollback unconfirmed")]
    RollbackFailed,
}
impl From<crate::control::Error> for QueryError {
    fn from(e: crate::control::Error) -> Self {
        use crate::control::{Error, error::ResourceError, missing::ExecutionError};
        match e {
            Error::Malformed => Self::Malformed,
            Error::Unauthorized => Self::Unauthorized,
            Error::Forbidden => Self::Forbidden,
            Error::Conflict => Self::Conflict,
            Error::ReadConflict => Self::ReadConflict,
            Error::CursorInvalidated => Self::CursorInvalidated,

            Error::WindowsDeclaredEnrollmentNotReady => Self::WindowsDeclaredEnrollmentNotReady,
            Error::CommitUnknown => Self::CommitUnknown,
            Error::RollbackFailed => Self::RollbackFailed,
            Error::NotFound => Self::Missing(Missing::Inventory),
            Error::Unsupported => Self::Unsupported,
            Error::Unavailable(f) => Self::Unavailable(f),
            Error::Resource(ResourceError::Missing) => Self::Missing(Missing::Resource),
            Error::Execution(ExecutionError::MissingOperation) => Self::Missing(Missing::Operation),
            Error::Execution(ExecutionError::MissingTask) => Self::Missing(Missing::Task),

            Error::EnrollmentPaused | Error::Configuration(_) | Error::CertificateRequest => {
                Self::Unavailable(crate::control::Failure::CommandInvariant)
            }
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for QueryError {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        crate::control::Error::from(e).into()
    }
}
impl From<rss_mdm_policy::Error> for QueryError {
    fn from(_: rss_mdm_policy::Error) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_authorization_service::Error> for QueryError {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        crate::control::Error::from(e).into()
    }
}
