//! Closed HTTP request projection; domain errors are converted only at this ingress.
use crate::{ConfigIssue, Failure, resource_catalog};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("selected first-use requirements are not ready")]
    FirstUseNotReady,
    #[error("first-use operation not observed")]
    FirstUseOperationMissing,
    #[error("MDM software distribution is disabled")]
    MdmSoftwareDisabled,
    #[error(transparent)]
    RecoveryCredentials(#[from] rss_mdm_recovery_credentials::Error),
    #[error(transparent)]
    Archive(#[from] rss_mdm_certificate_archive_service::Error),
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error("resource cursor invalidated; restart pagination")]
    ResourceCursorInvalidated,
    #[error("request body too large")]
    RequestTooLarge,
    #[error(transparent)]
    Group(#[from] rss_mdm_group_service::GroupMissing),
    #[error("policy not found")]
    PolicyMissing,
    #[error(transparent)]
    Resource(#[from] resource_catalog::error::ResourceError),
    #[error(transparent)]
    Execution(#[from] rss_mdm_device_service::control::missing::ExecutionError),
    #[error(transparent)]
    Publication(#[from] rss_mdm_software_service::management::publication::error::PublicationError),
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("object is still referenced")]
    Referenced,
    #[error("query continuation does not match the current context")]
    QueryCursorInvalidated,
    #[error("read authority changed during the request")]
    QueryReadConflict,
    #[error("fixed query result is no longer available")]
    QueryResultUnavailable,
    #[error("self-service registration quota reached")]
    RegistrationLimit,
    #[error("new registration admission paused")]
    EnrollmentPaused,
    #[error("Windows declared enrollment is not ready")]
    WindowsDeclaredEnrollmentNotReady,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback not acknowledged; original attempt remains unresolved")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error(transparent)]
    AgentPackage(#[from] rss_mdm_software_service::agent_packages::Rejection),
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("scope not found")]
    ScopeNotFound,
    #[error("action not supported")]
    Unsupported,
}
impl Error {
    pub fn is_not_found(&self) -> bool {
        self.status() == axum::http::StatusCode::NOT_FOUND
    }
}

impl From<axum::extract::rejection::JsonRejection> for Error {
    fn from(error: axum::extract::rejection::JsonRejection) -> Self {
        if error.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
            Self::RequestTooLarge
        } else {
            Self::Malformed
        }
    }
}

impl From<rss_mdm_recovery_credentials::native::Error> for Error {
    fn from(e: rss_mdm_recovery_credentials::native::Error) -> Self {
        use rss_mdm_recovery_credentials::native::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Forbidden => Self::Forbidden,
            E::Unauthorized => Self::Unauthorized,
            E::NotFound => Self::NotFound,
            E::OperationNotFound => Self::Execution(
                rss_mdm_device_service::control::missing::ExecutionError::MissingOperation,
            ),
            E::Conflict => Self::Conflict,
            E::ReadConflict => Self::QueryReadConflict,
            E::CursorInvalidated => Self::QueryCursorInvalidated,
            E::Unsupported => Self::Unsupported,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            _ => Self::Unavailable(crate::Failure::CommandStorage),
        }
    }
}
