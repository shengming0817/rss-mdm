use crate::native::{ConfigIssue, Failure};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("MDM software distribution is disabled")]
    MdmSoftwareDisabled,
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error(transparent)]
    Execution(#[from] crate::native::missing::ExecutionError),
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("read authority changed during the request")]
    ReadConflict,
    #[error("query continuation does not match the current context")]
    CursorInvalidated,
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
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("action not supported")]
    Unsupported,
}
impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound | Self::Resource(_) | Self::Execution(_)
        )
    }
}
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ResourceError {
    #[error("resource_not_found")]
    Missing,
}

impl From<rss_mdm_task_state::Error> for Error {
    fn from(error: rss_mdm_task_state::Error) -> Self {
        match error {
            rss_mdm_task_state::Error::Malformed => Self::Malformed,
            rss_mdm_task_state::Error::Conflict => Self::Conflict,
        }
    }
}

impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(error: rss_mdm_registration_service::device::DeviceError) -> Self {
        match error {
            rss_mdm_registration_service::device::DeviceError::InvalidSource => Self::Malformed,
        }
    }
}

impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(error: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::from(rss_mdm_audit_integration::Error::Fact(error))
    }
}

impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        Self::from(&error)
    }
}

impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(error: &rss_mdm_audit_integration::Error) -> Self {
        use rss_mdm_audit_integration::ErrorClass as C;
        match error.class() {
            C::CommitUnknown => Self::CommitUnknown,
            C::RollbackFailed => Self::RollbackFailed,
            C::RequestDeadline => Self::Unavailable(Failure::RequestDeadline),
            C::AuditIntegrity => Self::Unavailable(Failure::AuditIntegrity),
            C::AuditAdmission => Self::Unavailable(Failure::AuditAdmission),
            C::AuditIsolation => Self::Unavailable(Failure::AuditIsolation),
            C::AuditContract => Self::Unavailable(Failure::AuditContract),

            C::Audit => Self::Unavailable(Failure::Audit),
        }
    }
}

impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as Authorization;
        match error {
            Authorization::Malformed => Self::Malformed,
            Authorization::Unauthorized => Self::Unauthorized,
            Authorization::Forbidden => Self::Forbidden,
            Authorization::Corrupt | Authorization::Storage => Self::Unavailable(Failure::Database),
            Authorization::Deadline => Self::Unavailable(Failure::RequestDeadline),
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Configuration => Self::Configuration(ConfigIssue::IdentityConfiguration),
            Authorization::Audit(error) => Self::from(error.as_ref()),
        }
    }
}

impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        use rss_mdm_authorization_service::error::AuthorizationError as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Corrupt => Self::Unavailable(Failure::Database),
        }
    }
}
