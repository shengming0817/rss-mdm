use crate::{ConfigIssue, Failure};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("Malformed")]
    Malformed,
    #[error("Conflict")]
    Conflict,
    #[error("ReadConflict")]
    ReadConflict,
    #[error("CursorInvalidated")]
    CursorInvalidated,
    #[error("EnrollmentPaused")]
    EnrollmentPaused,
    #[error("CommitUnknown")]
    CommitUnknown,
    #[error("RollbackFailed")]
    RollbackFailed,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden")]
    Forbidden,
    #[error("NotFound")]
    NotFound,
    #[error("Unsupported")]
    Unsupported,
    #[error("configuration invalid")]
    Configuration(ConfigIssue),
    #[error("dependency unavailable")]
    Unavailable(Failure),
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(error: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        use rss_mdm_authorization_service::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::Failure::Database),
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
            Authorization::Corrupt | Authorization::Storage => {
                Self::Unavailable(crate::Failure::Database)
            }
            Authorization::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Configuration => {
                Self::Configuration(crate::ConfigIssue::IdentityConfiguration)
            }
            Authorization::Audit(error) => Self::from(error.as_ref()),
        }
    }
}

impl From<rss_mdm_registration_service::Error> for Error {
    fn from(error: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match error {
            R::Agent(_) => Self::Unauthorized,
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Corrupt | R::Storage | R::Retirement => Self::Unavailable(crate::Failure::Database),
            R::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            R::Conflict => Self::Conflict,
            R::ReadConflict => Self::ReadConflict,
            R::CursorInvalidated => Self::CursorInvalidated,
            R::EnrollmentPaused => Self::EnrollmentPaused,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::Capacity | R::RegistrationLimit => Self::Unavailable(crate::Failure::Capacity),
            R::Runtime => Self::Unavailable(crate::Failure::Runtime),
            R::Configuration => Self::Configuration(crate::ConfigIssue::IdentityConfiguration),
            R::Audit(e) => Self::from(e.as_ref()),
        }
    }
}
