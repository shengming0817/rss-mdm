//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::deployment::{ConfigIssue, Error, Failure};
impl From<crate::deployment::authorization::error::AuthorizationError> for Error {
    fn from(error: crate::deployment::authorization::error::AuthorizationError) -> Self {
        use crate::deployment::authorization::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::deployment::Failure::Database),
        }
    }
}
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(error: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        match error {
            rss_mdm_registration_service::enrollment::EnrollmentError::InvalidPassword => {
                Self::Malformed
            }
        }
    }
}
impl From<crate::deployment::device::DeviceError> for Error {
    fn from(error: crate::deployment::device::DeviceError) -> Self {
        match error {
            crate::deployment::device::DeviceError::InvalidSource => Self::Malformed,
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
                Self::Unavailable(crate::deployment::Failure::Database)
            }
            Authorization::Deadline => {
                Self::Unavailable(crate::deployment::Failure::RequestDeadline)
            }
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Configuration => {
                Self::Configuration(crate::deployment::ConfigIssue::IdentityConfiguration)
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
            R::Corrupt | R::Storage | R::Retirement => {
                Self::Unavailable(crate::deployment::Failure::Database)
            }
            R::Deadline => Self::Unavailable(crate::deployment::Failure::RequestDeadline),
            R::Conflict => Self::Conflict,
            R::ReadConflict => Self::ReadConflict,
            R::CursorInvalidated => Self::CursorInvalidated,
            R::EnrollmentPaused => Self::EnrollmentPaused,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::Capacity | R::RegistrationLimit => {
                Self::Unavailable(crate::deployment::Failure::Capacity)
            }
            R::Runtime => Self::Unavailable(crate::deployment::Failure::Runtime),
            R::Configuration => {
                Self::Configuration(crate::deployment::ConfigIssue::IdentityConfiguration)
            }
            R::Audit(e) => Self::from(e.as_ref()),
        }
    }
}

impl From<rss_mdm_apple_mdm::Error> for Error {
    fn from(error: rss_mdm_apple_mdm::Error) -> Self {
        match error {
            rss_mdm_apple_mdm::Error::Malformed => Self::Malformed,
            rss_mdm_apple_mdm::Error::Unsupported => Self::Unsupported,
            rss_mdm_apple_mdm::Error::Conflict => Self::Conflict,
        }
    }
}

impl From<crate::management::Error> for Error {
    fn from(error: crate::management::Error) -> Self {
        use crate::management::{Error as S, Failure as F};
        match error {
            S::Malformed => Self::Malformed,
            S::Forbidden => Self::Forbidden,
            S::AgentPackage(_) => Self::Conflict,
            S::Conflict => Self::Conflict,
            S::Unsupported => Self::Unsupported,
            S::ResourceMissing => Self::Resource(crate::deployment::error::ResourceError::Missing),
            S::Publication(e) => Self::Publication(e),
            S::CommitUnknown => Self::CommitUnknown,
            S::RollbackFailed => Self::RollbackFailed,
            S::Authorization(e) => e.into(),
            S::Audit(e) => e.as_ref().into(),
            S::Unavailable(e) => match e {
                F::SoftwareCatalogStorage => Self::Unavailable(Failure::SoftwareCatalogStorage),
                F::SoftwareCatalogInvariant => Self::Unavailable(Failure::SoftwareCatalogInvariant),
                F::PublicationStorage => Self::Unavailable(Failure::PublicationStorage),
                F::Clock => Self::Unavailable(Failure::Clock),
                F::Runtime => Self::Unavailable(Failure::Runtime),
                F::ContentStorage => Self::Unavailable(Failure::ContentStorage),
                F::ContentInvariant => Self::Unavailable(Failure::ContentInvariant),
                F::ContentMetadata => Self::Unavailable(Failure::ContentMetadata),
                F::ContentDeadline => Self::Unavailable(Failure::ContentDeadline),
                F::ContentCleanup => Self::Unavailable(Failure::ContentCleanup),
                F::ContentConfiguration => Self::Configuration(ConfigIssue::Content),
            },
        }
    }
}

impl From<rss_mdm_task_trust::Error> for Error {
    fn from(error: rss_mdm_task_trust::Error) -> Self {
        use rss_mdm_task_trust::Error as E;
        match error {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::NotFound => Self::NotFound,
            E::Unsupported => Self::Unsupported,
            E::ReadConflict => Self::Conflict,
            E::CursorInvalidated => Self::Conflict,
            E::EnrollmentPaused => Self::Conflict,
            E::Configuration(_) => Self::Unavailable(crate::deployment::Failure::Database),
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_task_trust::Failure::Audit => crate::deployment::Failure::Audit,
                rss_mdm_task_trust::Failure::AuditAdmission => {
                    crate::deployment::Failure::AuditAdmission
                }
                rss_mdm_task_trust::Failure::AuditContract => {
                    crate::deployment::Failure::AuditContract
                }
                rss_mdm_task_trust::Failure::AuditIntegrity => {
                    crate::deployment::Failure::AuditIntegrity
                }
                rss_mdm_task_trust::Failure::AuditIsolation => {
                    crate::deployment::Failure::AuditIsolation
                }
                rss_mdm_task_trust::Failure::Capacity => crate::deployment::Failure::Capacity,
                rss_mdm_task_trust::Failure::CommandInvariant => {
                    crate::deployment::Failure::CommandInvariant
                }
                rss_mdm_task_trust::Failure::Database => crate::deployment::Failure::Database,
                rss_mdm_task_trust::Failure::RequestDeadline => {
                    crate::deployment::Failure::RequestDeadline
                }
                rss_mdm_task_trust::Failure::Runtime => crate::deployment::Failure::Runtime,
            }),
        }
    }
}
