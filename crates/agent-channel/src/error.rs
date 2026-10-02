use crate::{ConfigIssue, Failure};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid protocol configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation conflict")]
    Conflict,
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("object not found")]
    Missing(Missing),
    #[error("action unsupported")]
    Unsupported,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    Resource,
    Operation,
    Task,
    SoftwareSource,
    SoftwareCandidate,
}
impl Missing {
    fn code(self) -> &'static str {
        match self {
            Self::Resource => "resource_not_found",
            Self::Operation => "operation_not_found",
            Self::Task => "task_not_found",
            Self::SoftwareSource => "software_source_not_found",
            Self::SoftwareCandidate => "software_candidate_not_found",
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Conflict => Self::Conflict,
            A::CommitUnknown => Self::CommitUnknown,
            A::RollbackFailed => Self::RollbackFailed,
            A::Deadline => Self::Unavailable(Failure::RequestDeadline),
            A::Audit(e) => e.as_ref().into(),
            A::Corrupt | A::Storage | A::Configuration => Self::Unavailable(Failure::Database),
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match e {
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict => Self::Conflict,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::Deadline => Self::Unavailable(Failure::RequestDeadline),
            R::NotFound => Self::NotFound,
            R::Audit(e) => e.as_ref().into(),
            R::Corrupt | R::Storage | R::Retirement | R::Configuration => {
                Self::Unavailable(Failure::Database)
            }
            R::Capacity => Self::Unavailable(Failure::Capacity),
            R::Runtime => Self::Unavailable(Failure::Runtime),
        }
    }
}
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(_: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(_: rss_mdm_registration_service::device::DeviceError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_inventory_service::collection::CollectionError> for Error {
    fn from(_: rss_mdm_inventory_service::collection::CollectionError) -> Self {
        Self::Conflict
    }
}
impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::Error as I;
        match e {
            I::Malformed => Self::Malformed,
            I::Unauthorized => Self::Unauthorized,
            I::Forbidden => Self::Forbidden,
            I::Conflict => Self::Conflict,
            I::CommitUnknown => Self::CommitUnknown,
            I::RollbackFailed => Self::RollbackFailed,
            I::NotFound | I::Group(_) => Self::NotFound,
            I::Audit(e) => e.as_ref().into(),
            I::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_inventory_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_inventory_service::Failure::Audit => Failure::Audit,
                rss_mdm_inventory_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_inventory_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_inventory_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_inventory_service::Failure::AuditContract => Failure::AuditContract,
                other => Failure::Inventory(other),
            }),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(e).into()
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::from(&e)
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(e: &rss_mdm_audit_integration::Error) -> Self {
        use rss_mdm_audit_integration::ErrorClass as A;
        match e.class() {
            A::CommitUnknown => Self::CommitUnknown,
            A::RollbackFailed => Self::RollbackFailed,
            A::RequestDeadline => Self::Unavailable(Failure::RequestDeadline),
            A::Audit => Self::Unavailable(Failure::Audit),
            A::AuditIntegrity => Self::Unavailable(Failure::AuditIntegrity),
            A::AuditAdmission => Self::Unavailable(Failure::AuditAdmission),
            A::AuditIsolation => Self::Unavailable(Failure::AuditIsolation),
            A::AuditContract => Self::Unavailable(Failure::AuditContract),
        }
    }
}
impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e { E::Malformed => Self::Malformed, E::CertificateRequest => Self::CertificateRequest,
            E::Unauthorized => Self::Unauthorized, E::Forbidden => Self::Forbidden, E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown, E::RollbackFailed => Self::RollbackFailed, E::Unsupported => Self::Unsupported,
            E::NotFound => Self::NotFound, E::Resource(_) => Self::Missing(Missing::Resource),
            E::Execution(e) => Self::Missing(match e { rss_mdm_execution_service::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => Self::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingCandidate => Missing::SoftwareCandidate }),
            E::Configuration(c) => Self::Unavailable(Failure::ExecutionConfiguration(c)),
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,
                other => Failure::Execution(other),
            }),
        }
    }
}
impl From<Error> for rss_mdm_execution_service::channels::Rejection {
    fn from(e: Error) -> Self {
        use rss_mdm_execution_service::channels::Rejection as R;
        match e {
            Error::CommitUnknown => R::CommitUnknown,
            Error::RollbackFailed => R::RollbackFailed,
            Error::Malformed | Error::CertificateRequest => R::Malformed,
            Error::Unauthorized => R::Unauthorized,
            Error::Forbidden => R::Forbidden,
            Error::Conflict => R::Conflict,
            Error::Unavailable(Failure::RequestDeadline) => R::Deadline,
            Error::Unavailable(Failure::Audit) => R::Audit,
            Error::Unavailable(Failure::AuditIntegrity) => R::AuditIntegrity,
            Error::Unavailable(Failure::AuditAdmission) => R::AuditAdmission,
            Error::Unavailable(Failure::AuditIsolation) => R::AuditIsolation,
            Error::Unavailable(Failure::AuditContract) => R::AuditContract,
            Error::Unavailable(Failure::Protocol) => R::Protocol,
            _ => R::Storage,
        }
    }
}
impl From<rss_mdm_content_service::Error> for Error {
    fn from(error: rss_mdm_content_service::Error) -> Self {
        use rss_mdm_content_service::Error as Content;
        match error {
            Content::Configuration => Self::Unavailable(Failure::ContentConfiguration),
            Content::Malformed => Self::Malformed,
            Content::Conflict => Self::Conflict,
            Content::Storage => Self::Unavailable(Failure::ContentStorage),
            Content::Invariant => Self::Unavailable(Failure::ContentInvariant),
            Content::Metadata => Self::Unavailable(Failure::ContentMetadata),
            Content::Deadline => Self::Unavailable(Failure::ContentDeadline),
            Content::Cleanup => Self::Unavailable(Failure::ContentCleanup),
        }
    }
}
