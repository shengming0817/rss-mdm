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
    #[error("Agent credential rejected")]
    Agent(rss_mdm_agent_wire::enroll::ErrorCode),
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
    SoftwarePublication,
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
            R::Agent(c) => Self::Agent(c),
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::ReadConflict | R::CursorInvalidated | R::Conflict | R::EnrollmentPaused => {
                Self::Conflict
            }
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::Deadline => Self::Unavailable(Failure::RequestDeadline),
            R::NotFound => Self::NotFound,
            R::Audit(e) => e.as_ref().into(),
            R::Corrupt | R::Storage | R::Retirement | R::Configuration => {
                Self::Unavailable(Failure::Database)
            }
            R::Capacity | R::RegistrationLimit => Self::Unavailable(Failure::Capacity),
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
            Content::CommitUnknown => Self::Unavailable(Failure::ContentStorage),
            Content::Cleanup => Self::Unavailable(Failure::ContentCleanup),
        }
    }
}

impl Error {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound | Self::Missing(_))
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
            E::Configuration(_) => Self::Unavailable(crate::Failure::Database),
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_task_trust::Failure::Audit => crate::Failure::Audit,
                rss_mdm_task_trust::Failure::AuditAdmission => crate::Failure::AuditAdmission,
                rss_mdm_task_trust::Failure::AuditContract => crate::Failure::AuditContract,
                rss_mdm_task_trust::Failure::AuditIntegrity => crate::Failure::AuditIntegrity,
                rss_mdm_task_trust::Failure::AuditIsolation => crate::Failure::AuditIsolation,
                rss_mdm_task_trust::Failure::Capacity => crate::Failure::Capacity,
                rss_mdm_task_trust::Failure::CommandInvariant => crate::Failure::Database,
                rss_mdm_task_trust::Failure::Database => crate::Failure::Database,
                rss_mdm_task_trust::Failure::RequestDeadline => crate::Failure::RequestDeadline,
                rss_mdm_task_trust::Failure::Runtime => crate::Failure::Runtime,
            }),
        }
    }
}

impl From<rss_transactional_messaging_postgres::PgError> for Error {
    fn from(e: rss_transactional_messaging_postgres::PgError) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind as K;
        match e.kind() {
            K::Conflict | K::OwnershipLost => Self::Conflict,
            K::DeadlineElapsed => Self::Unavailable(Failure::RequestDeadline),
            K::Permanent | K::Invariant => Self::Unavailable(Failure::Protocol),
            K::Transient => Self::Unavailable(Failure::Database),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        crate::database::db(e)
    }
}
