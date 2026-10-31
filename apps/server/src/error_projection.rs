//! Cross-owner host assembly conversions; protocol projections belong to ingress.
use crate::{Error, Failure};
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(e: crate::authorization::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(e: crate::enrollment::EnrollmentError) -> Self {
        rss_mdm_registration_service::Error::from(e).into()
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(e: crate::device::DeviceError) -> Self {
        rss_mdm_registration_service::Error::from(e).into()
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(e: crate::collection::CollectionError) -> Self {
        rss_mdm_inventory_service::Error::from(e).into()
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
impl From<rss_mdm_inventory_service::transaction::Fault> for Error {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        match e {
            rss_mdm_inventory_service::transaction::Fault::Request(e) => e.into(),
            _ => rss_mdm_inventory_service::Error::Unavailable(
                rss_mdm_inventory_service::Failure::AssetsStorage,
            )
            .into(),
        }
    }
}
impl From<rss_mdm_policy::Error> for Error {
    fn from(e: rss_mdm_policy::Error) -> Self {
        Self::Policy(e.into())
    }
}
impl From<rss_mdm_resource_service::error::ResourceError> for Error {
    fn from(e: rss_mdm_resource_service::error::ResourceError) -> Self {
        Self::Resource(e.into())
    }
}
impl From<rss_mdm_execution_service::missing::ExecutionError> for Error {
    fn from(e: rss_mdm_execution_service::missing::ExecutionError) -> Self {
        Self::Execution(e.into())
    }
}
impl From<rss_mdm_software_service::management::publication::error::PublicationError> for Error {
    fn from(e: rss_mdm_software_service::management::publication::error::PublicationError) -> Self {
        rss_mdm_software_service::management::Error::from(e).into()
    }
}
pub(crate) fn audit_deadline(outcome: rss_mdm_audit_integration::WriteOutcome) -> Error {
    use rss_mdm_audit_integration::WriteOutcome as W;
    match outcome {
        W::Unknown | W::Committed => Error::CommitUnknown,
        W::RollbackFailed => Error::RollbackFailed,
        W::RolledBack | W::CommitNotStarted => Error::Unavailable(Failure::RequestDeadline),
    }
}
#[cfg(test)]
#[path = "../tests/error_projection/unit.rs"]
mod tests;

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
                rss_mdm_task_trust::Failure::CommandInvariant => crate::Failure::CommandInvariant,
                rss_mdm_task_trust::Failure::Database => crate::Failure::Database,
                rss_mdm_task_trust::Failure::RequestDeadline => crate::Failure::RequestDeadline,
                rss_mdm_task_trust::Failure::Runtime => crate::Failure::Runtime,
            }),
        }
    }
}
