//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::{ConfigIssue, Error, Failure};
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(error: crate::authorization::error::AuthorizationError) -> Self {
        use crate::authorization::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::Failure::Database),
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
impl From<crate::device::DeviceError> for Error {
    fn from(error: crate::device::DeviceError) -> Self {
        match error {
            crate::device::DeviceError::InvalidSource => Self::Malformed,
        }
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(error: crate::collection::CollectionError) -> Self {
        match error {
            crate::collection::CollectionError::CorrelationConflict => Self::Conflict,
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

impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::{Error as I, Failure as F};
        match e {
            I::Group(_) => Self::NotFound,
            I::Malformed => Self::Malformed,
            I::Unauthorized => Self::Unauthorized,
            I::Forbidden => Self::Forbidden,
            I::Conflict => Self::Conflict,
            I::NotFound => Self::NotFound,
            I::CommitUnknown => Self::CommitUnknown,
            I::RollbackFailed => Self::RollbackFailed,
            I::Audit(e) => Self::from(e.as_ref()),
            I::Unavailable(f) => Self::Unavailable(match f {
                F::AssetBytesLimit => crate::Failure::AssetBytesLimit,
                F::AssetCandidates => crate::Failure::AssetCandidates,
                F::AssetObjectLimit => crate::Failure::AssetObjectLimit,
                F::AssetSourceLimit => crate::Failure::AssetSourceLimit,
                F::AssetSources => crate::Failure::AssetSources,
                F::AssetsStorage => crate::Failure::AssetsStorage,
                F::Clock => crate::Failure::Clock,
                F::CollectionQuery => crate::Failure::CollectionQuery,
                F::ComplianceStorage => crate::Failure::ComplianceStorage,
                F::PlanningStorage => crate::Failure::PlanningStorage,
                F::InventoryQuery => crate::Failure::InventoryQuery,
                F::ManualQuery => crate::Failure::ManualQuery,
                F::Runtime => crate::Failure::Runtime,
                F::Database => crate::Failure::Database,
                F::Protocol => crate::Failure::Protocol,
                F::Capacity => crate::Failure::Capacity,
                F::InventoryRuntime => crate::Failure::InventoryRuntime,
                F::RequestDeadline => crate::Failure::RequestDeadline,
                F::Audit => crate::Failure::Audit,
                F::AuditIntegrity => crate::Failure::AuditIntegrity,
                F::AuditAdmission => crate::Failure::AuditAdmission,
                F::AuditIsolation => crate::Failure::AuditIsolation,
                F::AuditContract => crate::Failure::AuditContract,
            }),
        }
    }
}

impl From<rss_mdm_inventory_service::transaction::Fault> for Error {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        use rss_mdm_inventory_service::transaction::Fault as F;
        match e {
            F::Request(e) => e.into(),
            F::Storage(_) | F::Sql(_) => Self::Unavailable(crate::Failure::AssetsStorage),
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

impl From<rss_mdm_content_service::Error> for Error {
    fn from(error: rss_mdm_content_service::Error) -> Self {
        use rss_mdm_content_service::Error as Content;
        match error {
            Content::Configuration => Self::Configuration(ConfigIssue::Content),
            Content::Malformed => Self::Malformed,
            Content::Conflict => Self::Conflict,
            Content::Storage => Self::Unavailable(Failure::ContentStorage),
            Content::Invariant => Self::Unavailable(Failure::ContentInvariant),
            Content::Metadata => Self::Unavailable(Failure::ContentMetadata),
            Content::Deadline => Self::Unavailable(Failure::ContentDeadline),
            Content::CommitUnknown => Self::CommitUnknown,
            Content::Cleanup => Self::Unavailable(Failure::ContentCleanup),
        }
    }
}

impl From<rss_mdm_content_service::service::Error> for Error {
    fn from(e: rss_mdm_content_service::service::Error) -> Self {
        use rss_mdm_content_service::service::Error as C;
        match e {
            C::Content(e) => e.into(),
            C::Authorization(e) => e.into(),
            C::Audit(e) => e.as_ref().into(),
            C::Malformed => Self::Malformed,
            C::Conflict => Self::Conflict,
            C::Forbidden => Self::Forbidden,
            C::Missing => Self::Resource(crate::error::ResourceError::Missing),
            C::Unsupported => Self::Unsupported,
            C::Clock => Self::Unavailable(Failure::Clock),
            C::Import => Self::Unavailable(Failure::ContentImport),
            C::Storage => Self::Unavailable(Failure::ContentStorage),
            C::Invariant => Self::Unavailable(Failure::ContentInvariant),
            C::CommitUnknown => Self::CommitUnknown,
            C::RollbackFailed => Self::RollbackFailed,
        }
    }
}

impl From<rss_mdm_device_service::Error> for Error {
    fn from(e: rss_mdm_device_service::Error) -> Self {
        use rss_mdm_device_service::Error as E;
        match e {
            E::Capacity => Self::Unavailable(crate::Failure::Capacity),
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict => Self::Conflict,
            E::CursorInvalidated => Self::CursorInvalidated,
            E::ReadConflict => Self::ReadConflict,
            E::ResultUnavailable => Self::Unavailable(crate::Failure::CommandStorage),
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Audit(e) => Self::from(e),
            E::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            E::Storage => Self::Unavailable(crate::Failure::CommandStorage),
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

impl From<rss_mdm_scope_service::window::Error> for Error {
    fn from(e: rss_mdm_scope_service::window::Error) -> Self {
        match e {
            rss_mdm_scope_service::window::Error::Malformed => Self::Malformed,
            rss_mdm_scope_service::window::Error::Conflict => Self::Conflict,
            rss_mdm_scope_service::window::Error::Source(e) => Self::from(e),
        }
    }
}
