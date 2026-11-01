//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::control::{Error, Failure};
impl From<crate::control::authorization::error::AuthorizationError> for Error {
    fn from(error: crate::control::authorization::error::AuthorizationError) -> Self {
        use crate::control::authorization::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::control::Failure::Database),
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
impl From<crate::control::device::DeviceError> for Error {
    fn from(error: crate::control::device::DeviceError) -> Self {
        match error {
            crate::control::device::DeviceError::InvalidSource => Self::Malformed,
        }
    }
}
impl From<crate::control::collection::CollectionError> for Error {
    fn from(error: crate::control::collection::CollectionError) -> Self {
        match error {
            crate::control::collection::CollectionError::CorrelationConflict => Self::Conflict,
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
                Self::Unavailable(crate::control::Failure::Database)
            }
            Authorization::Deadline => Self::Unavailable(crate::control::Failure::RequestDeadline),
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Configuration => {
                Self::Configuration(crate::control::ConfigIssue::IdentityConfiguration)
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
                Self::Unavailable(crate::control::Failure::Database)
            }
            R::Deadline => Self::Unavailable(crate::control::Failure::RequestDeadline),
            R::Conflict => Self::Conflict,
            R::ReadConflict => Self::ReadConflict,
            R::CursorInvalidated => Self::CursorInvalidated,
            R::EnrollmentPaused => Self::EnrollmentPaused,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::Capacity | R::RegistrationLimit => {
                Self::Unavailable(crate::control::Failure::Capacity)
            }
            R::Runtime => Self::Unavailable(crate::control::Failure::Runtime),
            R::Configuration => {
                Self::Configuration(crate::control::ConfigIssue::IdentityConfiguration)
            }
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
                F::AssetBytesLimit => crate::control::Failure::AssetBytesLimit,
                F::AssetCandidates => crate::control::Failure::AssetCandidates,
                F::AssetObjectLimit => crate::control::Failure::AssetObjectLimit,
                F::AssetSourceLimit => crate::control::Failure::AssetSourceLimit,
                F::AssetSources => crate::control::Failure::AssetSources,
                F::AssetsStorage => crate::control::Failure::AssetsStorage,
                F::Clock => crate::control::Failure::Clock,
                F::CollectionQuery => crate::control::Failure::CollectionQuery,
                F::ComplianceStorage => crate::control::Failure::ComplianceStorage,
                F::PlanningStorage => crate::control::Failure::PlanningStorage,
                F::InventoryQuery => crate::control::Failure::InventoryQuery,
                F::ManualQuery => crate::control::Failure::ManualQuery,
                F::Runtime => crate::control::Failure::Runtime,
                F::Database => crate::control::Failure::Database,
                F::Protocol => crate::control::Failure::Protocol,
                F::Capacity => crate::control::Failure::Capacity,
                F::InventoryRuntime => crate::control::Failure::InventoryRuntime,
                F::RequestDeadline => crate::control::Failure::RequestDeadline,
                F::Audit => crate::control::Failure::Audit,
                F::AuditIntegrity => crate::control::Failure::AuditIntegrity,
                F::AuditAdmission => crate::control::Failure::AuditAdmission,
                F::AuditIsolation => crate::control::Failure::AuditIsolation,
                F::AuditContract => crate::control::Failure::AuditContract,
            }),
        }
    }
}

impl From<rss_mdm_inventory_service::transaction::Fault> for Error {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        use rss_mdm_inventory_service::transaction::Fault as F;
        match e {
            F::Request(e) => e.into(),
            F::Storage(_) | F::Sql(_) => Self::Unavailable(crate::control::Failure::AssetsStorage),
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

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        use crate::Error as E;
        match e {
            E::Capacity => Self::Unavailable(crate::control::Failure::Capacity),
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict => Self::Conflict,
            E::CursorInvalidated => Self::CursorInvalidated,
            E::ReadConflict => Self::ReadConflict,
            E::ResultUnavailable => Self::Unavailable(crate::control::Failure::CommandStorage),
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Audit(e) => Self::from(e),
            E::Deadline => Self::Unavailable(crate::control::Failure::RequestDeadline),
            E::Storage => Self::Unavailable(crate::control::Failure::CommandStorage),
        }
    }
}
