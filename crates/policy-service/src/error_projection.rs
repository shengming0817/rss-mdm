//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::{Error, Failure};
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
            Authorization::Configuration => Self::Unavailable(Failure::Database),
            Authorization::Audit(error) => Self::from(error.as_ref()),
        }
    }
}

impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::Error as I;
        match e {
            I::Malformed => Self::Malformed,
            I::Unauthorized => Self::Unauthorized,
            I::Forbidden => Self::Forbidden,
            I::Conflict | I::Referenced => Self::Conflict,
            I::NotFound => Self::NotFound,
            I::CommitUnknown => Self::CommitUnknown,
            I::RollbackFailed => Self::RollbackFailed,
            I::Audit(e) => Self::from(e.as_ref()),
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

impl From<rss_mdm_device_service::Error> for Error {
    fn from(e: rss_mdm_device_service::Error) -> Self {
        use rss_mdm_device_service::Error as E;
        match e {
            E::Capacity => Self::Unavailable(crate::Failure::AutomationStorage),
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict | E::CursorInvalidated | E::ReadConflict => Self::Conflict,
            E::ResultUnavailable => Self::Unavailable(crate::Failure::AutomationStorage),
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Audit(e) => Self::from(e),
            E::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            E::Storage => Self::Unavailable(crate::Failure::AutomationStorage),
        }
    }
}

impl From<rss_mdm_registration_service::Error> for Error {
    fn from(error: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match error {
            R::Unsupported => Self::Unsupported,
            R::Agent(_) => Self::Unauthorized,
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Corrupt | R::Storage | R::Retirement => Self::Unavailable(crate::Failure::Database),
            R::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            R::Conflict => Self::Conflict,
            R::ReadConflict => Self::Conflict,
            R::CursorInvalidated => Self::Conflict,
            R::EnrollmentPaused => Self::Conflict,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::Capacity | R::RegistrationLimit => Self::Unavailable(crate::Failure::Capacity),
            R::Runtime => Self::Unavailable(crate::Failure::Runtime),
            R::Configuration => Self::Unavailable(Failure::PolicyAdmission),
            R::Audit(e) => Self::from(e.as_ref()),
        }
    }
}

impl From<rss_mdm_content_service::Error> for Error {
    fn from(error: rss_mdm_content_service::Error) -> Self {
        use rss_mdm_content_service::Error as Content;
        match error {
            Content::Configuration => Self::Unavailable(Failure::PolicyAdmission),
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

impl From<rss_mdm_scope_service::window::Error> for Error {
    fn from(e: rss_mdm_scope_service::window::Error) -> Self {
        match e {
            rss_mdm_scope_service::window::Error::Malformed => Self::Malformed,
            rss_mdm_scope_service::window::Error::Conflict => Self::Conflict,
            rss_mdm_scope_service::window::Error::Source(e) => Self::from(e),
        }
    }
}

impl From<rss_mdm_script_service::Error> for Error {
    fn from(e: rss_mdm_script_service::Error) -> Self {
        use rss_mdm_script_service::Error as S;
        match e {
            S::Unsupported => Self::Unsupported,
            S::Malformed => Self::Malformed,
            S::Conflict => Self::Conflict,
            S::Forbidden => Self::Forbidden,
            S::Unauthorized => Self::Unauthorized,
            S::NotFound => Self::NotFound,
            S::Invariant => Self::Unavailable(Failure::PreparationContract),
            S::Unavailable => Self::Unavailable(Failure::Preparation),
            S::CommitUnknown => Self::CommitUnknown,
            S::RollbackFailed => Self::RollbackFailed,
            S::Inventory(e) => e.into(),
            S::Content(e) => e.into(),
            S::Audit(e) => Self::from(e.as_ref()),
        }
    }
}

impl From<rss_mdm_scope_service::Error> for Error {
    fn from(e: rss_mdm_scope_service::Error) -> Self {
        use rss_mdm_scope_service::Error as S;
        match e {
            S::Malformed => Self::Malformed,
            S::Unauthorized => Self::Unauthorized,
            S::Forbidden => Self::Forbidden,
            S::Conflict | S::Referenced => Self::Conflict,
            S::NotFound => Self::NotFound,
            S::Unsupported => Self::Unsupported,
            S::CommitUnknown => Self::CommitUnknown,
            S::RollbackFailed => Self::RollbackFailed,
            S::Unavailable(_) => Self::Unavailable(Failure::PolicyStorage),
        }
    }
}

impl From<rss_mdm_software_service::deployment::Error> for Error {
    fn from(e: rss_mdm_software_service::deployment::Error) -> Self {
        use rss_mdm_software_service::deployment::Error as E;
        match e {
            E::MdmSoftwareDisabled => Error::MdmSoftwareDisabled,
            E::Malformed => Error::Malformed,
            E::Unauthorized => Error::Unauthorized,
            E::Forbidden => Error::Forbidden,
            E::ReadConflict
            | E::CursorInvalidated
            | E::Conflict
            | E::EnrollmentPaused
            | E::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::NotFound | E::Resource(_) => Error::ResourceMissing,
            E::Unavailable(f) => Error::Unavailable(match f {
                rss_mdm_software_service::deployment::Failure::RequestDeadline => {
                    Failure::RequestDeadline
                }
                rss_mdm_software_service::deployment::Failure::Audit => Failure::Audit,
                rss_mdm_software_service::deployment::Failure::AuditIntegrity => {
                    Failure::AuditIntegrity
                }
                rss_mdm_software_service::deployment::Failure::AuditAdmission => {
                    Failure::AuditAdmission
                }
                rss_mdm_software_service::deployment::Failure::AuditIsolation => {
                    Failure::AuditIsolation
                }
                rss_mdm_software_service::deployment::Failure::AuditContract => {
                    Failure::AuditContract
                }
                rss_mdm_software_service::deployment::Failure::NativeProtection => {
                    Failure::NativeProtection
                }
                rss_mdm_software_service::deployment::Failure::NativeInputIntegrity => {
                    Failure::NativeInputIntegrity
                }
                rss_mdm_software_service::deployment::Failure::CommandInvariant => {
                    Failure::CommandInvariant
                }
                rss_mdm_software_service::deployment::Failure::ContentStorage => {
                    Failure::ContentStorage
                }
                rss_mdm_software_service::deployment::Failure::ContentMetadata => {
                    Failure::ContentMetadata
                }
                rss_mdm_software_service::deployment::Failure::ContentInvariant => {
                    Failure::ContentInvariant
                }
                rss_mdm_software_service::deployment::Failure::ContentDeadline => {
                    Failure::ContentDeadline
                }
                rss_mdm_software_service::deployment::Failure::ContentCleanup => {
                    Failure::ContentCleanup
                }
                rss_mdm_software_service::deployment::Failure::AutomationConnection => {
                    Failure::AutomationConnection
                }
                rss_mdm_software_service::deployment::Failure::AutomationAdmission => {
                    Failure::AutomationAdmission
                }
                rss_mdm_software_service::deployment::Failure::AutomationStorage => {
                    Failure::AutomationStorage
                }
                rss_mdm_software_service::deployment::Failure::Database => Failure::Database,
                rss_mdm_software_service::deployment::Failure::AssetObjectLimit => {
                    Failure::AssetObjectLimit
                }
                rss_mdm_software_service::deployment::Failure::AssetSourceLimit => {
                    Failure::AssetSourceLimit
                }
                rss_mdm_software_service::deployment::Failure::AssetBytesLimit => {
                    Failure::AssetBytesLimit
                }
                rss_mdm_software_service::deployment::Failure::Clock => Failure::Clock,
                rss_mdm_software_service::deployment::Failure::Capacity => Failure::Capacity,
                rss_mdm_software_service::deployment::Failure::Runtime => Failure::Runtime,
                rss_mdm_software_service::deployment::Failure::SoftwareCatalogInvariant => {
                    Failure::SoftwareIntegrity
                }
                rss_mdm_software_service::deployment::Failure::PlanningAdmission => {
                    Failure::PolicyAdmission
                }
                rss_mdm_software_service::deployment::Failure::PlanningStorage => {
                    Failure::PolicyStorage
                }
                rss_mdm_software_service::deployment::Failure::Timeline
                | rss_mdm_software_service::deployment::Failure::IdentityStorage
                | rss_mdm_software_service::deployment::Failure::ResourceAdmission
                | rss_mdm_software_service::deployment::Failure::CommandAdmission
                | rss_mdm_software_service::deployment::Failure::ContentImport
                | rss_mdm_software_service::deployment::Failure::SoftwareCatalogStorage
                | rss_mdm_software_service::deployment::Failure::CommandStorage
                | rss_mdm_software_service::deployment::Failure::AssetsStorage
                | rss_mdm_software_service::deployment::Failure::ComplianceStorage
                | rss_mdm_software_service::deployment::Failure::ResourceStorage
                | rss_mdm_software_service::deployment::Failure::PublicationStorage
                | rss_mdm_software_service::deployment::Failure::InventoryQuery
                | rss_mdm_software_service::deployment::Failure::AssetCandidates
                | rss_mdm_software_service::deployment::Failure::AssetSources
                | rss_mdm_software_service::deployment::Failure::ManualQuery
                | rss_mdm_software_service::deployment::Failure::CollectionQuery
                | rss_mdm_software_service::deployment::Failure::InventoryRuntime
                | rss_mdm_software_service::deployment::Failure::Protocol => Failure::Preparation,
            }),
            E::Configuration(_) => Error::Unavailable(Failure::PreparationConfiguration),
            E::Execution(_) | E::Publication(_) | E::CertificateRequest => {
                Error::Unavailable(Failure::PreparationContract)
            }
        }
    }
}

impl From<rss_mdm_registration_service::enrollment::tasks::Error> for Error {
    fn from(e: rss_mdm_registration_service::enrollment::tasks::Error) -> Self {
        use rss_mdm_registration_service::enrollment::tasks::Error as E;
        match e {
            E::Unsupported => Error::Unsupported,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::Conflict => Error::Conflict,
            E::NotFound => Error::NotFound,
            E::Audit(e) => Self::from(e.as_ref()),
            E::Invariant => Error::Unavailable(Failure::CommandInvariant),
            E::Unavailable => Error::Unavailable(Failure::PolicyStorage),
        }
    }
}

impl From<rss_mdm_device_service::control::Error> for Error {
    fn from(e: rss_mdm_device_service::control::Error) -> Self {
        use rss_mdm_device_service::control::Error as E;
        match e {
            E::Malformed => Error::Malformed,
            E::Unauthorized => Error::Unauthorized,
            E::Forbidden => Error::Forbidden,
            E::ReadConflict
            | E::CursorInvalidated
            | E::Conflict
            | E::EnrollmentPaused
            | E::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::NotFound | E::Resource(_) => Error::ResourceMissing,
            E::Unavailable(f) => Error::Unavailable(match f {
                rss_mdm_device_service::control::Failure::RequestDeadline => {
                    Failure::RequestDeadline
                }
                rss_mdm_device_service::control::Failure::Audit => Failure::Audit,
                rss_mdm_device_service::control::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_device_service::control::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_device_service::control::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_device_service::control::Failure::AuditContract => Failure::AuditContract,
                rss_mdm_device_service::control::Failure::NativeProtection => {
                    Failure::NativeProtection
                }
                rss_mdm_device_service::control::Failure::NativeInputIntegrity => {
                    Failure::NativeInputIntegrity
                }
                rss_mdm_device_service::control::Failure::CommandInvariant => {
                    Failure::CommandInvariant
                }
                rss_mdm_device_service::control::Failure::ContentStorage => Failure::ContentStorage,
                rss_mdm_device_service::control::Failure::ContentMetadata => {
                    Failure::ContentMetadata
                }
                rss_mdm_device_service::control::Failure::ContentInvariant => {
                    Failure::ContentInvariant
                }
                rss_mdm_device_service::control::Failure::ContentDeadline => {
                    Failure::ContentDeadline
                }
                rss_mdm_device_service::control::Failure::ContentCleanup => Failure::ContentCleanup,
                rss_mdm_device_service::control::Failure::AutomationConnection => {
                    Failure::AutomationConnection
                }
                rss_mdm_device_service::control::Failure::AutomationAdmission => {
                    Failure::AutomationAdmission
                }
                rss_mdm_device_service::control::Failure::AutomationStorage => {
                    Failure::AutomationStorage
                }
                rss_mdm_device_service::control::Failure::Database => Failure::Database,
                rss_mdm_device_service::control::Failure::AssetObjectLimit => {
                    Failure::AssetObjectLimit
                }
                rss_mdm_device_service::control::Failure::AssetSourceLimit => {
                    Failure::AssetSourceLimit
                }
                rss_mdm_device_service::control::Failure::AssetBytesLimit => {
                    Failure::AssetBytesLimit
                }
                rss_mdm_device_service::control::Failure::Clock => Failure::Clock,
                rss_mdm_device_service::control::Failure::Capacity => Failure::Capacity,
                rss_mdm_device_service::control::Failure::Runtime => Failure::Runtime,
                rss_mdm_device_service::control::Failure::SoftwareCatalogInvariant => {
                    Failure::SoftwareIntegrity
                }
                rss_mdm_device_service::control::Failure::PlanningAdmission => {
                    Failure::PolicyAdmission
                }
                rss_mdm_device_service::control::Failure::PlanningStorage => Failure::PolicyStorage,
                rss_mdm_device_service::control::Failure::Timeline
                | rss_mdm_device_service::control::Failure::IdentityStorage
                | rss_mdm_device_service::control::Failure::ResourceAdmission
                | rss_mdm_device_service::control::Failure::CommandAdmission
                | rss_mdm_device_service::control::Failure::ContentImport
                | rss_mdm_device_service::control::Failure::SoftwareCatalogStorage
                | rss_mdm_device_service::control::Failure::CommandStorage
                | rss_mdm_device_service::control::Failure::AssetsStorage
                | rss_mdm_device_service::control::Failure::ComplianceStorage
                | rss_mdm_device_service::control::Failure::ResourceStorage
                | rss_mdm_device_service::control::Failure::PublicationStorage
                | rss_mdm_device_service::control::Failure::InventoryQuery
                | rss_mdm_device_service::control::Failure::AssetCandidates
                | rss_mdm_device_service::control::Failure::AssetSources
                | rss_mdm_device_service::control::Failure::ManualQuery
                | rss_mdm_device_service::control::Failure::CollectionQuery
                | rss_mdm_device_service::control::Failure::InventoryRuntime
                | rss_mdm_device_service::control::Failure::Protocol => Failure::Preparation,
            }),
            E::Configuration(_) => Error::Unavailable(Failure::PreparationConfiguration),
            E::Execution(_) | E::CertificateRequest => {
                Error::Unavailable(Failure::PreparationContract)
            }
        }
    }
}
