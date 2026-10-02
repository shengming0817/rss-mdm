//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::{ConfigIssue, Error, Failure};
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
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(error: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        match error {
            rss_mdm_registration_service::enrollment::EnrollmentError::InvalidPassword => {
                Self::Malformed
            }
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
impl From<rss_mdm_inventory_service::collection::CollectionError> for Error {
    fn from(error: rss_mdm_inventory_service::collection::CollectionError) -> Self {
        match error {
            rss_mdm_inventory_service::collection::CollectionError::CorrelationConflict => {
                Self::Conflict
            }
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
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Corrupt | R::Storage | R::Retirement => Self::Unavailable(crate::Failure::Database),
            R::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            R::Conflict => Self::Conflict,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::Capacity => Self::Unavailable(crate::Failure::Capacity),
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
            I::Group(m) => Self::Group(m),
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
                F::FlowStorage => crate::Failure::FlowStorage,
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

impl From<rss_mdm_execution_service::channels::Rejection> for Error {
    fn from(e: rss_mdm_execution_service::channels::Rejection) -> Self {
        use rss_mdm_execution_service::channels::Rejection as R;
        match e {
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::AuditIsolation => Self::Unavailable(crate::Failure::AuditIsolation),
            R::AuditAdmission => Self::Unavailable(crate::Failure::AuditAdmission),
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict => Self::Conflict,
            R::Storage => Self::Unavailable(crate::Failure::Database),
            R::Protocol => Self::Unavailable(crate::Failure::Protocol),
            R::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            R::AuditIntegrity => Self::Unavailable(crate::Failure::AuditIntegrity),
            R::AuditContract => Self::Unavailable(crate::Failure::AuditContract),
            R::Audit => Self::Unavailable(crate::Failure::Audit),
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
            C::Missing => Self::Resource(
                rss_mdm_flow_service::resource_catalog::error::ResourceError::Missing,
            ),
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

impl From<rss_mdm_software_service::management::Error> for Error {
    fn from(error: rss_mdm_software_service::management::Error) -> Self {
        use rss_mdm_software_service::management::{Error as S, Failure as F};
        match error {
            S::Malformed => Self::Malformed,
            S::Forbidden => Self::Forbidden,
            S::Conflict => Self::Conflict,
            S::Unsupported => Self::Unsupported,
            S::ResourceMissing => Self::Resource(
                rss_mdm_flow_service::resource_catalog::error::ResourceError::Missing,
            ),
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

impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::CertificateRequest => Self::CertificateRequest,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Unsupported => Self::Unsupported,
            E::Execution(e) => Self::Execution(e),
            E::Resource(_) => Self::Resource(
                rss_mdm_flow_service::resource_catalog::error::ResourceError::Missing,
            ),
            E::Publication(e) => Self::Publication(e),
            E::Configuration(c) => Self::Configuration(match c {
                rss_mdm_execution_service::ConfigIssue::Audit => ConfigIssue::Audit,
                rss_mdm_execution_service::ConfigIssue::Execution => ConfigIssue::Execution,
                rss_mdm_execution_service::ConfigIssue::Content => ConfigIssue::Content,
                rss_mdm_execution_service::ConfigIssue::TaskSigning => ConfigIssue::TaskSigning,
                rss_mdm_execution_service::ConfigIssue::Publication => ConfigIssue::Publication,
                rss_mdm_execution_service::ConfigIssue::IdentityConfiguration => {
                    ConfigIssue::IdentityConfiguration
                }
            }),
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_execution_service::Failure::NativeProtection => Failure::NativeProtection,
                rss_mdm_execution_service::Failure::NativeInputIntegrity => {
                    Failure::NativeInputIntegrity
                }
                rss_mdm_execution_service::Failure::Timeline => Failure::Timeline,
                rss_mdm_execution_service::Failure::IdentityStorage => Failure::IdentityStorage,
                rss_mdm_execution_service::Failure::ResourceAdmission => Failure::ResourceAdmission,
                rss_mdm_execution_service::Failure::PlanningAdmission => Failure::PlanningAdmission,
                rss_mdm_execution_service::Failure::FlowAdmission => Failure::FlowAdmission,
                rss_mdm_execution_service::Failure::AutomationConnection => {
                    Failure::AutomationConnection
                }
                rss_mdm_execution_service::Failure::AutomationAdmission => {
                    Failure::AutomationAdmission
                }
                rss_mdm_execution_service::Failure::ContentStorage => Failure::ContentStorage,
                rss_mdm_execution_service::Failure::ContentMetadata => Failure::ContentMetadata,
                rss_mdm_execution_service::Failure::ContentInvariant => Failure::ContentInvariant,
                rss_mdm_execution_service::Failure::ContentDeadline => Failure::ContentDeadline,
                rss_mdm_execution_service::Failure::ContentCleanup => Failure::ContentCleanup,
                rss_mdm_execution_service::Failure::ContentImport => Failure::ContentImport,
                rss_mdm_execution_service::Failure::SoftwareCatalogStorage => {
                    Failure::SoftwareCatalogStorage
                }
                rss_mdm_execution_service::Failure::SoftwareCatalogInvariant => {
                    Failure::SoftwareCatalogInvariant
                }
                rss_mdm_execution_service::Failure::CommandStorage => Failure::CommandStorage,
                rss_mdm_execution_service::Failure::CommandInvariant => Failure::CommandInvariant,
                rss_mdm_execution_service::Failure::PlanningStorage => Failure::PlanningStorage,
                rss_mdm_execution_service::Failure::AssetsStorage => Failure::AssetsStorage,
                rss_mdm_execution_service::Failure::ComplianceStorage => Failure::ComplianceStorage,
                rss_mdm_execution_service::Failure::ResourceStorage => Failure::ResourceStorage,
                rss_mdm_execution_service::Failure::PublicationStorage => {
                    Failure::PublicationStorage
                }
                rss_mdm_execution_service::Failure::AutomationStorage => Failure::AutomationStorage,
                rss_mdm_execution_service::Failure::FlowStorage => Failure::FlowStorage,
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Database => Failure::Database,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::InventoryQuery => Failure::InventoryQuery,
                rss_mdm_execution_service::Failure::AssetCandidates => Failure::AssetCandidates,
                rss_mdm_execution_service::Failure::AssetSources => Failure::AssetSources,
                rss_mdm_execution_service::Failure::ManualQuery => Failure::ManualQuery,
                rss_mdm_execution_service::Failure::CollectionQuery => Failure::CollectionQuery,
                rss_mdm_execution_service::Failure::AssetObjectLimit => Failure::AssetObjectLimit,
                rss_mdm_execution_service::Failure::AssetSourceLimit => Failure::AssetSourceLimit,
                rss_mdm_execution_service::Failure::AssetBytesLimit => Failure::AssetBytesLimit,
                rss_mdm_execution_service::Failure::InventoryRuntime => Failure::InventoryRuntime,
                rss_mdm_execution_service::Failure::Clock => Failure::Clock,
                rss_mdm_execution_service::Failure::Capacity => Failure::Capacity,
                rss_mdm_execution_service::Failure::Runtime => Failure::Runtime,
                rss_mdm_execution_service::Failure::Protocol => Failure::Protocol,
            }),
        }
    }
}

impl From<rss_mdm_flow_service::Error> for Error {
    fn from(e: rss_mdm_flow_service::Error) -> Self {
        use rss_mdm_flow_service::Error as F;
        match e {
            F::Malformed => Self::Malformed,
            F::Planning(e) => Self::Planning(e),
            F::Resource(e) => Self::Resource(e),
            F::Conflict => Self::Conflict,
            F::CommitUnknown => Self::CommitUnknown,
            F::RollbackFailed => Self::RollbackFailed,
            F::Unauthorized => Self::Unauthorized,
            F::Forbidden => Self::Forbidden,
            F::NotFound => Self::NotFound,
            F::Unsupported => Self::Unsupported,
            F::Unavailable(f) => match f {
                rss_mdm_flow_service::Failure::Preparation(f) => {
                    rss_mdm_execution_service::Error::Unavailable(f).into()
                }
                rss_mdm_flow_service::Failure::PreparationConfiguration(c) => {
                    rss_mdm_execution_service::Error::Configuration(c).into()
                }
                rss_mdm_flow_service::Failure::PreparationContract => {
                    Self::Unavailable(Failure::NativeInputIntegrity)
                }
                rss_mdm_flow_service::Failure::Inventory(f) => {
                    rss_mdm_inventory_service::Error::Unavailable(f).into()
                }
                rss_mdm_flow_service::Failure::ResourceContent(e) => e.into(),
                rss_mdm_flow_service::Failure::ResourceSoftwareIntegrity => {
                    Self::Unavailable(Failure::SoftwareCatalogInvariant)
                }
                rss_mdm_flow_service::Failure::ResourceAdmission => {
                    Self::Unavailable(Failure::ResourceAdmission)
                }
                rss_mdm_flow_service::Failure::PlanningAdmission => {
                    Self::Unavailable(Failure::PlanningAdmission)
                }
                rss_mdm_flow_service::Failure::FlowAdmission => {
                    Self::Unavailable(Failure::FlowAdmission)
                }
                rss_mdm_flow_service::Failure::AutomationConnection => {
                    Self::Unavailable(Failure::AutomationConnection)
                }
                rss_mdm_flow_service::Failure::AutomationAdmission => {
                    Self::Unavailable(Failure::AutomationAdmission)
                }
                rss_mdm_flow_service::Failure::PlanningStorage => {
                    Self::Unavailable(Failure::PlanningStorage)
                }
                rss_mdm_flow_service::Failure::ResourceStorage => {
                    Self::Unavailable(Failure::ResourceStorage)
                }
                rss_mdm_flow_service::Failure::AutomationStorage => {
                    Self::Unavailable(Failure::AutomationStorage)
                }
                rss_mdm_flow_service::Failure::FlowStorage => {
                    Self::Unavailable(Failure::FlowStorage)
                }
                rss_mdm_flow_service::Failure::RequestDeadline => {
                    Self::Unavailable(Failure::RequestDeadline)
                }
                rss_mdm_flow_service::Failure::Database => Self::Unavailable(Failure::Database),
                rss_mdm_flow_service::Failure::Audit => Self::Unavailable(Failure::Audit),
                rss_mdm_flow_service::Failure::AuditIntegrity => {
                    Self::Unavailable(Failure::AuditIntegrity)
                }
                rss_mdm_flow_service::Failure::AuditIsolation => {
                    Self::Unavailable(Failure::AuditIsolation)
                }
                rss_mdm_flow_service::Failure::AuditContract => {
                    Self::Unavailable(Failure::AuditContract)
                }
                rss_mdm_flow_service::Failure::AuditAdmission => {
                    Self::Unavailable(Failure::AuditAdmission)
                }
                rss_mdm_flow_service::Failure::AssetObjectLimit => {
                    Self::Unavailable(Failure::AssetObjectLimit)
                }
                rss_mdm_flow_service::Failure::AssetSourceLimit => {
                    Self::Unavailable(Failure::AssetSourceLimit)
                }
                rss_mdm_flow_service::Failure::AssetBytesLimit => {
                    Self::Unavailable(Failure::AssetBytesLimit)
                }
                rss_mdm_flow_service::Failure::Clock => Self::Unavailable(Failure::Clock),
                rss_mdm_flow_service::Failure::Capacity => Self::Unavailable(Failure::Capacity),
                rss_mdm_flow_service::Failure::Runtime => Self::Unavailable(Failure::Runtime),
            },
        }
    }
}
impl From<rss_mdm_execution_service::queries::QueryError> for Error {
    fn from(e: rss_mdm_execution_service::queries::QueryError) -> Self {
        use rss_mdm_execution_service::queries::{Missing, QueryError as Q};
        match e {
            Q::Malformed => Self::Malformed, Q::Unauthorized => Self::Unauthorized, Q::Forbidden => Self::Forbidden, Q::Conflict => Self::Conflict,
            Q::Unsupported => Self::Unsupported, Q::CommitUnknown => Self::CommitUnknown, Q::RollbackFailed => Self::RollbackFailed,
            Q::Unavailable(f) => rss_mdm_execution_service::Error::Unavailable(f).into(),
            Q::Missing(m) => match m {
                Missing::Policy => Self::Planning(rss_mdm_flow_service::planning::error::PlanningError::Missing(rss_mdm_flow_service::planning::error::Missing::Policy)),
                Missing::Inventory => Self::NotFound, Missing::Resource => Self::Resource(rss_mdm_flow_service::resource_catalog::error::ResourceError::Missing),
                Missing::Operation => Self::Execution(rss_mdm_execution_service::missing::ExecutionError::MissingOperation),
                Missing::Task => Self::Execution(rss_mdm_execution_service::missing::ExecutionError::MissingTask),
                Missing::SoftwareSource => Self::Publication(rss_mdm_software_service::management::publication::error::PublicationError::MissingSource),
                Missing::SoftwareCandidate => Self::Publication(rss_mdm_software_service::management::publication::error::PublicationError::MissingCandidate),
            },
        }
    }
}
