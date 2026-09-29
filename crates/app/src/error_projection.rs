//! Capability failures projected into CLI, startup and lifecycle diagnostics.
use crate::Error;
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
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(error: crate::enrollment::EnrollmentError) -> Self {
        match error {
            crate::enrollment::EnrollmentError::InvalidPassword => Self::Malformed,
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

pub(crate) fn audit_deadline(outcome: rss_mdm_audit_integration::WriteOutcome) -> crate::Error {
    match outcome {
        rss_mdm_audit_integration::WriteOutcome::Unknown
        | rss_mdm_audit_integration::WriteOutcome::Committed => crate::Error::CommitUnknown,
        rss_mdm_audit_integration::WriteOutcome::RollbackFailed => crate::Error::RollbackFailed,
        rss_mdm_audit_integration::WriteOutcome::RolledBack
        | rss_mdm_audit_integration::WriteOutcome::CommitNotStarted => {
            crate::Error::Unavailable(crate::Failure::RequestDeadline)
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
        match error {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            rss_mdm_audit_integration::Error::Audit(error) if error.is_interrupted() => {
                Self::Unavailable(crate::Failure::RequestDeadline)
            }
            rss_mdm_audit_integration::Error::Receipt => {
                Self::Unavailable(crate::Failure::AuditIntegrity)
            }
            rss_mdm_audit_integration::Error::Admission => {
                Self::Unavailable(crate::Failure::AuditAdmission)
            }
            rss_mdm_audit_integration::Error::Isolation => {
                Self::Unavailable(crate::Failure::AuditIsolation)
            }
            rss_mdm_audit_integration::Error::Fact(_) => {
                Self::Unavailable(crate::Failure::AuditContract)
            }
            rss_mdm_audit_integration::Error::Audit(error) => {
                use rss_audit_postgres::Error as Audit;
                Self::Unavailable(match error {
                    Audit::Admission(_) => crate::Failure::AuditAdmission,
                    Audit::Conflict | Audit::StorageContract | Audit::IntegrityRequired => {
                        crate::Failure::AuditIntegrity
                    }
                    Audit::Ledger(error) => match error {
                        rss_ledger_postgres::Error::Storage(_)
                        | rss_ledger_postgres::Error::Messaging(_) => crate::Failure::Audit,
                        rss_ledger_postgres::Error::Admission(_) => crate::Failure::AuditAdmission,
                        _ => crate::Failure::AuditIntegrity,
                    },
                    Audit::InvalidBound
                    | Audit::ScopeMismatch
                    | Audit::Protocol(_)
                    | Audit::ReadBudgetExceeded => crate::Failure::AuditContract,
                    _ => crate::Failure::Audit,
                })
            }
        }
    }
}

/// Independent request settlement cannot overwrite the protected operation's certainty.

/// Diagnostic cause is independent of the protected operation's settlement state.

#[cfg(test)]
#[path = "../tests/error_projection/unit.rs"]
mod tests;

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
            I::Group(m) => {
                Self::Planning(crate::planning::error::PlanningError::Missing(match m {
                    rss_mdm_inventory_service::groups::GroupMissing::Group => {
                        crate::planning::error::Missing::Group
                    }
                    rss_mdm_inventory_service::groups::GroupMissing::Rule => {
                        crate::planning::error::Missing::Rule
                    }
                    rss_mdm_inventory_service::groups::GroupMissing::Device => {
                        crate::planning::error::Missing::Device
                    }
                }))
            }
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

impl From<crate::execution::channels::Rejection> for Error {
    fn from(e: crate::execution::channels::Rejection) -> Self {
        use crate::execution::channels::Rejection as R;
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
impl From<Error> for crate::execution::channels::Rejection {
    fn from(e: Error) -> Self {
        match e {
            Error::CommitUnknown => Self::CommitUnknown,
            Error::RollbackFailed => Self::RollbackFailed,
            Error::Unavailable(crate::Failure::AuditIsolation) => Self::AuditIsolation,
            Error::Unavailable(crate::Failure::AuditAdmission) => Self::AuditAdmission,
            Error::Malformed | Error::CertificateRequest => Self::Malformed,
            Error::Unauthorized => Self::Unauthorized,
            Error::Forbidden => Self::Forbidden,
            Error::Conflict => Self::Conflict,
            Error::Unavailable(crate::Failure::Protocol) => Self::Protocol,
            Error::Unavailable(crate::Failure::RequestDeadline) => Self::Deadline,
            Error::Unavailable(crate::Failure::AuditIntegrity) => Self::AuditIntegrity,
            Error::Unavailable(crate::Failure::AuditContract) => Self::AuditContract,
            Error::Unavailable(crate::Failure::Audit) => Self::Audit,
            _ => Self::Storage,
        }
    }
}

impl From<rss_mdm_flow_service::ConfigIssue> for crate::ConfigIssue {
    fn from(v: rss_mdm_flow_service::ConfigIssue) -> Self {
        match v {
            rss_mdm_flow_service::ConfigIssue::Audit => Self::Audit,
            rss_mdm_flow_service::ConfigIssue::AppleListeners => Self::AppleListeners,
            rss_mdm_flow_service::ConfigIssue::AppleScep => Self::AppleScep,
            rss_mdm_flow_service::ConfigIssue::AppleProfileSigner => Self::AppleProfileSigner,
            rss_mdm_flow_service::ConfigIssue::AppleApns => Self::AppleApns,
            rss_mdm_flow_service::ConfigIssue::AppleChallengeWebhook => Self::AppleChallengeWebhook,
            rss_mdm_flow_service::ConfigIssue::AppleNotifyWebhook => Self::AppleNotifyWebhook,
            rss_mdm_flow_service::ConfigIssue::Execution => Self::Execution,
            rss_mdm_flow_service::ConfigIssue::Content => Self::Content,
            rss_mdm_flow_service::ConfigIssue::TaskSigning => Self::TaskSigning,
            rss_mdm_flow_service::ConfigIssue::Flow => Self::Flow,
            rss_mdm_flow_service::ConfigIssue::Publication => Self::Publication,
            rss_mdm_flow_service::ConfigIssue::Listen => Self::Listen,
            rss_mdm_flow_service::ConfigIssue::AccessDatabase => Self::AccessDatabase,
            rss_mdm_flow_service::ConfigIssue::RuntimeDatabase => Self::RuntimeDatabase,
            rss_mdm_flow_service::ConfigIssue::DatabaseAddress => Self::DatabaseAddress,
            rss_mdm_flow_service::ConfigIssue::DatabasePassword => Self::DatabasePassword,
            rss_mdm_flow_service::ConfigIssue::DatabaseCa => Self::DatabaseCa,
            rss_mdm_flow_service::ConfigIssue::ProductOrigin => Self::ProductOrigin,
            rss_mdm_flow_service::ConfigIssue::Instance => Self::Instance,
            rss_mdm_flow_service::ConfigIssue::IdentityDatabase => Self::IdentityDatabase,
            rss_mdm_flow_service::ConfigIssue::IdentityAuditDatabase => Self::IdentityAuditDatabase,
            rss_mdm_flow_service::ConfigIssue::IdentityConfiguration => Self::IdentityConfiguration,
            rss_mdm_flow_service::ConfigIssue::Issuer => Self::Issuer,
            rss_mdm_flow_service::ConfigIssue::Tenant => Self::Tenant,
            rss_mdm_flow_service::ConfigIssue::FileAccess => Self::FileAccess,
            rss_mdm_flow_service::ConfigIssue::FileShape => Self::FileShape,
            rss_mdm_flow_service::ConfigIssue::FileSize => Self::FileSize,
            rss_mdm_flow_service::ConfigIssue::SecretEncoding => Self::SecretEncoding,
            rss_mdm_flow_service::ConfigIssue::SecretContents => Self::SecretContents,
            rss_mdm_flow_service::ConfigIssue::Budget => Self::Budget,
            rss_mdm_flow_service::ConfigIssue::WindowsListeners => Self::WindowsListeners,
            rss_mdm_flow_service::ConfigIssue::EnrollmentCa => Self::EnrollmentCa,
            rss_mdm_flow_service::ConfigIssue::NativeTls => Self::NativeTls,
            rss_mdm_flow_service::ConfigIssue::ProtocolKey => Self::ProtocolKey,
        }
    }
}

impl From<crate::ConfigIssue> for rss_mdm_flow_service::ConfigIssue {
    fn from(v: crate::ConfigIssue) -> Self {
        match v {
            crate::ConfigIssue::Audit => Self::Audit,
            crate::ConfigIssue::AppleListeners => Self::AppleListeners,
            crate::ConfigIssue::AppleScep => Self::AppleScep,
            crate::ConfigIssue::AppleProfileSigner => Self::AppleProfileSigner,
            crate::ConfigIssue::AppleApns => Self::AppleApns,
            crate::ConfigIssue::AppleChallengeWebhook => Self::AppleChallengeWebhook,
            crate::ConfigIssue::AppleNotifyWebhook => Self::AppleNotifyWebhook,
            crate::ConfigIssue::Execution => Self::Execution,
            crate::ConfigIssue::Content => Self::Content,
            crate::ConfigIssue::TaskSigning => Self::TaskSigning,
            crate::ConfigIssue::Flow => Self::Flow,
            crate::ConfigIssue::Publication => Self::Publication,
            crate::ConfigIssue::Listen => Self::Listen,
            crate::ConfigIssue::AccessDatabase => Self::AccessDatabase,
            crate::ConfigIssue::RuntimeDatabase => Self::RuntimeDatabase,
            crate::ConfigIssue::DatabaseAddress => Self::DatabaseAddress,
            crate::ConfigIssue::DatabasePassword => Self::DatabasePassword,
            crate::ConfigIssue::DatabaseCa => Self::DatabaseCa,
            crate::ConfigIssue::ProductOrigin => Self::ProductOrigin,
            crate::ConfigIssue::Instance => Self::Instance,
            crate::ConfigIssue::IdentityDatabase => Self::IdentityDatabase,
            crate::ConfigIssue::IdentityAuditDatabase => Self::IdentityAuditDatabase,
            crate::ConfigIssue::IdentityConfiguration => Self::IdentityConfiguration,
            crate::ConfigIssue::Issuer => Self::Issuer,
            crate::ConfigIssue::Tenant => Self::Tenant,
            crate::ConfigIssue::FileAccess => Self::FileAccess,
            crate::ConfigIssue::FileShape => Self::FileShape,
            crate::ConfigIssue::FileSize => Self::FileSize,
            crate::ConfigIssue::SecretEncoding => Self::SecretEncoding,
            crate::ConfigIssue::SecretContents => Self::SecretContents,
            crate::ConfigIssue::Budget => Self::Budget,
            crate::ConfigIssue::WindowsListeners => Self::WindowsListeners,
            crate::ConfigIssue::EnrollmentCa => Self::EnrollmentCa,
            crate::ConfigIssue::NativeTls => Self::NativeTls,
            crate::ConfigIssue::ProtocolKey => Self::ProtocolKey,
        }
    }
}

impl From<rss_mdm_flow_service::Failure> for crate::Failure {
    fn from(v: rss_mdm_flow_service::Failure) -> Self {
        match v {
            rss_mdm_flow_service::Failure::ResourceAdmission => Self::ResourceAdmission,
            rss_mdm_flow_service::Failure::PlanningAdmission => Self::PlanningAdmission,
            rss_mdm_flow_service::Failure::FlowSource => Self::FlowSource,
            rss_mdm_flow_service::Failure::FlowConnection => Self::FlowConnection,
            rss_mdm_flow_service::Failure::FlowAdmission => Self::FlowAdmission,
            rss_mdm_flow_service::Failure::AutomationConnection => Self::AutomationConnection,
            rss_mdm_flow_service::Failure::AutomationAdmission => Self::AutomationAdmission,
            rss_mdm_flow_service::Failure::ApplePush => Self::ApplePush,
            rss_mdm_flow_service::Failure::AppleStorage => Self::AppleStorage,
            rss_mdm_flow_service::Failure::AppleInvariant => Self::AppleInvariant,
            rss_mdm_flow_service::Failure::ContentStorage => Self::ContentStorage,
            rss_mdm_flow_service::Failure::ContentMetadata => Self::ContentMetadata,
            rss_mdm_flow_service::Failure::ContentInvariant => Self::ContentInvariant,
            rss_mdm_flow_service::Failure::ContentDeadline => Self::ContentDeadline,
            rss_mdm_flow_service::Failure::ContentCleanup => Self::ContentCleanup,
            rss_mdm_flow_service::Failure::ContentImport => Self::ContentImport,
            rss_mdm_flow_service::Failure::SoftwareCatalogStorage => Self::SoftwareCatalogStorage,
            rss_mdm_flow_service::Failure::SoftwareCatalogInvariant => {
                Self::SoftwareCatalogInvariant
            }
            rss_mdm_flow_service::Failure::CommandStorage => Self::CommandStorage,
            rss_mdm_flow_service::Failure::CommandInvariant => Self::CommandInvariant,
            rss_mdm_flow_service::Failure::PlanningStorage => Self::PlanningStorage,
            rss_mdm_flow_service::Failure::AssetsStorage => Self::AssetsStorage,
            rss_mdm_flow_service::Failure::ComplianceStorage => Self::ComplianceStorage,
            rss_mdm_flow_service::Failure::ResourceStorage => Self::ResourceStorage,
            rss_mdm_flow_service::Failure::PublicationStorage => Self::PublicationStorage,
            rss_mdm_flow_service::Failure::AutomationStorage => Self::AutomationStorage,
            rss_mdm_flow_service::Failure::FlowStorage => Self::FlowStorage,
            rss_mdm_flow_service::Failure::RequestDeadline => Self::RequestDeadline,
            rss_mdm_flow_service::Failure::IdentityStorage => Self::IdentityStorage,
            rss_mdm_flow_service::Failure::IdentityValidation => Self::IdentityValidation,
            rss_mdm_flow_service::Failure::IdentityDeadline => Self::IdentityDeadline,
            rss_mdm_flow_service::Failure::IdentityProtocol => Self::IdentityProtocol,
            rss_mdm_flow_service::Failure::InventoryPool => Self::InventoryPool,
            rss_mdm_flow_service::Failure::Database => Self::Database,
            rss_mdm_flow_service::Failure::AccessAdmission => Self::AccessAdmission,
            rss_mdm_flow_service::Failure::Audit => Self::Audit,
            rss_mdm_flow_service::Failure::AuditIntegrity => Self::AuditIntegrity,
            rss_mdm_flow_service::Failure::AuditIsolation => Self::AuditIsolation,
            rss_mdm_flow_service::Failure::AuditContract => Self::AuditContract,
            rss_mdm_flow_service::Failure::AuditAdmission => Self::AuditAdmission,
            rss_mdm_flow_service::Failure::InventoryQuery => Self::InventoryQuery,
            rss_mdm_flow_service::Failure::AssetCandidates => Self::AssetCandidates,
            rss_mdm_flow_service::Failure::AssetSources => Self::AssetSources,
            rss_mdm_flow_service::Failure::ManualQuery => Self::ManualQuery,
            rss_mdm_flow_service::Failure::CollectionQuery => Self::CollectionQuery,
            rss_mdm_flow_service::Failure::AssetObjectLimit => Self::AssetObjectLimit,
            rss_mdm_flow_service::Failure::AssetSourceLimit => Self::AssetSourceLimit,
            rss_mdm_flow_service::Failure::AssetBytesLimit => Self::AssetBytesLimit,
            rss_mdm_flow_service::Failure::InventoryRuntime => Self::InventoryRuntime,
            rss_mdm_flow_service::Failure::Observation => Self::Observation,
            rss_mdm_flow_service::Failure::Clock => Self::Clock,
            rss_mdm_flow_service::Failure::Capacity => Self::Capacity,
            rss_mdm_flow_service::Failure::Runtime => Self::Runtime,
            rss_mdm_flow_service::Failure::Certificate => Self::Certificate,
            rss_mdm_flow_service::Failure::Protocol => Self::Protocol,
        }
    }
}

impl From<crate::Failure> for rss_mdm_flow_service::Failure {
    fn from(v: crate::Failure) -> Self {
        match v {
            crate::Failure::ResourceAdmission => Self::ResourceAdmission,
            crate::Failure::PlanningAdmission => Self::PlanningAdmission,
            crate::Failure::FlowSource => Self::FlowSource,
            crate::Failure::FlowConnection => Self::FlowConnection,
            crate::Failure::FlowAdmission => Self::FlowAdmission,
            crate::Failure::AutomationConnection => Self::AutomationConnection,
            crate::Failure::AutomationAdmission => Self::AutomationAdmission,
            crate::Failure::ApplePush => Self::ApplePush,
            crate::Failure::AppleStorage => Self::AppleStorage,
            crate::Failure::AppleInvariant => Self::AppleInvariant,
            crate::Failure::ContentStorage => Self::ContentStorage,
            crate::Failure::ContentMetadata => Self::ContentMetadata,
            crate::Failure::ContentInvariant => Self::ContentInvariant,
            crate::Failure::ContentDeadline => Self::ContentDeadline,
            crate::Failure::ContentCleanup => Self::ContentCleanup,
            crate::Failure::ContentImport => Self::ContentImport,
            crate::Failure::SoftwareCatalogStorage => Self::SoftwareCatalogStorage,
            crate::Failure::SoftwareCatalogInvariant => Self::SoftwareCatalogInvariant,
            crate::Failure::CommandStorage => Self::CommandStorage,
            crate::Failure::CommandInvariant => Self::CommandInvariant,
            crate::Failure::PlanningStorage => Self::PlanningStorage,
            crate::Failure::AssetsStorage => Self::AssetsStorage,
            crate::Failure::ComplianceStorage => Self::ComplianceStorage,
            crate::Failure::ResourceStorage => Self::ResourceStorage,
            crate::Failure::PublicationStorage => Self::PublicationStorage,
            crate::Failure::AutomationStorage => Self::AutomationStorage,
            crate::Failure::FlowStorage => Self::FlowStorage,
            crate::Failure::RequestDeadline => Self::RequestDeadline,
            crate::Failure::IdentityStorage => Self::IdentityStorage,
            crate::Failure::IdentityValidation => Self::IdentityValidation,
            crate::Failure::IdentityDeadline => Self::IdentityDeadline,
            crate::Failure::IdentityProtocol => Self::IdentityProtocol,
            crate::Failure::InventoryPool => Self::InventoryPool,
            crate::Failure::Database => Self::Database,
            crate::Failure::AccessAdmission => Self::AccessAdmission,
            crate::Failure::Audit => Self::Audit,
            crate::Failure::AuditIntegrity => Self::AuditIntegrity,
            crate::Failure::AuditIsolation => Self::AuditIsolation,
            crate::Failure::AuditContract => Self::AuditContract,
            crate::Failure::AuditAdmission => Self::AuditAdmission,
            crate::Failure::InventoryQuery => Self::InventoryQuery,
            crate::Failure::AssetCandidates => Self::AssetCandidates,
            crate::Failure::AssetSources => Self::AssetSources,
            crate::Failure::ManualQuery => Self::ManualQuery,
            crate::Failure::CollectionQuery => Self::CollectionQuery,
            crate::Failure::AssetObjectLimit => Self::AssetObjectLimit,
            crate::Failure::AssetSourceLimit => Self::AssetSourceLimit,
            crate::Failure::AssetBytesLimit => Self::AssetBytesLimit,
            crate::Failure::InventoryRuntime => Self::InventoryRuntime,
            crate::Failure::Observation => Self::Observation,
            crate::Failure::Clock => Self::Clock,
            crate::Failure::Capacity => Self::Capacity,
            crate::Failure::Runtime => Self::Runtime,
            crate::Failure::Certificate => Self::Certificate,
            crate::Failure::Protocol => Self::Protocol,
        }
    }
}

impl From<rss_mdm_flow_service::Error> for crate::Error {
    fn from(v: rss_mdm_flow_service::Error) -> Self {
        match v {
            rss_mdm_flow_service::Error::Malformed => Self::Malformed,
            rss_mdm_flow_service::Error::CertificateRequest => Self::CertificateRequest,
            rss_mdm_flow_service::Error::Conflict => Self::Conflict,
            rss_mdm_flow_service::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_flow_service::Error::RollbackFailed => Self::RollbackFailed,
            rss_mdm_flow_service::Error::Unauthorized => Self::Unauthorized,
            rss_mdm_flow_service::Error::Forbidden => Self::Forbidden,
            rss_mdm_flow_service::Error::NotFound => Self::NotFound,
            rss_mdm_flow_service::Error::Unsupported => Self::Unsupported,
            rss_mdm_flow_service::Error::Configuration(v) => Self::Configuration(v.into()),
            rss_mdm_flow_service::Error::Planning(v) => Self::Planning(v.into()),
            rss_mdm_flow_service::Error::Resource(v) => Self::Resource(v.into()),
            rss_mdm_flow_service::Error::Execution(v) => Self::Execution(v.into()),
            rss_mdm_flow_service::Error::Publication(v) => Self::Publication(v.into()),
            rss_mdm_flow_service::Error::Unavailable(v) => Self::Unavailable(v.into()),
        }
    }
}

impl From<crate::Error> for rss_mdm_flow_service::Error {
    fn from(v: crate::Error) -> Self {
        match v {
            crate::Error::Malformed => Self::Malformed,
            crate::Error::CertificateRequest => Self::CertificateRequest,
            crate::Error::Conflict => Self::Conflict,
            crate::Error::CommitUnknown => Self::CommitUnknown,
            crate::Error::RollbackFailed => Self::RollbackFailed,
            crate::Error::Unauthorized => Self::Unauthorized,
            crate::Error::Forbidden => Self::Forbidden,
            crate::Error::NotFound => Self::NotFound,
            crate::Error::Unsupported => Self::Unsupported,
            crate::Error::Configuration(v) => Self::Configuration(v.into()),
            crate::Error::Planning(v) => Self::Planning(v.into()),
            crate::Error::Resource(v) => Self::Resource(v.into()),
            crate::Error::Execution(v) => Self::Execution(v.into()),
            crate::Error::Publication(v) => Self::Publication(v.into()),
            crate::Error::Unavailable(v) => Self::Unavailable(v.into()),
        }
    }
}

impl From<rss_mdm_policy::Error> for Error {
    fn from(e: rss_mdm_policy::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}

impl From<rss_mdm_windows_channel::Error> for Error {
    fn from(e: rss_mdm_windows_channel::Error) -> Self {
        use rss_mdm_windows_channel::Error as Native;
        match e {
            Native::Malformed => Self::Malformed,
            Native::CertificateRequest => Self::CertificateRequest,
            Native::Conflict => Self::Conflict,
            Native::CommitUnknown => Self::CommitUnknown,
            Native::RollbackFailed => Self::RollbackFailed,
            Native::Unauthorized => Self::Unauthorized,
            Native::Forbidden => Self::Forbidden,
            Native::NotFound => Self::NotFound,
            Native::Unsupported => Self::Unsupported,
            Native::Configuration(rss_mdm_windows_channel::ConfigIssue::ProtocolKey) => {
                Self::Configuration(crate::ConfigIssue::ProtocolKey)
            }
            Native::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_windows_channel::Failure::Audit => crate::Failure::Audit,
                rss_mdm_windows_channel::Failure::AuditAdmission => crate::Failure::AuditAdmission,
                rss_mdm_windows_channel::Failure::AuditContract => crate::Failure::AuditContract,
                rss_mdm_windows_channel::Failure::AuditIntegrity => crate::Failure::AuditIntegrity,
                rss_mdm_windows_channel::Failure::AuditIsolation => crate::Failure::AuditIsolation,
                rss_mdm_windows_channel::Failure::Capacity => crate::Failure::Capacity,
                rss_mdm_windows_channel::Failure::Certificate => crate::Failure::Certificate,
                rss_mdm_windows_channel::Failure::Clock => crate::Failure::Clock,
                rss_mdm_windows_channel::Failure::Database => crate::Failure::Database,
                rss_mdm_windows_channel::Failure::Protocol => crate::Failure::Protocol,
                rss_mdm_windows_channel::Failure::RequestDeadline => {
                    crate::Failure::RequestDeadline
                }
            }),
            Native::Service(e) => e.into(),
        }
    }
}

impl From<rss_mdm_apple_channel::Error> for Error {
    fn from(e: rss_mdm_apple_channel::Error) -> Self {
        use rss_mdm_apple_channel::Error as Native;
        match e {
            Native::Malformed => Self::Malformed,
            Native::CertificateRequest => Self::CertificateRequest,
            Native::Conflict => Self::Conflict,
            Native::CommitUnknown => Self::CommitUnknown,
            Native::RollbackFailed => Self::RollbackFailed,
            Native::Unauthorized => Self::Unauthorized,
            Native::Forbidden => Self::Forbidden,
            Native::NotFound => Self::NotFound,
            Native::Unsupported => Self::Unsupported,
            Native::Configuration(rss_mdm_apple_channel::ConfigIssue::AppleApns) => {
                Self::Configuration(crate::ConfigIssue::AppleApns)
            }
            Native::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_apple_channel::Failure::AppleInvariant => crate::Failure::AppleInvariant,
                rss_mdm_apple_channel::Failure::ApplePush => crate::Failure::ApplePush,
                rss_mdm_apple_channel::Failure::AppleStorage => crate::Failure::AppleStorage,
                rss_mdm_apple_channel::Failure::Audit => crate::Failure::Audit,
                rss_mdm_apple_channel::Failure::AuditAdmission => crate::Failure::AuditAdmission,
                rss_mdm_apple_channel::Failure::AuditContract => crate::Failure::AuditContract,
                rss_mdm_apple_channel::Failure::AuditIntegrity => crate::Failure::AuditIntegrity,
                rss_mdm_apple_channel::Failure::AuditIsolation => crate::Failure::AuditIsolation,
                rss_mdm_apple_channel::Failure::Certificate => crate::Failure::Certificate,
                rss_mdm_apple_channel::Failure::Database => crate::Failure::Database,
                rss_mdm_apple_channel::Failure::Protocol => crate::Failure::Protocol,
                rss_mdm_apple_channel::Failure::RequestDeadline => crate::Failure::RequestDeadline,
            }),
            Native::Service(e) => e.into(),
        }
    }
}

impl From<rss_mdm_management_http::Error> for Error {
    fn from(e: rss_mdm_management_http::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
