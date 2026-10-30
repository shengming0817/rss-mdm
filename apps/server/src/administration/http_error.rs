//! HTTP projection of application-owned failures; service code never constructs HTTP errors.
use crate::{Error,Failure};
use rss_mdm_management_http::{Error as Http,Failure as HttpFailure};
impl From<Error> for Http {
    fn from(error: Error) -> Self {
        match error {
            Error::Webhook(error) => error.into(),
            Error::NotFound => Self::NotFound,
            Error::FirstUseNotReady => Self::FirstUseNotReady,
            Error::FirstUseOperationMissing => Self::FirstUseOperationMissing,
            Error::Malformed => Self::Malformed,
            Error::Unsupported => Self::Unsupported,
            Error::Unauthorized => Self::Unauthorized,
            Error::Forbidden => Self::Forbidden,
            Error::Conflict => Self::Conflict,
            Error::CommitUnknown => Self::CommitUnknown,
            Error::RollbackFailed => Self::RollbackFailed,
            Error::CertificateRequest => Self::CertificateRequest,
            Error::Resource(error) => error.into(),
            Error::Policy(error) => error.into(),
            Error::Scope(error) => error.into(),
            Error::Execution(error) => error.into(),
            Error::Authorization(error) => error.into(),
            Error::Registration(error) => error.into(),
            Error::Inventory(error) => error.into(),
            Error::Software(error) => error.into(),
            Error::Content(error) => error.into(),
            Error::ContentRequest(error) => error.into(),
            Error::Http(error) => error,
            Error::Configuration(_) => Self::Configuration(rss_mdm_management_http::ConfigIssue::IdentityConfiguration),
            Error::Unavailable(reason) => Self::Unavailable(match reason {
                Failure::CursorAdmission => HttpFailure::Database,
                Failure::ContentStorage => HttpFailure::ContentStorage,
                Failure::ContentMetadata => HttpFailure::ContentMetadata,
                Failure::ContentInvariant => HttpFailure::ContentInvariant,
                Failure::ContentDeadline => HttpFailure::ContentDeadline,
                Failure::ContentCleanup => HttpFailure::ContentCleanup,
                Failure::CommandStorage => HttpFailure::CommandStorage,
                Failure::CommandInvariant => HttpFailure::CommandInvariant,
                Failure::PlanningStorage => HttpFailure::PlanningStorage,
                Failure::RequestDeadline => HttpFailure::RequestDeadline,
                Failure::IdentityStorage => HttpFailure::IdentityStorage,
                Failure::InventoryPool => HttpFailure::Database,
                Failure::Database => HttpFailure::Database,
                Failure::AccessAdmission => HttpFailure::Database,
                Failure::Audit => HttpFailure::Audit,
                Failure::AuditIntegrity => HttpFailure::AuditIntegrity,
                Failure::AuditIsolation => HttpFailure::AuditIsolation,
                Failure::AuditAdmission => HttpFailure::AuditAdmission,
                Failure::AuditContract => HttpFailure::AuditContract,
                Failure::InventoryQuery => HttpFailure::InventoryQuery,
                Failure::ManualQuery => HttpFailure::ManualQuery,
                Failure::CollectionQuery => HttpFailure::CollectionQuery,
                Failure::AssetObjectLimit => HttpFailure::AssetObjectLimit,
                Failure::AssetSourceLimit => HttpFailure::AssetSourceLimit,
                Failure::AssetBytesLimit => HttpFailure::AssetBytesLimit,
                Failure::Clock => HttpFailure::Clock,
                Failure::Capacity => HttpFailure::Capacity,
                Failure::Runtime => HttpFailure::Runtime,
                Failure::Certificate => HttpFailure::Database,
            }),
            Error::Apple(error) => {
                use rss_mdm_apple_channel::{Error as E,Failure as F};
                match error {
                    E::Malformed => Self::Malformed,
                    E::Unauthorized => Self::Unauthorized,
                    E::Forbidden => Self::Forbidden,
                    E::Conflict => Self::Conflict,
                    E::CommitUnknown => Self::CommitUnknown,
                    E::RollbackFailed => Self::RollbackFailed,
                    E::Unavailable(F::RequestDeadline) => Self::Unavailable(HttpFailure::RequestDeadline),
                    E::Unavailable(F::Audit) => Self::Unavailable(HttpFailure::Audit),
                    E::Unavailable(F::AuditIntegrity) => Self::Unavailable(HttpFailure::AuditIntegrity),
                    E::Unavailable(F::AuditAdmission) => Self::Unavailable(HttpFailure::AuditAdmission),
                    E::Unavailable(F::AuditIsolation) => Self::Unavailable(HttpFailure::AuditIsolation),
                    E::Unavailable(F::AuditContract) => Self::Unavailable(HttpFailure::AuditContract),
                    _ => Self::Unavailable(HttpFailure::Database),
                }
            }
            Error::Windows(error) => {
                use rss_mdm_windows_channel::{Error as E,Failure as F};
                match error {
                    E::Malformed => Self::Malformed,
                    E::Unauthorized => Self::Unauthorized,
                    E::Forbidden => Self::Forbidden,
                    E::Conflict => Self::Conflict,
                    E::CommitUnknown => Self::CommitUnknown,
                    E::RollbackFailed => Self::RollbackFailed,
                    E::Unavailable(F::RequestDeadline) => Self::Unavailable(HttpFailure::RequestDeadline),
                    E::Unavailable(F::Audit) => Self::Unavailable(HttpFailure::Audit),
                    E::Unavailable(F::AuditIntegrity) => Self::Unavailable(HttpFailure::AuditIntegrity),
                    E::Unavailable(F::AuditAdmission) => Self::Unavailable(HttpFailure::AuditAdmission),
                    E::Unavailable(F::AuditIsolation) => Self::Unavailable(HttpFailure::AuditIsolation),
                    E::Unavailable(F::AuditContract) => Self::Unavailable(HttpFailure::AuditContract),
                    _ => Self::Unavailable(HttpFailure::Database),
                }
            }
        }
    }
}
