//! The retirement coordinator borrows Policy cleanup on its original transaction.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_service::control::{
    Error, Failure,
    configuration_cleanup::*,
    transaction::{Fault, Result},
};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin, sync::Arc};
use uuid::Uuid;
pub(crate) struct Cleanup(pub Arc<rss_mdm_policy_service::configuration::Transactions>);
impl ConfigurationCleanup for Cleanup {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
        device: &'a str,
        audit: &'a RequestAudit,
    ) -> Pin<Box<dyn Future<Output = Result<Progress>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .retirement_cleanup_in(tx, retirement, device, audit)
                .await
                .map(|v| Progress {
                    pending: v.pending,
                    blocker: v.blocker,
                })
                .map_err(|e| match e {
                    rss_mdm_policy_service::transaction::Fault::Storage(e) => Fault::Storage(e),
                    rss_mdm_policy_service::transaction::Fault::Sql(e) => Fault::Sql(e),
                    rss_mdm_policy_service::transaction::Fault::Request(e) => error(e).into(),
                })
        })
    }
}

pub(super) fn error(e: rss_mdm_policy_service::Error) -> rss_mdm_device_service::control::Error {
    use rss_mdm_policy_service::{Error as P, Failure as F};
    match e {
        P::CommitUnknown => Error::CommitUnknown,
        P::RollbackFailed => Error::RollbackFailed,
        P::ReadConflict => Error::ReadConflict,
        P::Conflict => Error::Conflict,
        P::WindowsDeclaredEnrollmentNotReady => Error::WindowsDeclaredEnrollmentNotReady,
        P::Malformed => Error::Malformed,
        P::Unauthorized => Error::Unauthorized,
        P::Forbidden => Error::Forbidden,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => Error::NotFound,
        P::MdmSoftwareDisabled => Error::Unsupported,
        P::Unsupported => Error::Unsupported,
        P::Unavailable(F::Inventory(f)) => rss_mdm_inventory_service::Error::Unavailable(f).into(),
        P::Unavailable(F::PreparationConfiguration) => {
            Error::Configuration(rss_mdm_device_service::control::ConfigIssue::CommandStorage)
        }
        P::Unavailable(f) => Error::Unavailable(match f {
            F::Preparation => Failure::CommandStorage,
            F::PreparationContract => Failure::NativeInputIntegrity,
            F::SoftwareIntegrity => Failure::SoftwareCatalogInvariant,
            F::PolicyAdmission => Failure::PlanningAdmission,
            F::PolicyStorage | F::PolicyTransient => Failure::PlanningStorage,
            F::AutomationConnection => Failure::AutomationConnection,
            F::AutomationAdmission => Failure::AutomationAdmission,
            F::AutomationStorage => Failure::AutomationStorage,
            F::RequestDeadline => Failure::RequestDeadline,
            F::Database => Failure::Database,
            F::Audit => Failure::Audit,
            F::AuditIntegrity => Failure::AuditIntegrity,
            F::AuditIsolation => Failure::AuditIsolation,
            F::AuditContract => Failure::AuditContract,
            F::AuditAdmission => Failure::AuditAdmission,
            F::AssetObjectLimit => Failure::AssetObjectLimit,
            F::AssetSourceLimit => Failure::AssetSourceLimit,
            F::AssetBytesLimit => Failure::AssetBytesLimit,
            F::Clock => Failure::Clock,
            F::NativeProtection => Failure::NativeProtection,
            F::ContentStorage => Failure::ContentStorage,
            F::ContentInvariant => Failure::ContentInvariant,
            F::ContentMetadata => Failure::ContentMetadata,
            F::ContentDeadline => Failure::ContentDeadline,
            F::ContentCleanup => Failure::ContentCleanup,
            F::NativeInputIntegrity => Failure::NativeInputIntegrity,
            F::CommandInvariant => Failure::CommandInvariant,
            F::Capacity => Failure::Capacity,
            F::Runtime => Failure::Runtime,
            F::Inventory(_) | F::PreparationConfiguration => {
                unreachable!("handled before scalar failure mapping")
            }
        }),
    }
}

#[cfg(test)]
mod error_regression {
    use super::*;
    #[test]
    fn configuration_participation_retains_recovery_and_audit_diagnoses() {
        use rss_mdm_policy_service::{Error as P, Failure as F};
        assert!(matches!(
            error(P::Unavailable(F::NativeInputIntegrity)),
            Error::Unavailable(Failure::NativeInputIntegrity)
        ));
        assert!(matches!(
            error(P::Unavailable(F::CommandInvariant)),
            Error::Unavailable(Failure::CommandInvariant)
        ));
        assert!(matches!(
            error(P::Unavailable(F::AuditIntegrity)),
            Error::Unavailable(Failure::AuditIntegrity)
        ));
        assert!(matches!(
            error(P::Unavailable(F::RequestDeadline)),
            Error::Unavailable(Failure::RequestDeadline)
        ));
        assert!(matches!(error(P::CommitUnknown), Error::CommitUnknown));
        assert!(matches!(error(P::RollbackFailed), Error::RollbackFailed));
    }
}
