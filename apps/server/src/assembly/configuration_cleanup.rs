//! The retirement coordinator borrows Policy cleanup on its original transaction.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_execution_service::{
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
                    rss_mdm_policy_service::transaction::Fault::Request(e) => {
                        use rss_mdm_policy_service::Error as P;
                        match e {
                            P::CommitUnknown => Error::CommitUnknown,
                            P::RollbackFailed => Error::RollbackFailed,
                            P::ReadConflict
                            | P::Conflict
                            | P::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
                            P::Malformed => Error::Malformed,
                            P::Unauthorized => Error::Unauthorized,
                            P::Forbidden => Error::Forbidden,
                            P::Unavailable(_) => Error::Unavailable(Failure::CommandStorage),
                            _ => Error::Unsupported,
                        }
                        .into()
                    }
                })
        })
    }
}

pub(super) fn error(e: rss_mdm_policy_service::Error) -> rss_mdm_execution_service::Error {
    use rss_mdm_policy_service::Error as P;
    match e {
        P::CommitUnknown => Error::CommitUnknown,
        P::RollbackFailed => Error::RollbackFailed,
        P::ReadConflict | P::Conflict | P::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
        P::Malformed => Error::Malformed,
        P::Unauthorized => Error::Unauthorized,
        P::Forbidden => Error::Forbidden,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => Error::NotFound,
        P::Unavailable(_) => Error::Unavailable(Failure::CommandStorage),
        _ => Error::Unsupported,
    }
}
