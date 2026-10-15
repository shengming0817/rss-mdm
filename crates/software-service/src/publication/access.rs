//! Current product authorization borrowed by the final publication transaction.
use super::{Error, Result};
use rss_transactional_messaging_postgres::PgTransaction;
use std::{future::Future, pin::Pin};

/// Trusted product caller checks current management permissions on the transaction supplied.
/// Returns whether enabling a draft is permitted; it does not perform a lifecycle change.
pub trait PublishAccess: Send + Sync {
    fn check<'a, 'c>(
        &'a self,
        tx: &'a mut PgTransaction<'c>,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;
}

pub struct ManagementAccess<'a> {
    pub proof: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
    pub permission: rss_mdm_authorization_service::Permission,
}
impl PublishAccess for ManagementAccess<'_> {
    fn check<'a, 'c>(
        &'a self,
        tx: &'a mut PgTransaction<'c>,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            if tx.tenant_id().to_string() != self.proof.tenant_id() {
                return Err(Error::Identity);
            }
            self.proof.check_live().map_err(|_| Error::Identity)?;
            let snapshot = crate::management::transaction::current(tx, self.proof)
                .await
                .map_err(|_| Error::Identity)?;
            snapshot
                .require(self.proof, self.permission, None)
                .map_err(|_| Error::Identity)?;
            Ok(snapshot
                .require(
                    self.proof,
                    rss_mdm_authorization_service::Permission::SoftwareWrite,
                    None,
                )
                .is_ok())
        })
    }
}
