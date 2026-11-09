//! Policy reference checks and durable Scope publication acceptance.
use crate::transaction::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
use uuid::Uuid;
pub struct ScopeChanges {
    profile: rss_mdm_install_support::StorageProfile,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
}
impl ScopeChanges {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
    ) -> Self {
        Self {
            profile,
            runtime,
            tenant,
        }
    }
    fn validate(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(crate::Error::Forbidden.into());
        }
        Ok(())
    }
    pub async fn publication_recorded_in(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: rss_mdm_scope_postgres::ScopeOwner,
        run: Uuid,
    ) -> Result<()> {
        let profile = self.profile();

        self.validate(tx)?;
        crate::worker::jobs::enqueue_job_in(
            profile,
            tx,
            run,
            &crate::worker::Work::PolicyReconcile {
                policy: owner.policy,
            },
        )
        .await?;
        Ok(())
    }
}
