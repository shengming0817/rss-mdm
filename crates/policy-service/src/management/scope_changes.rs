//! Policy reference checks and durable Scope publication acceptance.
use crate::transaction::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
use uuid::Uuid;
pub struct ScopeChanges {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
}
impl ScopeChanges {
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId) -> Self {
        Self { runtime, tenant }
    }
    fn validate(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(crate::Error::Forbidden.into());
        }
        Ok(())
    }
    pub async fn used_in(&self, tx: &mut PgTransaction<'_>, scope: Uuid) -> Result<bool> {
        self.validate(tx)?;
        Ok(rss_mdm_policy_postgres::scope::used_in(tx, scope).await?)
    }
    pub async fn publication_recorded_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        run: Uuid,
    ) -> Result<()> {
        self.validate(tx)?;
        crate::worker::jobs::enqueue_job_in(
            tx,
            run,
            &crate::worker::Work::PolicyScope { scope, run },
        )
        .await?;
        Ok(())
    }
}
pub async fn advance_in(
    tx: &mut PgTransaction<'_>,
    audit: &rss_mdm_audit_integration::AuditStore,
    task: Uuid,
    scope: Uuid,
    after: Option<String>,
) -> Result<()> {
    let policies = rss_mdm_policy_postgres::scope::dependents_in(tx, scope, after).await?;
    for policy in policies.iter().take(64) {
        crate::worker::jobs::enqueue_job_in(
            tx,
            Uuid::new_v4(),
            &crate::worker::Work::PolicyReconcile { policy: *policy },
        )
        .await?;
    }
    if policies.len() <= 64 {
        return crate::worker::jobs::finish_job_in(tx, audit, task, None).await;
    }
    rss_mdm_policy_postgres::work::cursor_in(tx, task, Some(policies[63].to_string())).await?;
    Ok(())
}
