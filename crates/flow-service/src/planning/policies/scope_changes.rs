//! Policy owns publication fan-out; Scope only records one durable handoff.
use crate::transaction::*;
use rss_mdm_scope_service::sources::{Pending, ScopeDependents};
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
    fn validate(&self, tx: &PgTransaction<'_>) -> rss_mdm_scope_service::transaction::Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(rss_mdm_scope_service::Error::Forbidden.into());
        }
        Ok(())
    }
}
fn project(e: Fault) -> rss_mdm_scope_service::transaction::Fault {
    use rss_mdm_scope_service::{Error as E, Failure as F, transaction::Fault as P};
    match e {
        Fault::Storage(e) => P::Storage(e),
        Fault::Sql(e) => P::Sql(e),
        Fault::Request(e) => match e {
            crate::Error::Conflict => E::Conflict.into(),
            crate::Error::Malformed => E::Malformed.into(),
            crate::Error::Forbidden | crate::Error::Unauthorized => E::Forbidden.into(),
            crate::Error::CommitUnknown => E::CommitUnknown.into(),
            crate::Error::RollbackFailed => E::RollbackFailed.into(),
            _ => E::Unavailable(F::Storage).into(),
        },
    }
}
impl ScopeDependents for ScopeChanges {
    fn used_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: Uuid,
    ) -> Pending<'a, bool, rss_mdm_scope_service::transaction::Fault> {
        Box::pin(async move {
            self.validate(tx)?;
            let tenant = self.tenant.to_string();
            Ok(tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ((definition->>'scope')::uuid=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE (stage->>'scope')::uuid=$2)))").bind(tenant).bind(scope).fetch_one(c).await
            })).await?)
        })
    }
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: Uuid,
        run: Uuid,
    ) -> Pending<'a, (), rss_mdm_scope_service::transaction::Fault> {
        Box::pin(async move {
            self.validate(tx)?;
            crate::automation::jobs::enqueue_job_in(
                tx,
                run,
                &crate::automation::JobInput::PolicyScope { scope, run },
            )
            .await
            .map_err(project)?;
            Ok(())
        })
    }
}
pub async fn advance_in(
    tx: &mut PgTransaction<'_>,
    audit: &rss_mdm_audit_integration::AuditStore,
    task: Uuid,
    scope: Uuid,
    after: Option<String>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let policies=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (definition->>'scope'=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE stage->>'scope'=$2)) AND id>coalesce($3::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 65").bind(tenant).bind(scope.to_string()).bind(after).fetch_all(c).await
    })).await?;
    for policy in policies.iter().take(64) {
        crate::automation::jobs::enqueue_job_in(
            tx,
            Uuid::new_v4(),
            &crate::automation::JobInput::PolicyReconcile { policy: *policy },
        )
        .await?;
    }
    if policies.len() <= 64 {
        return crate::automation::jobs::finish_job_in(tx, audit, task, None).await;
    }
    let tenant = tx.tenant_id().to_string();
    let cursor = policies[63].to_string();
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(task).bind(cursor).execute(c).await?;Ok(())})).await?;
    Ok(())
}
