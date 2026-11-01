//! Enrollment recovery has its own durable domain; notifications only accelerate polling.
use crate::device_access::execution::{Error, Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub fn scope(tenant: rss_request_context::TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.registration.device-access.v1")
        .expect("fixed Enrollment scope")
}
pub async fn run_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let target = rss_reconcile::Target::new(scope(tx.tenant_id()), format!("run:{id}"))
        .map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(tx.tenant_id()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    tx.with_connection(|c| Box::pin(async move {
        sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'access_recovery')").execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}

pub async fn policy_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_access_tasks.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_access_tasks.policy_recovery.input_revision+1").bind(tenant).bind(id).execute(c).await?;Ok(())
    })).await?;
    entity_in(reconcile, tx, &format!("policy:{id}")).await
}
pub async fn entity_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<()> {
    let target =
        rss_reconcile::Target::new(scope(tx.tenant_id()), entity).map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(tx.tenant_id()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'access_recovery')").execute(c).await?;Ok(())})).await?;
    Ok(())
}
