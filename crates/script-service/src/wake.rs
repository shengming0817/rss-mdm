//! Script recovery has its own durable domain; notifications only accelerate polling.
use crate::{Error, Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub fn scope(tenant: rss_request_context::TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.script.v1").expect("fixed Script scope")
}
pub async fn run_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let target = rss_reconcile::Target::new(scope(tx.tenant_id()), format!("run:{id}"))
        .map_err(|_| Error::Malformed)?;
    let resources = resources_in(tx, target.entity()).await?;
    reconcile
        .wake_in(tx, &target, &resources, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
    tx.with_connection(|c| Box::pin(async move {
        sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'script_recovery')").execute(c).await?;
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
        sqlx::query("INSERT INTO mdm_script.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_script.policy_recovery.input_revision+1").bind(tenant).bind(id).execute(c).await?;Ok(())
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
    let resources = resources_in(tx, target.entity()).await?;
    reconcile
        .wake_in(tx, &target, &resources, (), |_, _| {
            Box::pin(async { Ok(()) })
        })
        .await?;
    tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'script_recovery')").execute(c).await?;Ok(())})).await?;
    Ok(())
}

/// Resolve resources from immutable owner facts; policy work only registers run work.
pub(crate) async fn resources_in(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<rss_reconcile::ResourceSet> {
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        let device = crate::storage::read_run(tx, id).await?.target.device;
        return Ok(rss_mdm_registration_service::lifecycle::resources::device(
            tx.tenant_id(),
            &device,
            rss_mdm_registration_service::lifecycle::resources::Work::ScriptRecovery,
        ));
    }
    if entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
        .is_some()
    {
        return Ok(rss_reconcile::ResourceSet::empty(tx.tenant_id()));
    }
    Err(Error::Malformed.into())
}
