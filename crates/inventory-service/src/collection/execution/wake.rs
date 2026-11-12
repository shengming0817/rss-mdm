//! Durable Collection work; wake notifications carry no authority.
use crate::{Error, transaction::Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub fn scope(tenant: rss_request_context::TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.collection.v1").expect("fixed collection scope")
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
    tx.with_connection(|c|Box::pin(async move{sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'collection_recovery')").execute(c).await?;Ok(())})).await?;
    Ok(())
}

pub async fn policy_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_inventory.collection_policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_inventory.collection_policy_recovery.input_revision+1").bind(tenant).bind(id).execute(c).await?;Ok(())
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
    tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'collection_recovery')").execute(c).await?;Ok(())})).await?;
    Ok(())
}

/// Device work declares the current endpoint; policy fanout only registers targets.
pub(crate) async fn resources_in(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<rss_reconcile::ResourceSet> {
    use rss_mdm_registration_service::lifecycle::resources::{self, Work};
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        let tenant = tx.tenant_id().to_string();
        let (device, channel): (String, String) = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("SELECT device,channel FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        let work = match channel.as_str() {
            "agent" => Work::AgentCollectionRecovery,
            "mdm" => Work::Exclusive,
            _ => return Err(Error::Unavailable(crate::Failure::PlanningStorage).into()),
        };
        return Ok(resources::device(tx.tenant_id(), &device, work));
    }
    if let Some(work) = super::scheduled::Work::parse(entity) {
        return Ok(resources::device(
            tx.tenant_id(),
            &work.device,
            Work::Exclusive,
        ));
    }
    if let Some(device) = entity.strip_prefix("checkin:") {
        return Ok(resources::device(tx.tenant_id(), device, Work::Exclusive));
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
