//! Script recovery has its own durable domain; notifications only accelerate polling.
use crate::{Error, Result};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub fn scope(tenant: rss_request_context::TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, rss_mdm_work_page::relay::lanes::SCRIPT.domain)
        .expect("fixed Script scope")
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
    tx.with_connection(|c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_notify('mdm_work','script_recovery')")
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}

pub async fn policy_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let epoch = tx.expected_epoch().get();

    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        let updated=sqlx::query("INSERT INTO mdm_script.policy_recovery(tenant_id,policy,expected_epoch) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_script.policy_recovery.input_revision+1 WHERE mdm_script.policy_recovery.expected_epoch=excluded.expected_epoch").bind(tenant).bind(id).bind(epoch).execute(c).await?;
            if updated.rows_affected()!=1{return Err(sqlx::Error::Protocol("original work epoch mismatch".into()))}
            Ok(())
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
    tx.with_connection(|c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_notify('mdm_work','script_recovery')")
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
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
        let device: Uuid = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_script.runs WHERE tenant_id=current_setting('rss.tenant_id')::uuid AND id=$1")
                .bind(id).fetch_one(c).await
        })).await?;
        let device =
            rss_mdm_agent_wire::DeviceId::try_from(device).map_err(|_| Error::Invariant)?;
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
