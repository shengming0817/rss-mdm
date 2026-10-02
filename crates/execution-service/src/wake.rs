use crate::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
pub async fn wake_native_in(
    source: std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    let source_tenant = tx.tenant_id();
    let name = device.to_owned();
    let interested = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(source.native_interest_on(c, source_tenant, &name).await) })
        })
        .await??;
    let tenant = tx.tenant_id().to_string();
    let name = device.to_owned();
    // Authority ingress exists even without configuration policies. Do not create
    // idle per-device configuration state unless an assignment can use it.
    let changed=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,i64>("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) SELECT $1::uuid,$2 WHERE EXISTS(SELECT 1 FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2) OR $3::boolean ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1 RETURNING input_revision").bind(tenant).bind(name).bind(interested).fetch_optional(c).await
    })).await?;
    if changed.is_none() {
        return Ok(());
    }
    let target = rss_reconcile::Target::new(
        crate::recovery_scope(tx.tenant_id()),
        format!("configuration:{device}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
