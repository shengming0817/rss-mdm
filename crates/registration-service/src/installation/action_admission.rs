//! Transaction-bound current authorization and owner locks for action requests.
use crate::installation::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
/// Registration owns the only endpoint fence. Keep it through authorization and effects.
pub(crate) async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    lock_devices(tx, &[device.to_owned()]).await
}
/// Discover the complete transaction target set before taking any channel or run locks.
pub(crate) async fn lock_devices(tx: &mut PgTransaction<'_>, devices: &[String]) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let devices = devices.to_vec();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::lifecycle::lock_devices_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant,
                &devices,
            )
            .await)
        })
    })
    .await??;
    Ok(())
}

pub async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub async fn authorized(
    tx: &mut PgTransaction<'_>,
    proof: &crate::installation::authorization::context::AuthorizedPrincipal,
    device: &str,
    permission: crate::installation::authorization::Permission,
) -> Result<crate::installation::authorization::Snapshot> {
    let snapshot = current(tx, proof).await?;
    snapshot.require(proof, permission, Some(device))?;
    Ok(snapshot)
}
pub async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::installation::authorization::context::AuthorizedPrincipal,
) -> Result<crate::installation::authorization::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::installation::authorization::lock_shared_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &instance,
                )
                .await
                .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::installation::authorization::snapshot_on(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant,
                    &instance,
                )
                .await)
            })
        })
        .await??;
    Ok(snapshot)
}
