use crate::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
use sha2::{Digest, Sha256};

pub(crate) fn configuration_key(device: &str) -> String {
    format!("configuration:{:x}", Sha256::digest(device.as_bytes()))
}

pub async fn wake_native_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    wake_native_batch_in(reconcile, source, tx, &[device.to_owned()]).await
}

/// Coalesced source changes update only interested devices. All wakes and the
/// caller's input checkpoint use this transaction; RSS remains the wake owner.
pub async fn wake_native_batch_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    devices: &[String],
) -> Result<()> {
    if devices.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let devices = devices
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if devices.is_empty() {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let selected = devices.clone();
    let rows = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as::<_, (String,Option<uuid::Uuid>,bool)>("SELECT wanted.device,d.retirement,c.device IS NOT NULL FROM unnest($2::text[]) wanted(device) LEFT JOIN mdm_access.devices d ON d.tenant_id=$1::uuid AND d.id=wanted.device LEFT JOIN mdm_planning.configuration_devices c ON c.tenant_id=$1::uuid AND c.device=wanted.device ORDER BY wanted.device COLLATE \"C\"")
            .bind(tenant).bind(selected).fetch_all(c).await
    })).await?;
    let retirements = rows
        .iter()
        .filter_map(|(_, id, _)| *id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut interested = rows
        .iter()
        .filter(|(_, _, present)| *present)
        .map(|(device, _, _)| device.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let missing = rows
        .iter()
        .filter(|(_, _, present)| !*present)
        .map(|(device, _, _)| device.clone())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let tenant = tx.tenant_id();
        let selected = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(source.native_interests_on(c, tenant, &missing).await) })
            })
            .await?
            .map_err(Error::from)?;
        interested.extend(selected);
    }
    let tenant = tx.tenant_id().to_string();
    let interested = interested.into_iter().collect::<Vec<_>>();
    let updated = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, String>("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) SELECT $1::uuid,device FROM unnest($2::text[]) wanted(device) ORDER BY device COLLATE \"C\" ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1 RETURNING device")
            .bind(tenant).bind(interested).fetch_all(c).await
    })).await?;
    let mut targets = retirements
        .into_iter()
        .map(|id| format!("retirement:{id}"))
        .chain(updated.iter().map(|device| configuration_key(device)))
        .collect::<Vec<_>>();
    targets.sort();
    for entity in &targets {
        let target = rss_reconcile::Target::new(crate::recovery_scope(tx.tenant_id()), entity)
            .map_err(|_| Error::Malformed)?;
        reconcile
            .wake_in(
                tx,
                &target,
                &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
    }
    if !targets.is_empty() {
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    }
    Ok(())
}

/// A changed assignment wakes its exact registration generation; no policy-wide rescan.
pub async fn wake_policy_device_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    version: uuid::Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
) -> crate::Result<()> {
    crate::actions::scheduled::wake_in(
        reconcile,
        tx,
        crate::actions::scheduled::Work {
            version,
            registration: target.registration_id,
            generation: target.generation,
        },
    )
    .await
}
