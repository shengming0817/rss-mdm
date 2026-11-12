use crate::deployment::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
use sha2::{Digest, Sha256};

pub(crate) fn agent_install_key(device: &rss_mdm_agent_wire::DeviceId) -> String {
    format!(
        "agent-install:{:x}",
        Sha256::digest(device.to_string().as_bytes())
    )
}

pub async fn wake_native_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    wake_native_batch_in(reconcile, source, tx, &[device.to_owned()]).await
}

/// Coalesced source changes update only interested devices. All wakes and the
/// caller's input checkpoint use this transaction; RSS remains the wake owner.
pub async fn wake_native_batch_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    devices: &[rss_mdm_agent_wire::DeviceId],
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
        sqlx::query_as::<_, (uuid::Uuid,Option<uuid::Uuid>,bool)>("SELECT wanted.device,d.retirement,c.device IS NOT NULL FROM unnest($2::uuid[]) wanted(device) LEFT JOIN mdm_access.devices d ON d.tenant_id=$1::uuid AND d.id=wanted.device LEFT JOIN mdm_software_deployment.agent_install_inputs c ON c.tenant_id=$1::uuid AND c.device=wanted.device ORDER BY wanted.device")
            .bind(tenant).bind(selected.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.and_then(|rows| rows.into_iter().map(|(id, retirement, present)| Ok((crate::deployment::database::device_id(id)?, retirement, present))).collect::<std::result::Result<Vec<_>, sqlx::Error>>())
    })).await?;
    let retirements = rows
        .iter()
        .filter_map(|(_, id, _)| *id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut interested = rows
        .iter()
        .filter(|(_, _, present)| *present)
        .map(|(device, _, _)| *device)
        .collect::<std::collections::BTreeSet<_>>();
    let missing = rows
        .iter()
        .filter(|(_, _, present)| !*present)
        .map(|(device, _, _)| *device)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let tenant = tx.tenant_id();
        let selected = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(crate::deployment::sources::candidates::PolicyCandidates {
                        objects: source.clone(),
                    }
                    .native_interests_on(c, tenant, &missing)
                    .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        interested.extend(selected);
    }
    let tenant = tx.tenant_id().to_string();
    let interested = interested.into_iter().collect::<Vec<_>>();
    let updated = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, uuid::Uuid>("INSERT INTO mdm_software_deployment.agent_install_inputs(tenant_id,device) SELECT $1::uuid,device FROM unnest($2::uuid[]) wanted(device) ORDER BY device ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_software_deployment.agent_install_inputs.input_revision+1 RETURNING device")
            .bind(tenant).bind(interested.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.and_then(crate::deployment::database::device_ids)
    })).await?;
    let mut targets = retirements
        .into_iter()
        .map(|id| format!("retirement:{id}"))
        .chain(updated.iter().map(agent_install_key))
        .collect::<Vec<_>>();
    targets.sort();
    for entity in &targets {
        let target =
            rss_reconcile::Target::new(crate::deployment::recovery_scope(tx.tenant_id()), entity)
                .map_err(|_| Error::Malformed)?;
        let resources = crate::deployment::recovery::resources_in(tx, target.entity()).await?;
        reconcile
            .wake_in(tx, &target, &resources, (), |_, _| {
                Box::pin(async { Ok(()) })
            })
            .await?;
    }
    if !targets.is_empty() {
        crate::deployment::worker_wake::notify_in(
            tx,
            crate::deployment::worker_wake::Work::CommandRecovery,
        )
        .await?;
    }
    Ok(())
}
