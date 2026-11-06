//! Bounded presence projection on the authorized caller's existing snapshot.
use super::*;
pub async fn directory_presence_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    devices: &[String],
) -> crate::transaction::Result<BTreeSet<String>> {
    if devices.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let catalog = stored(rss_mdm_inventory_postgres::catalog_in(c, tenant).await)?;
    let fields = catalog.fields().map(|f| f.key).collect::<Vec<_>>();
    let rows = sqlx::query("SELECT * FROM mdm_access.asset_sources_at($1,NULL)")
        .bind(devices)
        .fetch_all(&mut *c)
        .await?;
    let selected = planning::SnapshotReader::select_sources_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        rows,
        &rss_mdm_inventory::CollectionScope::Device,
        &fields,
    )
    .await?;
    let mut owners = selected
        .subjects
        .into_iter()
        .map(|(scope, (device, _))| (scope, device))
        .collect::<BTreeMap<_, _>>();
    let (present, manual) = rss_mdm_inventory_postgres::directory_presence_in(
        c,
        tenant,
        owners.keys().cloned().collect(),
        devices.to_vec(),
    )
    .await?;
    let mut result: BTreeSet<String> = manual.into_iter().collect();
    for scope in present {
        result.insert(owners.remove(&scope).ok_or(Error::Malformed)?);
    }
    Ok(result)
}
