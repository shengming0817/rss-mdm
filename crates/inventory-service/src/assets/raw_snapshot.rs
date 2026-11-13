//! Raw persistence and source qualification are captured once; resolution stays in Inventory.
use super::*;
use rss_mdm_inventory::{ArrayFact, Catalog, CollectionScope, Source, SourceFact, ValueType};

#[derive(serde::Deserialize)]
struct SourceRow {
    device: rss_mdm_agent_wire::DeviceId,
    channel: String,
    source: String,
    epoch: String,
    dataset: String,
    scope: String,
}
/// The catalog included by the same SQL snapshot as the facts.
pub fn catalog(value: &Value) -> Result<Catalog> {
    if value["ok"] != true {
        return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
    }
    stored(Catalog::new(stored(serde_json::from_value(
        value["catalog"].clone(),
    ))?))
}
/// Compose on the caller's transaction; no source, publication or writer locks are acquired.
pub async fn read_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    cut: &rss_mdm_inventory::AssetCut,
    ids: &[rss_mdm_agent_wire::DeviceId],
    catalog: &Catalog,
    scope: &CollectionScope,
) -> Result<Vec<DeviceSummary>> {
    if cut.tenant() != Uuid::from_bytes(tenant.octets()) || ids.len() > 1000 {
        return Err(Error::Forbidden.into());
    }
    let keys = catalog
        .fields()
        .filter(|f| fields::visible(f))
        .map(|f| f.key.as_str())
        .collect::<Vec<_>>();
    let raw: Value =
        sqlx::query_scalar(crate::storage_profile::sql(profile).assets_raw_snapshot_read_on_1)
            .bind(tenant.to_string())
            .bind(ids.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
            .bind(keys)
            .bind(cut.to_json())
            .bind(stored(serde_json::to_value(scope))?)
            .fetch_one(c)
            .await?;
    decode(profile, tenant, ids, catalog, scope, raw)
}
/// Decode a composed SELECT using the same provenance checks and resolvers as standalone reads.
pub fn decode(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    ids: &[rss_mdm_agent_wire::DeviceId],
    catalog: &Catalog,
    scope: &CollectionScope,
    raw: Value,
) -> Result<Vec<DeviceSummary>> {
    if raw["ok"] != true || ids.len() > 1000 {
        return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
    }
    let sources: Vec<SourceRow> = stored(serde_json::from_value(raw["sources"].clone()))?;
    let mut subjects = BTreeMap::new();
    let mut devices = ids
        .iter()
        .map(|id| {
            (
                *id,
                DeviceView {
                    collection_scope: scope.clone(),
                    device: *id,
                    channels: BTreeSet::new(),
                    fields: BTreeMap::new(),
                    lists: BTreeMap::new(),
                    quality: Vec::new(),
                    revisions: BTreeMap::new(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for row in sources {
        let source = stored(Source::parse(&row.source))?;
        if source.channel().map(|c| c.as_str()) != Some(row.channel.as_str()) {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let expected = crate::device::scope_dataset(
            profile,
            tenant,
            &row.device,
            &row.source,
            stored(Uuid::parse_str(&row.epoch))?,
            &row.dataset,
        )?;
        if stored(expected.encode())? != row.scope {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let device = devices
            .get_mut(&row.device)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
        device.channels.insert(row.channel);
        subjects.insert(row.scope, row.device);
    }
    let facts = stored(rss_mdm_inventory_postgres::snapshot::decode(
        stored(serde_json::from_value(raw["observed"].clone()))?,
        stored(serde_json::from_value(raw["manual"].clone()))?,
        stored(serde_json::from_value(raw["versions"].clone()))?,
    ))?;
    let mut scalars: BTreeMap<(rss_mdm_agent_wire::DeviceId, FieldKey), Vec<SourceFact>> =
        BTreeMap::new();
    let mut arrays: BTreeMap<(rss_mdm_agent_wire::DeviceId, FieldKey), Vec<ArrayFact>> =
        BTreeMap::new();
    for row in facts.scalars {
        if &row.fact.evidence.scope != scope {
            continue;
        }
        let device = subjects
            .get(&row.scope)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
        scalars
            .entry((*device, row.field))
            .or_default()
            .push(row.fact);
    }
    for row in facts.arrays {
        if &row.fact.evidence.scope != scope {
            continue;
        }
        let device = subjects
            .get(&row.scope)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
        arrays
            .entry((*device, row.field))
            .or_default()
            .push(row.fact);
    }
    for row in facts.manual {
        devices
            .get_mut(&row.device)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?
            .revisions
            .insert(row.field, row.revision);
        scalars
            .entry((row.device, row.field))
            .or_default()
            .push(row.fact);
    }
    for row in facts.manual_arrays {
        devices
            .get_mut(&row.device)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?
            .revisions
            .insert(row.field, row.revision);
        arrays
            .entry((row.device, row.field))
            .or_default()
            .push(row.fact);
    }
    let quality_rows: Vec<Value> = stored(serde_json::from_value(raw["quality"].clone()))?;
    for value in quality_rows {
        let row: quality::Record = stored(serde_json::from_value(value.clone()))?;
        let device = subjects
            .get(&row.scope)
            .ok_or(Error::Unavailable(Failure::CollectionQuery))?;
        let mut quality = quality::decode_record(&row)?;
        let selected: Vec<String> =
            stored(serde_json::from_value(value["selected_fields"].clone()))?;
        quality
            .fields
            .retain(|f| &f.scope == scope && selected.iter().any(|key| key == f.field.as_str()));
        devices
            .get_mut(device)
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?
            .quality
            .push(quality);
    }
    devices
        .into_iter()
        .map(|(id, mut device)| {
            let mut resolved_arrays = BTreeMap::new();
            for definition in catalog.fields().filter(|f| fields::visible(f)) {
                let key = definition.key;
                if matches!(definition.value_type, ValueType::Array { .. }) {
                    let facts = arrays
                        .remove(&(id, key))
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| definition.sources.contains_key(&f.evidence.source))
                        .collect();
                    resolved_arrays.insert(
                        key,
                        stored(rss_mdm_inventory::resolve_array(definition, facts))?,
                    );
                } else {
                    let facts = scalars
                        .remove(&(id, key))
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| definition.sources.contains_key(&f.evidence.source))
                        .collect();
                    device
                        .fields
                        .insert(key, stored(rss_mdm_inventory::resolve(definition, facts))?);
                }
            }
            restrict_fields(&mut device, catalog);
            Ok(DeviceSummary {
                scalars: device,
                arrays: resolved_arrays,
            })
        })
        .collect()
}

/// Scalar projection for callers already holding an authorized connection and fixed asset cut.
pub async fn scalar_devices_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    cut: &AssetCut,
    ids: &[rss_mdm_agent_wire::DeviceId],
    catalog: &Catalog,
) -> Result<Vec<DeviceView>> {
    let catalog = stored(Catalog::new(
        catalog
            .fields()
            .filter(|f| !matches!(f.value_type, ValueType::Array { .. }))
            .cloned()
            .collect(),
    ))?;
    Ok(read_on(
        profile,
        c,
        tenant,
        cut,
        ids,
        &catalog,
        &CollectionScope::Device,
    )
    .await?
    .into_iter()
    .map(|view| view.scalars)
    .collect())
}
