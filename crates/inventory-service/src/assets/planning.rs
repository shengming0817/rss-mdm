//! Transaction-borrowing, bounded asset snapshot projection consumed by target planning.
//! Fixed-watermark enumeration. No transaction survives a returned page.
use super::*;
use rss_mdm_inventory::SourceFact;
use sqlx::Row;

pub struct AssetPage {
    pub catalog: rss_mdm_inventory::Catalog,
    pub devices: Vec<DeviceView>,
    pub next: Option<String>,
}
pub struct SnapshotReader {
    pub tenant: TenantId,
}
impl SnapshotReader {
    pub async fn live_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        devices: &[String],
    ) -> Result<BTreeSet<String>> {
        if devices.len() > 1000 {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let tenant = self.tenant.to_string();
        let devices = devices.to_vec();
        let rows: Vec<String> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::live_at(c, tenant, devices, watermark).await
                })
            })
            .await?;
        Ok(rows.into_iter().collect())
    }
    pub async fn asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        after: Option<String>,
        limit: usize,
        scope: &ReadScope,
    ) -> Result<AssetPage> {
        if watermark < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let tenant = self.tenant.to_string();
        let all = scope.devices.is_none();
        let allowed: Vec<_> = scope
            .devices
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut ids: Vec<String> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::page_at(
                        c,
                        tenant,
                        watermark,
                        after,
                        all,
                        allowed,
                        (limit + 1) as i64,
                    )
                    .await
                })
            })
            .await?;
        let more = ids.len() > limit;
        ids.truncate(limit);
        let next = more.then(|| ids.last().expect("nonempty lookahead page").clone());
        let catalog = catalog_in(tx, self.tenant, watermark).await?;
        let mut devices = self
            .asset_devices_at_in(tx, watermark, &ids, &catalog)
            .await?;
        for device in &mut devices {
            restrict_fields(device, &catalog, scope.sensitive);
        }
        Ok(AssetPage {
            devices,
            next,
            catalog,
        })
    }

    async fn asset_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,
    ) -> Result<Vec<DeviceView>> {
        let mut devices: BTreeMap<_, _> = ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    DeviceView {
                        device: id.clone(),
                        channels: BTreeSet::new(),
                        fields: BTreeMap::new(),
                        lists: BTreeMap::new(),
                        quality: vec![],
                        revisions: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let tenant = self.tenant.to_string();
        let selected = ids.to_vec();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::sources_at(c, tenant, selected, watermark).await
                })
            })
            .await?;
        if rows.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let datasets = datasets_in(tx, self.tenant).await?;
        let mut scopes = Vec::new();
        let mut subjects = BTreeMap::new();
        for row in rows {
            let device: String = row.try_get("device")?;
            let source = stored(rss_mdm_inventory::Source::parse(row.try_get("source")?))?;
            let channel: &str = row.try_get("channel")?;
            if channel != source.channel().ok_or(Error::Malformed)?.as_str() {
                return Err(Error::Unavailable(Failure::InventoryQuery).into());
            }
            for dataset in datasets.get(&source).into_iter().flatten() {
                let scope = crate::device::scope_dataset(
                    self.tenant,
                    stored(Uuid::parse_str(row.try_get("registration")?))?,
                    source.as_str(),
                    stored(Uuid::parse_str(row.try_get("epoch")?))?,
                    dataset,
                )?;
                let generation: u64 = stored(row.try_get::<&str, _>("generation")?.parse())?;
                devices
                    .get_mut(&device)
                    .ok_or(Error::Unavailable(Failure::AssetsStorage))?
                    .channels
                    .insert(channel.to_owned());
                subjects.insert(stored(scope.encode())?, (device.clone(), generation));
                scopes.push(scope);
            }
        }
        let tenant = self.tenant;
        let selected = ids.to_vec();
        let (observed, manual) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let observed =
                        rss_mdm_inventory_postgres::read_at_in(c, tenant, &scopes, watermark)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("frozen inventory unavailable".into())
                            })?;
                    let manual =
                        rss_mdm_inventory_postgres::manual_at_in(c, tenant, &selected, watermark)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("frozen manual unavailable".into())
                            })?;
                    Ok((observed, manual))
                })
            })
            .await?;
        let mut facts: BTreeMap<(String, FieldKey), Vec<SourceFact>> = BTreeMap::new();
        for mut row in observed {
            let (device, generation) = subjects
                .get(&row.scope)
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
            row.fact.evidence.registration_generation = Some(*generation);
            if let Some(old) = &mut row.fact.last_known {
                old.evidence.registration_generation = Some(*generation);
            }
            facts
                .entry((device.clone(), row.field))
                .or_default()
                .push(row.fact);
        }
        for row in manual {
            devices
                .get_mut(&row.device)
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?
                .revisions
                .insert(row.field, row.revision);
            facts
                .entry((row.device, row.field))
                .or_default()
                .push(row.fact);
        }
        let tenant = self.tenant.to_string();
        let keys: Vec<_> = subjects.keys().cloned().collect();
        let quality = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::collection::read::quality_at(c, tenant, keys, watermark).await
                })
            })
            .await?;
        for row in quality {
            let scope: String = row.try_get("scope")?;
            let (device, generation) = subjects
                .get(&scope)
                .ok_or(Error::Unavailable(Failure::CollectionQuery))?;
            devices
                .get_mut(device)
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?
                .quality
                .push(quality::decode(&row, *generation)?);
        }
        for (id, device) in &mut devices {
            for definition in catalog.fields() {
                let field = definition.key;
                device.fields.insert(
                    field,
                    stored(rss_mdm_inventory::resolve(
                        definition,
                        facts
                            .remove(&(id.clone(), field))
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|fact| definition.sources.contains_key(&fact.evidence.source))
                            .collect(),
                    ))?,
                );
            }
        }
        let result: Vec<_> = devices.into_values().collect();
        if stored(serde_json::to_vec(&result))?.len() > 64 * 1024 * 1024 {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        Ok(result)
    }
}
