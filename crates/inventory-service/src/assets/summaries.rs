//! Display projections read immutable array metadata while scalar consumers retain their values.
use super::*;
use rss_mdm_inventory::{ArrayFact, Catalog, CollectionScope, ResolvedArray, ValueType};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceSummary {
    pub scalars: DeviceView,
    pub arrays: BTreeMap<FieldKey, ResolvedArray>,
}
impl planning::SnapshotReader {
    pub async fn summary_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        watermark: i64,
        ids: &[String],
        catalog: &Catalog,
    ) -> Result<Vec<DeviceSummary>> {
        self.scoped_summary_devices_on(c, watermark, ids, catalog, &CollectionScope::Device)
            .await
    }
    pub async fn scoped_summary_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        watermark: i64,
        ids: &[String],
        catalog: &Catalog,

        scope: &CollectionScope,
    ) -> Result<Vec<DeviceSummary>> {
        let visible = catalog
            .fields()
            .filter(|f| fields::visible(f))
            .collect::<Vec<_>>();
        let scalar_catalog = stored(Catalog::new(
            visible
                .iter()
                .copied()
                .filter(|f| !matches!(f.value_type, ValueType::Array { .. }))
                .cloned()
                .collect(),
        ))?;
        let array_fields = visible
            .into_iter()
            .filter(|f| matches!(f.value_type, ValueType::Array { .. }))
            .map(|f| f.key)
            .collect::<Vec<_>>();
        let mut devices = self
            .scoped_scalar_devices_on(c, watermark, ids, &scalar_catalog, scope)
            .await?;
        let mut facts: BTreeMap<(String, FieldKey), Vec<ArrayFact>> = BTreeMap::new();
        if !array_fields.is_empty() {
            let selected = self
                .sources_on(c, watermark, ids, scope, &array_fields)
                .await?;
            let observed = stored(
                rss_mdm_inventory_postgres::arrays::read_at_in(
                    c,
                    self.tenant,
                    &selected.scopes,
                    watermark,
                    &array_fields,
                )
                .await,
            )?;
            for mut row in observed {
                if &row.fact.evidence.scope != scope {
                    continue;
                }
                let (device, generation) = selected
                    .subjects
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
            let manual = if matches!(scope, CollectionScope::Device) {
                stored(
                    rss_mdm_inventory_postgres::arrays::manual_at_in(
                        c,
                        self.tenant,
                        ids,
                        watermark,
                        &array_fields,
                    )
                    .await,
                )?
            } else {
                Vec::new()
            };
            for row in manual {
                devices
                    .iter_mut()
                    .find(|d| d.device == row.device)
                    .ok_or(Error::Unavailable(Failure::AssetsStorage))?
                    .revisions
                    .insert(row.field, row.revision);
                facts
                    .entry((row.device, row.field))
                    .or_default()
                    .push(row.fact);
            }
            let quality_rows = crate::collection::read::quality_at(
                c,
                self.tenant.to_string(),
                selected.subjects.keys().cloned().collect(),
                watermark,
                stored(serde_json::to_string(scope))?,
            )
            .await?;
            for row in quality_rows {
                use sqlx::Row;
                let coordinate: String = row.try_get("scope")?;
                let (id, generation) = selected
                    .subjects
                    .get(&coordinate)
                    .ok_or(Error::Unavailable(Failure::CollectionQuery))?;
                let mut quality = quality::decode(&row, *generation)?;
                let selected_fields: Vec<String> = row.try_get("selected_fields")?;
                quality.fields.retain(|f| {
                    &f.scope == scope
                        && array_fields.contains(&f.field)
                        && selected_fields.iter().any(|key| key == f.field.as_str())
                });
                let device = devices
                    .iter_mut()
                    .find(|d| &d.device == id)
                    .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
                if let Some(existing) = device
                    .quality
                    .iter_mut()
                    .find(|q| q.run_id == quality.run_id)
                {
                    existing.fields.extend(quality.fields);
                    existing.fields.sort_by_key(|f| f.field);
                } else {
                    device.quality.push(quality);
                }
            }
            for device in &mut devices {
                if let Some(channels) = selected.channels.get(&device.device) {
                    device.channels.extend(channels.iter().cloned());
                }
            }
        }
        devices
            .into_iter()
            .map(|device| {
                let mut arrays = BTreeMap::new();
                for key in &array_fields {
                    let definition = stored(catalog.definition(*key))?;
                    let sources = facts
                        .remove(&(device.device.clone(), *key))
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| definition.sources.contains_key(&f.evidence.source))
                        .collect();
                    arrays.insert(
                        *key,
                        stored(rss_mdm_inventory::resolve_array(definition, sources))?,
                    );
                }
                Ok(DeviceSummary {
                    scalars: device,
                    arrays,
                })
            })
            .collect()
    }
}
