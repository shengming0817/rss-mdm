//! Fixed-watermark enumeration. No transaction survives a returned page.
use super::*;
use rss_mdm_inventory::SourceFact;
use sqlx::Row;

pub(in crate::management) struct AssetPage {
    pub devices: Vec<DeviceView>,
    pub next: Option<String>,
}
impl Management {
    pub(in crate::management) async fn live_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        devices: &[String],
    ) -> Result<BTreeSet<String>> {
        if devices.len() > 1000 {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        }
        let tenant = self.tenant.to_string();
        let devices = devices.to_vec();
        let rows: Vec<String> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        r#"
                WITH latest AS (
                    SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                    FROM mdm_access.asset_authority_history
                    WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
                      AND kind IN('registration','credential','source')
                    ORDER BY kind,identity,revision DESC
                ), live AS (
                    SELECT device,registration FROM latest GROUP BY device,registration
                    HAVING bool_or(kind='registration' AND document->>'state'='active')
                       AND bool_or(kind='credential' AND document->>'state'='active')
                       AND bool_or(kind='source' AND document->>'enabled'='true')
                ) SELECT DISTINCT device FROM live
            "#,
                    )
                    .bind(tenant)
                    .bind(devices)
                    .bind(watermark)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        Ok(rows.into_iter().collect())
    }
    pub(in crate::management) async fn asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        after: Option<String>,
        limit: usize,
        scope: &ReadScope,
    ) -> Result<AssetPage> {
        if watermark < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
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
                    sqlx::query_scalar(
                        r#"
              WITH latest AS (
                SELECT DISTINCT ON(identity COLLATE "C") identity,document
                FROM mdm_access.asset_authority_history
                WHERE tenant_id=$1::uuid AND kind='device' AND revision<=$2
                  AND identity COLLATE "C">coalesce($3::text,'') COLLATE "C"
                  AND ($4 OR identity=ANY($5))
                ORDER BY identity COLLATE "C",revision DESC
              ) SELECT identity FROM latest WHERE document IS NOT NULL
                ORDER BY identity COLLATE "C" LIMIT $6
            "#,
                    )
                    .bind(tenant)
                    .bind(watermark)
                    .bind(after)
                    .bind(all)
                    .bind(allowed)
                    .bind((limit + 1) as i64)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        let more = ids.len() > limit;
        ids.truncate(limit);
        let next = more.then(|| ids.last().expect("nonempty lookahead page").clone());
        let devices = self.asset_devices_at_in(tx, watermark, &ids).await?;
        Ok(AssetPage { devices, next })
    }

    async fn asset_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        ids: &[String],
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
                        quality: vec![],
                        revisions: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let tenant = self.tenant.to_string();
        let selected = ids.to_vec();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query(r#"
              WITH latest AS (
                SELECT DISTINCT ON(kind,identity) kind,identity,registration,device,document
                FROM mdm_access.asset_authority_history
                WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
                  AND kind IN('registration','credential','source')
                ORDER BY kind,identity,revision DESC
              ) SELECT r.device,r.identity AS registration,r.document->>'generation' AS generation,
                  r.document->>'channel' AS channel,s.document->>'source' AS source,s.document->>'epoch' AS epoch
                FROM latest r JOIN latest s ON s.registration=r.registration AND s.kind='source'
                JOIN latest c ON c.registration=r.registration AND c.kind='credential'
                WHERE r.kind='registration' AND r.document->>'state'='active'
                  AND c.document->>'state'='active' AND s.document->>'enabled'='true'
                ORDER BY r.device,s.identity LIMIT 2001
            "#).bind(tenant).bind(selected).bind(watermark).fetch_all(c).await
        })).await?;
        if rows.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let mut scopes = Vec::new();
        let mut subjects = BTreeMap::new();
        for row in rows {
            let device: String = row.try_get("device")?;
            let source = stored(rss_mdm_inventory::Source::parse(row.try_get("source")?))?;
            let channel: &str = row.try_get("channel")?;
            if channel != source.channel().ok_or(Error::Malformed)?.as_str() {
                return Err(Error::Unavailable(Failure::InventoryQuery).into());
            }
            for dataset in rss_mdm_inventory::datasets(source) {
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
                    .ok_or(Error::Unavailable(Failure::ManagementStorage))?
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
                .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
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
                .ok_or(Error::Unavailable(Failure::ManagementStorage))?
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
                    sqlx::query(
                        r#"
                WITH latest AS (
                  SELECT DISTINCT ON(scope,run) scope,sequence,run,document
                  FROM mdm_access.collection_history
                  WHERE tenant_id=$1::uuid AND scope=ANY($2) AND revision<=$3
                  ORDER BY scope,run,revision DESC
                ) SELECT DISTINCT ON(scope) scope,sequence,run::text AS id,
                    document->>'result' AS result,document->>'attempts' AS attempts,
                    (document->>'delivery_pending')::boolean AS delivery_pending
                  FROM latest WHERE document IS NOT NULL ORDER BY scope,sequence DESC,run DESC
            "#,
                    )
                    .bind(tenant)
                    .bind(keys)
                    .bind(watermark)
                    .fetch_all(c)
                    .await
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
                .ok_or(Error::Unavailable(Failure::ManagementStorage))?
                .quality
                .push(quality::decode(&row, *generation)?);
        }
        for (id, device) in &mut devices {
            for field in FieldKey::ALL {
                device.fields.insert(
                    field,
                    stored(rss_mdm_inventory::resolve(
                        field,
                        facts.remove(&(id.clone(), field)).unwrap_or_default(),
                    ))?,
                );
            }
        }
        let result: Vec<_> = devices.into_values().collect();
        if stored(serde_json::to_vec(&result))?.len() > 16 * 1024 * 1024 {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        Ok(result)
    }
}
