//! Transaction-borrowing, bounded asset snapshot projection consumed by target planning.
//! Fixed-watermark enumeration. No transaction survives a returned page.
use super::*;
use rss_mdm_inventory::SourceFact;
use sqlx::Row;

pub struct AssetPage {
    pub catalog: rss_mdm_inventory::Catalog,
    pub devices: Vec<DeviceSummary>,
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
            .summary_devices_at_in(tx, watermark, &ids, &catalog, &scope.collection_scope)
            .await?;
        for device in &mut devices {
            restrict_fields(&mut device.scalars, &catalog);
        }
        Ok(AssetPage {
            devices,
            next,
            catalog,
        })
    }

    async fn summary_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        watermark: i64,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,
        collection_scope: &rss_mdm_inventory::CollectionScope,
    ) -> Result<Vec<DeviceSummary>> {
        let reader = SnapshotReader {
            tenant: self.tenant,
        };
        let ids = ids.to_vec();
        let catalog = catalog.clone();
        let collection_scope = collection_scope.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(reader
                    .scoped_summary_devices_on(c, watermark, &ids, &catalog, &collection_scope)
                    .await)
            })
        })
        .await?
    }

    /// Authoritative endpoint sources borrowed by device views and identity reconciliation.
    /// Sensitive fields are excluded before field resolution.
    pub async fn scalar_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        watermark: i64,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,
    ) -> Result<Vec<DeviceView>> {
        self.scoped_scalar_devices_on(
            c,
            watermark,
            ids,
            catalog,
            &rss_mdm_inventory::CollectionScope::Device,
        )
        .await
    }

    pub(super) async fn scoped_scalar_devices_on(
        &self,
        c: &mut sqlx::PgConnection,
        watermark: i64,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,

        collection_scope: &rss_mdm_inventory::CollectionScope,
    ) -> Result<Vec<DeviceView>> {
        if ids.len() > 1000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let mut devices: BTreeMap<_, _> = ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    DeviceView {
                        collection_scope: collection_scope.clone(),
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
        let fields = catalog
            .fields()
            .filter(|f| fields::visible(f))
            .map(|f| f.key)
            .collect::<Vec<_>>();
        let selected_sources = self
            .sources_on(c, watermark, ids, collection_scope, &fields)
            .await?;
        for (id, channels) in selected_sources.channels {
            devices
                .get_mut(&id)
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?
                .channels = channels;
        }
        let scopes = selected_sources.scopes;
        let subjects = selected_sources.subjects;
        let tenant = self.tenant;
        let selected = ids.to_vec();
        let observed =
            rss_mdm_inventory_postgres::read_scalars_at_in(c, tenant, &scopes, watermark, &fields)
                .await
                .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
        let manual = if matches!(collection_scope, rss_mdm_inventory::CollectionScope::Device) {
            rss_mdm_inventory_postgres::manual_scalars_at_in(
                c, tenant, &selected, watermark, &fields,
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?
        } else {
            Vec::new()
        };
        let mut facts: BTreeMap<(String, FieldKey), Vec<SourceFact>> = BTreeMap::new();
        for mut row in observed {
            if &row.fact.evidence.scope != collection_scope {
                continue;
            }
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
        let quality = crate::collection::read::quality_at(
            c,
            tenant,
            keys,
            watermark,
            stored(serde_json::to_string(collection_scope))?,
        )
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
                .push({
                    let mut quality = quality::decode(&row, *generation)?;
                    let selected: Vec<String> = row.try_get("selected_fields")?;
                    quality.fields.retain(|f| {
                        &f.scope == collection_scope
                            && selected.iter().any(|key| key == f.field.as_str())
                    });
                    quality
                });
        }
        for (id, device) in &mut devices {
            for definition in catalog.fields().filter(|f| fields::visible(f)) {
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
        for device in devices.values_mut() {
            restrict_fields(device, catalog);
        }
        let result: Vec<_> = devices.into_values().collect();
        Ok(result)
    }
}

/// Frozen rule input and caller authorization for one bounded asset page.
pub struct ConditionRequest<'a, C = Criteria> {
    pub watermark: i64,
    pub devices: &'a [DeviceSummary],
    pub catalog: &'a rss_mdm_inventory::Catalog,
    pub authorization: &'a ReadScope,
    pub condition: &'a InventoryCondition<C>,
    pub rule: &'a rss_mdm_group_postgres::core::Rule,
    pub associated: Option<&'a [crate::objects::DeviceObject]>,
}
impl SnapshotReader {
    /// Supply isolated contexts; the Group core owns complete predicate evaluation.
    pub async fn condition_inputs_in<C: serde::Serialize>(
        &self,
        tx: &mut PgTransaction<'_>,
        progress: Option<evaluation::EvaluationProgress>,
        request: ConditionRequest<'_, C>,
    ) -> Result<evaluation::EvaluationStep> {
        let ConditionRequest {
            watermark,
            devices,
            catalog,
            authorization,
            condition,
            rule,
            associated,
        } = request;
        use rss_mdm_group_postgres::core as g;
        use rss_mdm_inventory::CollectionScope as S;
        condition.validate()?;
        let ids: Vec<_> = devices.iter().map(|d| d.scalars.device.clone()).collect();
        if authorization
            .devices
            .as_ref()
            .is_some_and(|allowed| ids.iter().any(|id| !allowed.contains(id)))
        {
            return Err(Error::Forbidden.into());
        }
        filter::require_visible_rule(catalog, rule)?;
        let scopes = if rule.view().fields.is_empty() {
            vec![S::Device]
        } else {
            match &condition.selector {
                ScopeSelector::Device => vec![S::Device],
                ScopeSelector::Exact { scope } => vec![scope.as_ref().clone()],
                ScopeSelector::LocalUser { .. } | ScopeSelector::AllAuthorized => {
                    let tenant = self.tenant.to_string();
                    let selected = ids.clone();
                    let (identity, platform) = match &condition.selector {
                        ScopeSelector::LocalUser { platform, identity } => (
                            Some(identity.clone()),
                            Some(match platform {
                                rss_mdm_inventory::Platform::Windows => "windows",
                                rss_mdm_inventory::Platform::Macos => "macos",
                            }),
                        ),
                        _ => (None, None),
                    };
                    let mut scopes = if identity.is_none() {
                        vec![S::Device]
                    } else {
                        Vec::new()
                    };
                    let raw: Vec<String> = tx.with_connection(move |c| Box::pin(async move {
                    let sources = crate::device::read::sources_at(c, tenant.clone(), selected, watermark).await?;
                    let registrations: Vec<String> = sources.iter().map(|r| r.try_get("registration")).collect::<std::result::Result<_,sqlx::Error>>()?;
                    sqlx::query_scalar("SELECT DISTINCT (f->'scope')::text AS scope FROM mdm_access.collection_history h JOIN mdm_access.collection_versions v ON v.tenant_id=h.tenant_id AND v.version=h.document->>'progress_version' CROSS JOIN LATERAL jsonb_array_elements(v.metadata->'definition'->'fields') f WHERE h.tenant_id=$1::uuid AND revision<=$2 AND h.scope::jsonb->>'registration'=ANY($3) AND ($4::text IS NULL OR ($5::text='macos' AND ((f->'scope'->>'kind' IN ('macos_applications','macos_brew') AND f->'scope'->>'uid'=$4) OR (f->'scope'->'owner'->>'kind'='macos' AND f->'scope'->'owner'->>'uid'=$4))) OR ($5::text='windows' AND f->'scope'->'owner'->>'kind'='windows' AND f->'scope'->'owner'->>'sid'=$4)) LIMIT 129")
                        .bind(tenant).bind(watermark).bind(registrations).bind(identity).bind(platform).fetch_all(c).await
                })).await?;
                    if raw.len() > 128 {
                        return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
                    }
                    for raw in raw {
                        let scope: S = stored(serde_json::from_str(&raw))?;
                        if !scopes.contains(&scope) {
                            scopes.push(scope);
                        }
                    }
                    scopes
                }
            }
        };
        let quantifier = if rule.view().fields.is_empty() {
            g::Quantifier::One
        } else {
            match condition.quantifier {
                ScopeQuantifier::One => g::Quantifier::One,
                ScopeQuantifier::Any => g::Quantifier::Any,
                ScopeQuantifier::All => g::Quantifier::All,
            }
        };
        let keys: Vec<_> = associated.map_or_else(
            || devices.iter().map(|d| d.scalars.device.clone()).collect(),
            |inputs| inputs.iter().map(|i| i.object.key()).collect(),
        );
        let mut objects = keys
            .iter()
            .map(|key| {
                Ok(g::ObjectSnapshot {
                    memberships: BTreeMap::new(),
                    key: checked_input(g::ObjectKey::new(self.tenant, key))?,
                    quantifier,
                    complete: true,
                    contexts: BTreeMap::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut prepared = Vec::new();
        let mut versions = BTreeMap::new();
        for scope in &scopes {
            let scoped = self
                .summary_devices_at_in(tx, watermark, &ids, catalog, scope)
                .await?;
            versions.extend(evaluation::versions(&scoped, catalog, rule)?);
            prepared.push(scoped);
        }
        // Persist at most one unfinished object. Scalar-only pages retain normal batching;
        // callers narrow a page needing resumable payload work before any chunk is read.
        if !versions.is_empty() && objects.len() > 1 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let binding = digest(&(
            "inventory-evaluation-v1",
            self.tenant.to_string(),
            watermark,
            &ids,
            condition,
            rule.view().version,
            associated,
            &prepared,
        ))?;
        let mut progress = progress.unwrap_or(evaluation::EvaluationProgress {
            binding: binding.clone(),
            arrays: BTreeMap::new(),
        });
        if progress.binding != binding {
            return Err(Error::Conflict.into());
        }
        let wanted = evaluation::operands(rule)?;
        let tenant = self.tenant;
        let read_catalog = catalog.clone();
        let (ready, progress) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(async {
                        let ready = evaluation::advance_on(
                            c,
                            tenant,
                            &versions,
                            &read_catalog,
                            &wanted,
                            &mut progress,
                        )
                        .await?;
                        Ok::<_, crate::transaction::Fault>((ready, progress))
                    }
                    .await)
                })
            })
            .await??;
        if !ready {
            return Ok(evaluation::EvaluationStep::Pending(progress));
        }
        let mut contexts = BTreeMap::new();
        for (scope, scoped) in scopes.into_iter().zip(prepared) {
            let facts = if let Some(inputs) = associated {
                filter::associated_page(self.tenant, inputs, &scoped, catalog, rule, &progress)?
            } else {
                filter::page(self.tenant, &scoped, catalog, rule, &progress)?
            };
            for (index, (object, input)) in objects.iter_mut().zip(facts.objects).enumerate() {
                // Multi-scope universes contain only namespaces observed for this endpoint.
                // Exact selection retains an empty context, producing Unknown for missing facts.
                let observed = |device: &DeviceSummary| {
                    !device.scalars.quality.is_empty()
                        || device
                            .scalars
                            .fields
                            .values()
                            .any(|f| !f.sources.is_empty())
                        || device.arrays.values().any(|f| !f.sources.is_empty())
                };
                let exists = associated.map_or_else(
                    || observed(&scoped[index]),
                    |inputs| {
                        scoped
                            .iter()
                            .filter(|d| {
                                inputs[index]
                                    .members
                                    .iter()
                                    .any(|m| m.device == d.scalars.device)
                            })
                            .any(observed)
                    },
                );
                if quantifier != g::Quantifier::One && !exists {
                    continue;
                }
                if associated.is_none() {
                    contexts.insert(
                        (scoped[index].scalars.device.clone(), digest(&scope)?),
                        scoped[index].clone(),
                    );
                }
                object.contexts.insert(
                    digest(&scope)?,
                    input.contexts.into_values().next().expect("single context"),
                );
            }
        }
        Ok(evaluation::EvaluationStep::Ready(filter::FactPage {
            contexts,
            coverage: rule.view().fields.keys().cloned().collect(),
            objects,
        }))
    }
}

pub(super) struct SelectedSources {
    pub scopes: Vec<rss_observation::Scope>,
    pub subjects: BTreeMap<String, (String, u64)>,
    pub channels: BTreeMap<String, BTreeSet<String>>,
}
impl SnapshotReader {
    pub(super) async fn sources_on(
        &self,
        c: &mut sqlx::PgConnection,
        watermark: i64,
        ids: &[String],
        collection_scope: &rss_mdm_inventory::CollectionScope,
        fields: &[FieldKey],
    ) -> Result<SelectedSources> {
        let tenant = self.tenant.to_string();
        let selected = ids.to_vec();
        let rows = crate::device::read::sources_at(c, tenant, selected, watermark).await?;
        if rows.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let datasets =
            rss_mdm_inventory_postgres::datasets_in(c, self.tenant, collection_scope, fields)
                .await
                .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
        let mut channels = BTreeMap::new();
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
                channels
                    .entry(device.clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(channel.to_owned());
                subjects.insert(stored(scope.encode())?, (device.clone(), generation));
                scopes.push(scope);
            }
        }
        Ok(SelectedSources {
            scopes,
            subjects,
            channels,
        })
    }
}
