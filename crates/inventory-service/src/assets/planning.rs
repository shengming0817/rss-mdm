//! Transaction-borrowing, bounded asset snapshot projection consumed by target planning.
//! Fixed-cut enumeration. No transaction survives a returned page.
use super::*;
use sqlx::Row;

pub struct AssetPage {
    pub catalog: rss_mdm_inventory::Catalog,
    pub devices: Vec<DeviceSummary>,
    pub next: Option<String>,
}
#[derive(Clone)]
pub struct SnapshotReader {
    pub(super) profile: rss_mdm_install_support::StorageProfile,
    pub(super) tenant: TenantId,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
}
impl SnapshotReader {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn bind(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        tenant: TenantId,
    ) -> Self {
        Self {
            profile,
            runtime,
            tenant,
        }
    }
    fn check_in(&self, tx: &PgTransaction<'_>, cut: &rss_mdm_inventory::AssetCut) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant || cut.tenant() != Uuid::from_bytes(self.tenant.octets()) {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }

    pub async fn live_devices_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        cut: &rss_mdm_inventory::AssetCut,
        devices: &[String],
    ) -> Result<BTreeSet<String>> {
        let profile = self.profile;

        self.check_in(tx, cut)?;
        if devices.len() > 1000 {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let tenant = self.tenant.to_string();
        let devices = devices.to_vec();
        let rows: Vec<String> = tx
            .with_connection_context(&mut (cut,), move |(cut,), c| {
                Box::pin(async move {
                    crate::device::read::live_at(profile, c, tenant, devices, cut).await
                })
            })
            .await?;
        Ok(rows.into_iter().collect())
    }
    pub async fn asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        cut: &rss_mdm_inventory::AssetCut,
        after: Option<String>,
        limit: usize,
        scope: &ReadScope,
    ) -> Result<AssetPage> {
        let profile = self.profile;

        self.check_in(tx, cut)?;
        if !(1..=1000).contains(&limit) {
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
            .with_connection_context(&mut (cut,), move |(cut,), c| {
                Box::pin(async move {
                    crate::device::read::page_at(
                        profile,
                        c,
                        tenant,
                        cut,
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
        let catalog = catalog_at_in(tx, self.tenant, cut).await?;
        let mut devices = self
            .summary_devices_at_in(tx, cut, &ids, &catalog, &scope.collection_scope)
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
        cut: &rss_mdm_inventory::AssetCut,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,
        collection_scope: &rss_mdm_inventory::CollectionScope,
    ) -> Result<Vec<DeviceSummary>> {
        self.check_in(tx, cut)?;
        let reader = self.clone();
        let ids = ids.to_vec();
        let catalog = catalog.clone();
        let collection_scope = collection_scope.clone();
        tx.with_connection_context(&mut (cut,), move |(cut,), c| {
            Box::pin(async move {
                Ok(reader
                    .scoped_summary_devices_on(c, cut, &ids, &catalog, &collection_scope)
                    .await)
            })
        })
        .await?
    }

    /// Bounded scalar and array summaries borrowed from this runtime's original transaction.
    pub async fn summary_devices_in(
        &self,
        tx: &mut PgTransaction<'_>,
        cut: &AssetCut,
        ids: &[String],
        catalog: &rss_mdm_inventory::Catalog,
    ) -> Result<Vec<DeviceSummary>> {
        self.summary_devices_at_in(
            tx,
            cut,
            ids,
            catalog,
            &rss_mdm_inventory::CollectionScope::Device,
        )
        .await
    }
}

/// Frozen rule input and caller authorization for one bounded asset page.
pub struct ConditionRequest<'a> {
    pub cut: &'a rss_mdm_inventory::AssetCut,
    pub devices: &'a [DeviceSummary],
    pub catalog: &'a rss_mdm_inventory::Catalog,
    pub authorization: &'a ReadScope,
    pub selection: ConditionSelection<'a>,
    pub rule: &'a rss_mdm_group::Rule,
    pub associated: Option<&'a [crate::objects::DeviceObject]>,
}
impl SnapshotReader {
    /// Supply isolated contexts; the Group core owns complete predicate evaluation.
    pub async fn condition_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        progress: Option<evaluation::EvaluationProgress>,
        request: ConditionRequest<'_>,
    ) -> Result<evaluation::EvaluationStep> {
        let profile = self.profile;

        let ConditionRequest {
            cut,
            devices,
            catalog,
            authorization,
            selection,
            rule,
            associated,
        } = request;
        use rss_mdm_group as g;
        use rss_mdm_inventory::CollectionScope as S;
        self.check_in(tx, cut)?;
        selection.validate()?;
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
            match selection.selector {
                ScopeSelector::Device => vec![S::Device],
                ScopeSelector::Exact { scope } => vec![scope.as_ref().clone()],
                ScopeSelector::LocalUser { .. } | ScopeSelector::AllAuthorized => {
                    let tenant = self.tenant.to_string();
                    let selected = ids.clone();
                    let (identity, platform) = match selection.selector {
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
                    let raw: Vec<String> = tx
                        .with_connection_context(&mut (cut,), move |(cut,), c| {
                            Box::pin(async move {
                                let sources = crate::device::read::sources_at(
                                    profile,
                                    c,
                                    tenant.clone(),
                                    selected,
                                    cut,
                                )
                                .await?;
                                let registrations: Vec<String> = sources
                                    .iter()
                                    .map(|r| r.try_get("registration"))
                                    .collect::<std::result::Result<_, sqlx::Error>>()?;
                                sqlx::query_scalar(
                                    crate::storage_profile::sql(profile)
                                        .assets_planning_condition_inputs_in_1,
                                )
                                .bind(tenant)
                                .bind(cut.to_json())
                                .bind(registrations)
                                .bind(identity)
                                .bind(platform)
                                .fetch_all(c)
                                .await
                            })
                        })
                        .await?;
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
            match selection.quantifier {
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
                .summary_devices_at_in(tx, cut, &ids, catalog, scope)
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
            cut,
            &ids,
            selection,
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
    pub subjects: BTreeMap<String, (String, u64)>,
}
impl SnapshotReader {
    pub(super) async fn select_sources_on(
        profile: rss_mdm_install_support::StorageProfile,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
        rows: Vec<sqlx::postgres::PgRow>,
        collection_scope: &rss_mdm_inventory::CollectionScope,
        fields: &[FieldKey],
    ) -> Result<SelectedSources> {
        if rows.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let datasets = rss_mdm_inventory_postgres::datasets_in(c, tenant, collection_scope, fields)
            .await
            .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
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
                    profile,
                    tenant,
                    stored(Uuid::parse_str(row.try_get("registration")?))?,
                    source.as_str(),
                    stored(Uuid::parse_str(row.try_get("epoch")?))?,
                    dataset,
                )?;
                let generation: u64 = stored(row.try_get::<&str, _>("generation")?.parse())?;
                subjects.insert(stored(scope.encode())?, (device.clone(), generation));
            }
        }
        Ok(SelectedSources { subjects })
    }
}

/// One committed change in a fixed asset window. Interpretation belongs to the consuming owner.
pub struct AssetChange {
    pub revision: i64,
    pub kind: ChangeKind,
    pub device: Option<String>,
    pub fields: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Inventory,
    Manual,
    Device,
    Registration,
    Source,
    Credential,
    Collection,
    Catalog,
}
impl ChangeKind {
    pub fn changes_authority(self) -> bool {
        matches!(
            self,
            Self::Device | Self::Registration | Self::Source | Self::Credential
        )
    }
}
impl SnapshotReader {
    /// Read at most one page; both cuts are from this reader's tenant.
    pub async fn changes_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        from: Option<&AssetCut>,
        to: &AssetCut,
        after: i64,
        through: Option<i64>,
        limit: usize,
    ) -> Result<Vec<AssetChange>> {
        self.check_in(tx, to)?;
        if let Some(from) = from {
            self.check_in(tx, from)?;
        }
        if after < 0 || !(1..=1000).contains(&limit) || through.is_some_and(|v| v < after) {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let from = from.map(AssetCut::to_json);
        let to = to.to_json();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT revision,kind,identity->>'device' AS device,fields FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible($2,revision) AND mdm.asset_visible($3,revision) AND revision>$4 AND ($5::bigint IS NULL OR revision<=$5) ORDER BY revision LIMIT $6")
                .bind(tenant).bind(from).bind(to).bind(after).bind(through).bind(limit as i64).fetch_all(c).await
        })).await?;
        rows.into_iter()
            .map(|r| {
                Ok(AssetChange {
                    revision: r.try_get("revision")?,
                    kind: stored(serde_json::from_value(Value::String(r.try_get("kind")?)))?,
                    device: r.try_get("device")?,
                    fields: r.try_get("fields")?,
                })
            })
            .collect()
    }
    /// Check committed facts after an optional cut, optionally within a fixed upper cut.
    pub async fn changes_exist_in(
        &self,
        tx: &mut PgTransaction<'_>,
        from: Option<&AssetCut>,
        to: Option<&AssetCut>,
    ) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        for cut in [from, to].into_iter().flatten() {
            self.check_in(tx, cut)?;
        }
        let tenant = self.tenant.to_string();
        let from = from.map(AssetCut::to_json);
        let to = to.map(AssetCut::to_json);
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible($2,revision) AND ($3::jsonb IS NULL OR mdm.asset_visible($3,revision)))")
                .bind(tenant).bind(from).bind(to).fetch_one(c).await
        })).await?)
    }
}
