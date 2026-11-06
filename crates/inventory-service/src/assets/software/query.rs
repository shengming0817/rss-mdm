use super::*;
use crate::assets::{self, evaluation::EvaluationStep, planning::SnapshotReader};
use rss_mdm_group::{AssetContext, Outcome};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_inventory::{ArrayState, CollectionScope, Platform, Scalar, State};

impl AssetService {
    pub(super) async fn software_search(
        &self,
        tx: &mut PgTransaction<'_>,
        access: &Access,
        change: &crate::operation::Operation<Query>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<Response> {
        let input = &change.input;
        if change.expected_revision != 0
            || input.dimensions.len() > 7
            || input.dimensions.iter().collect::<BTreeSet<_>>().len() != input.dimensions.len()
            || input.software.standards.len() > 128
            || input.software.tags.len() > 32
            || input.software.risks.len() > 3
            || !input.devices.fields.is_empty()
            || !input.devices.sort.is_empty()
        {
            return Err(Error::Malformed.into());
        }
        if let Some(groups) = &input.groups {
            filter::validate_groups(&groups.ids)?;
        }
        if let Some(text) = &input.software.filter {
            filter::compile(text)?;
        }
        self.admit_software_result(tx).await?;
        let configuration = self.software_configuration(tx).await?;
        let reader = &self.software_sources.objects;
        let tenant = self.tenant;
        let before = tx
            .with_connection_context(&mut (reader,), move |(reader,), c| {
                Box::pin(async move { reader.relation_revision(c, tenant).await })
            })
            .await?;
        let objects = if input.context == AssetContext::AssociatedDevice {
            Some(
                tx.with_connection_context(&mut (reader,), move |(reader,), c| {
                    Box::pin(async move { reader.capture(c, tenant, None).await })
                })
                .await?,
            )
        } else {
            None
        };
        let asset_cut = objects
            .as_ref()
            .map_or_else(|| candidate.clone(), |o| o.asset_cut.clone());
        let association_revision = tx
            .with_connection_context(&mut (reader,), move |(reader,), c| {
                Box::pin(async move { reader.relation_revision(c, tenant).await })
            })
            .await?;
        if before != association_revision {
            return Err(Error::Conflict.into());
        }
        let catalog = assets::catalog_at_in(tx, self.tenant, &asset_cut).await?;
        let device_query = input.devices.compile(&catalog)?;
        self.validate_query(&device_query, &catalog)?;
        if let Some(condition) = &device_query.criteria {
            assets::filter::require_visible(&catalog, &condition.criteria)?;
        }
        let mut group_ids = BTreeSet::new();
        if let Some(filter) = &input.groups {
            group_ids.extend(filter.ids.iter().copied());
        }
        for standard in &configuration.standards {
            if let Some(ids) = standard
                .definition
                .as_ref()
                .and_then(|s| s.assessments.get(input.context).allowed_groups.as_ref())
            {
                group_ids.extend(ids.iter().copied());
            }
        }
        if group_ids.len() > 256 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let mut groups = Vec::new();
        let mut group_ready = BTreeMap::new();
        for id in group_ids {
            match self
                .software_sources
                .groups
                .capture_source_in(tx, store::group_id(id)?)
                .await?
            {
                Ok(source) => {
                    if source.coordinates.asset_context != input.context {
                        return Err(Error::Malformed.into());
                    }
                    let ready = self
                        .software_sources
                        .groups
                        .source_current_in(tx, &source)
                        .await?
                        .unwrap_or(false);
                    group_ready.insert(id, ready);
                    groups.push(source);
                }
                Err(
                    rss_mdm_group_postgres::Rejection::NotFound
                    | rss_mdm_group_postgres::Rejection::Deleted
                    | rss_mdm_group_postgres::Rejection::IncompleteSnapshot,
                ) => {
                    group_ready.insert(id, false);
                }
                Err(_) => return Err(Error::Unavailable(Failure::AssetsStorage).into()),
            }
        }
        let as_of = self
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let coordinates = Coordinates {
            asset_cut: asset_cut.clone(),
            configuration_revision: configuration.revision,
            association_revision,
            object_snapshot: objects.as_ref().map(|v| v.id),
            object_version: objects.as_ref().map(|v| v.version.clone()),
            context: input.context,
            groups,
            as_of,
        };
        let predicates = configuration
            .mappings
            .iter()
            .filter_map(|r| r.definition.as_ref().map(|m| (r.id, m)))
            .map(|(id, m)| Ok((id, filter::compile(&m.filter)?)))
            .collect::<Result<_>>()?;
        let software_predicate = input
            .software
            .filter
            .as_deref()
            .map(filter::compile)
            .transpose()?;
        let job = Job {
            query: input.clone(),
            predicates,
            software_predicate,
            configuration,
            coordinates,
            objects,
            group_ready,
            authorities: access.authorities.clone(),
        };
        let task = change.operation_id;
        self.enqueue_query_in(
            tx,
            task,
            &assets::tasks::QueryInput {
                query: device_query,
                scope: access.scope.clone(),
                asset_cut,
                as_of,
                software: Some(Box::new(job)),
            },
        )
        .await?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.software_progress(tenant_id,run,document) VALUES($1::uuid,$2,NULL)").bind(tenant).bind(task).execute(c).await?; Ok(())
        })).await?;
        Ok(Response::Mutation {
            receipt: MutationReceipt::Accepted {
                task,
                status_url: format!("/api/v1/software-asset-queries/{task}"),
            },
        })
    }

    pub(super) async fn software_current(
        &self,
        tx: &mut PgTransaction<'_>,
        job: &Job,
    ) -> Result<()> {
        // Match lock order at creation: authorization, configuration, Group, association.
        let now = self
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let authorities = &job.authorities;
        let valid = tx
            .with_connection_context(&mut (authorities,), move |(authorities,), c| {
                Box::pin(async move {
                    for (permission, authority) in *authorities {
                        let valid = authority
                            .valid(StorageProfile::Mdm, c, *permission, now)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("software query authority".into())
                            })?;
                        if !valid {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                })
            })
            .await?;
        if !valid {
            return Err(Error::Forbidden.into());
        }
        if self.software_revision(tx, false).await? != job.coordinates.configuration_revision {
            return Err(Error::Conflict.into());
        }
        for id in job.group_ready.keys() {
            let current = self
                .software_sources
                .groups
                .capture_source_in(tx, store::group_id(*id)?)
                .await?;
            let captured = job
                .coordinates
                .groups
                .iter()
                .find(|g| g.group.to_string() == id.to_string());
            match (current, captured) {
                (Ok(current), Some(old)) if &current == old => (),
                (
                    Err(
                        rss_mdm_group_postgres::Rejection::NotFound
                        | rss_mdm_group_postgres::Rejection::Deleted
                        | rss_mdm_group_postgres::Rejection::IncompleteSnapshot,
                    ),
                    None,
                ) => (),
                _ => return Err(Error::Conflict.into()),
            }
        }
        if job.query.context == AssetContext::AssociatedDevice {
            let reader = &self.software_sources.objects;
            let tenant = self.tenant;
            let revision = tx
                .with_connection_context(&mut (reader,), move |(reader,), c| {
                    Box::pin(async move { reader.relation_revision(c, tenant).await })
                })
                .await?;
            if revision != job.coordinates.association_revision {
                return Err(Error::Conflict.into());
            }
        }
        Ok(())
    }

    pub(in crate::assets) async fn advance_software_query(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &assets::tasks::QueryInput,
        job: &Job,
        after: Option<String>,
    ) -> Result<()> {
        self.software_current(tx, job).await?;
        let tenant = self.tenant.to_string();
        let raw: Option<serde_json::Value> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT document FROM mdm_assets.software_progress WHERE tenant_id=$1::uuid AND run=$2 FOR UPDATE").bind(tenant).bind(task).fetch_one(c).await
        })).await?;
        let mut progress = if let Some(raw) = raw {
            stored(serde_json::from_value::<ObjectProgress>(raw))?
        } else {
            let reader = &self.software_sources.objects;
            let tenant = self.tenant;
            let object = if let Some(snapshot) = &job.objects {
                let snapshot_id = snapshot.id;
                tx.with_connection_context(&mut (reader,), move |(reader,), c| {
                    Box::pin(async move {
                        Ok(reader
                            .page(c, tenant, snapshot_id, after, 1, None)
                            .await?
                            .into_iter()
                            .next())
                    })
                })
                .await?
            } else {
                let page =
                    SnapshotReader::bind(StorageProfile::Mdm, self.runtime.clone(), self.tenant)
                        .asset_page_in(tx, &input.asset_cut, after, 1, &input.scope)
                        .await?;
                if let Some(device) = page.devices.first() {
                    let device = device.scalars.device.clone();
                    let cut = &input.asset_cut;
                    Some(
                        tx.with_connection_context(&mut (reader, cut), move |(reader, cut), c| {
                            Box::pin(
                                async move { reader.endpoint_at(c, tenant, cut, &device).await },
                            )
                        })
                        .await?,
                    )
                } else {
                    None
                }
            };
            let Some(object) = object else {
                return self.finish_query_in(tx, task, None).await;
            };
            let Some(progress) = self
                .prepare_software_object(tx, task, input, job, object)
                .await?
            else {
                return Ok(());
            };
            progress
        };
        if let Some(array) = progress.arrays.get(progress.array).cloned() {
            let tenant = self.tenant;
            let scan = match progress.scan.take() {
                Some(scan) => scan,
                None => {
                    let value = array.value.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(rss_mdm_inventory_postgres::arrays::start_scan(
                                c,
                                tenant,
                                &value.version,
                            )
                            .await
                            .map_err(|_| Error::Malformed))
                        })
                    })
                    .await??
                }
            };
            if scan.metadata().count != array.value.count
                || scan.metadata().bytes != array.value.bytes
                || scan.metadata().digest != array.value.digest
            {
                return Err(Error::Malformed.into());
            }
            let start = scan.next_ordinal();
            let chunk = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(
                            rss_mdm_inventory_postgres::arrays::advance_scan(c, tenant, scan)
                                .await
                                .map_err(|_| Error::Malformed),
                        )
                    })
                })
                .await??;
            for (index, value) in chunk.items.into_iter().enumerate() {
                self.software_evidence(tx, task, job, &mut progress, &array, start + index, value)
                    .await?;
            }
            if chunk.state.verified() {
                progress.array += 1;
            } else {
                progress.scan = Some(chunk.state);
            }
            self.save_software_progress(tx, task, Some(&progress))
                .await?;
            return Ok(());
        }
        // Publish an object's memberships only after every selected immutable array was verified.
        if !self
            .publish_software_object(tx, task, job, &mut progress)
            .await?
        {
            self.save_software_progress(tx, task, Some(&progress))
                .await?;
            return Ok(());
        }
        self.save_software_progress(tx, task, None).await?;
        self.query_cursor_in(
            tx,
            task,
            Some(object_key(job.query.context, &progress.object.object)),
        )
        .await
    }

    async fn prepare_software_object(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &assets::tasks::QueryInput,
        job: &Job,
        object: crate::objects::DeviceObject,
    ) -> Result<Option<ObjectProgress>> {
        let reader = SnapshotReader::bind(StorageProfile::Mdm, self.runtime.clone(), self.tenant);
        let catalog = assets::catalog_at_in(tx, self.tenant, &input.asset_cut).await?;
        let ids: Vec<_> = object
            .members
            .iter()
            .map(|m| m.device.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let devices = reader
            .summary_devices_in(tx, &input.asset_cut, &ids, &catalog)
            .await?;
        let mut matched = object.verified;
        let mut unknown = !object.verified;
        let mut coverage_unknown = !object.verified;
        if let Some(condition) = &input.query.criteria {
            let rule = assets::rule(self.tenant, Uuid::nil(), &condition.criteria, &catalog)?;
            let saved = self.evaluation(tx, task).await?;
            let evaluation = reader
                .condition_inputs_in(
                    tx,
                    saved,
                    assets::planning::ConditionRequest {
                        cut: &input.asset_cut,
                        devices: &devices,
                        catalog: &catalog,
                        authorization: &input.scope,
                        selection: condition.selection(),
                        rule: &rule,
                        associated: (job.query.context == AssetContext::AssociatedDevice)
                            .then_some(std::slice::from_ref(&object)),
                    },
                )
                .await?;
            let facts = match evaluation {
                EvaluationStep::Pending(progress) => {
                    self.save_evaluation(tx, task, &progress).await?;
                    return Ok(None);
                }
                EvaluationStep::Ready(facts) => {
                    self.clear_evaluation(tx, task).await?;
                    facts
                }
            };
            let result = checked_input(rule.evaluate_page(
                &rss_mdm_group::PageInput {
                    tenant: self.tenant,
                    id: "software-assets",
                    version: &input.asset_cut.input_version(),
                    dictionary_version: rss_mdm_inventory::DICTIONARY,
                    coverage: &facts.coverage,
                    objects: &facts.objects,
                    after: None,
                },
                checked_input(rss_contract::Timepoint::try_from(input.as_of))?,
            ))?;
            let decision = result
                .objects
                .first()
                .map(|o| o.decision)
                .unwrap_or(rss_mdm_group::Decision::Unknown);
            matched &= decision == rss_mdm_group::Decision::Match;
            unknown |= decision == rss_mdm_group::Decision::Unknown;
        }
        let key = object_key(job.query.context, &object.object);
        let mut groups = BTreeMap::new();
        for (id, ready) in &job.group_ready {
            let mut decision = Decision::Unknown;
            if *ready && object.verified {
                if let Some(source) = job
                    .coordinates
                    .groups
                    .iter()
                    .find(|g| g.group.to_string() == id.to_string())
                {
                    if let Some(set) = source.coordinates.member_set {
                        let decisions = self
                            .software_sources
                            .groups
                            .source_decisions_in(tx, set, std::slice::from_ref(&key), 1024 * 1024)
                            .await?
                            .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
                        decision = match decisions.outcomes.get(&key) {
                            Some(Outcome::Match) => Decision::Match,
                            Some(Outcome::NoMatch) => Decision::NoMatch,
                            _ => Decision::Unknown,
                        };
                    } else {
                        decision = Decision::NoMatch;
                    }
                }
            }
            groups.insert(*id, decision);
        }
        if let Some(filter) = &job.query.groups {
            let decisions: Vec<_> = filter
                .ids
                .iter()
                .map(|id| groups.get(id).copied().unwrap_or(Decision::Unknown))
                .collect();
            let decision = match filter.combine {
                Combine::Union => filter::union(decisions),
                Combine::Intersection => {
                    if decisions.contains(&Decision::NoMatch) {
                        Decision::NoMatch
                    } else if decisions.contains(&Decision::Unknown) {
                        Decision::Unknown
                    } else {
                        Decision::Match
                    }
                }
            };
            matched &= decision == Decision::Match;
            unknown |= decision == Decision::Unknown;
        }
        let mut dimensions: BTreeMap<Dimension, Vec<String>> = BTreeMap::new();
        for (dimension, field) in [
            (Dimension::Os, "device.os.name"),
            (Dimension::Architecture, "device.architecture"),
        ] {
            let field = checked_input(rss_mdm_inventory::FieldKey::parse(field))?;
            let values: BTreeSet<_> = devices
                .iter()
                .filter_map(|d| d.scalars.fields.get(&field))
                .filter_map(|f| match &f.state {
                    State::Known(Scalar::String(value)) => Some(value.clone()),
                    _ => None,
                })
                .collect();
            dimensions.insert(dimension, values.into_iter().collect());
        }
        dimensions.insert(
            Dimension::DeviceGroup,
            job.query
                .groups
                .as_ref()
                .map(|f| {
                    f.ids
                        .iter()
                        .filter(|id| groups.get(id) == Some(&Decision::Match))
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        );
        let mut arrays = Vec::new();
        let mut quality = Vec::new();
        let mut known = false;
        for device in devices {
            let endpoint = &device.scalars.device;
            let mut scopes = vec![CollectionScope::Device];
            if let assets::Response::InventoryScopes {
                items, next_cursor, ..
            } = self
                .inventory_scopes(tx, endpoint, &input.scope, 1000, None, &input.asset_cut)
                .await?
            {
                if next_cursor.is_some() {
                    return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
                }
                scopes.extend(items.into_iter().map(|i| i.scope));
            }
            let platform = platform(&device);
            for scope in scopes {
                let tenant = self.tenant;
                let cut = &input.asset_cut;
                let selected = vec![endpoint.clone()];
                let reader = &reader;
                let catalog = &catalog;
                let current_scope = &scope;
                let summaries = tx
                    .with_connection_context(
                        &mut (reader, cut, catalog, current_scope),
                        move |(reader, cut, catalog, scope), c| {
                            Box::pin(async move {
                                reader
                                    .scoped_summary_devices_on(c, cut, &selected, catalog, scope)
                                    .await
                                    .map_err(|_| {
                                        sqlx::Error::Protocol(format!("software snapshot {tenant}"))
                                    })
                            })
                        },
                    )
                    .await?;
                for summary in summaries {
                    for source in SoftwareSource::ALL {
                        let field =
                            checked_input(rss_mdm_inventory::FieldKey::parse(source.field()))?;
                        let Some(resolved) = summary.arrays.get(&field) else {
                            continue;
                        };
                        known |= matches!(resolved.state, ArrayState::Known(_));
                        coverage_unknown |= matches!(
                            resolved.state,
                            ArrayState::Unknown { .. } | ArrayState::Conflict
                        );
                        let retained = resolved
                            .sources
                            .iter()
                            .filter_map(|f| f.last_known.as_ref())
                            .map(|old| RetainedEvidence {
                                array_version: old.value.version.clone(),
                                count: old.value.count,
                                evidence: old.evidence.clone(),
                            })
                            .collect();
                        quality.push(Quality {
                            endpoint: endpoint.clone(),
                            source,
                            scope: scope.clone(),
                            state: assets::lists::metadata_state(&resolved.state),
                            last_known: retained,
                            runs: summary.scalars.quality.clone(),
                        });
                        for fact in &resolved.sources {
                            let current = match (&resolved.state, &fact.state) {
                                (ArrayState::Known(selected), ArrayState::Known(value))
                                    if selected == value =>
                                {
                                    Some((value, &fact.evidence, object.verified))
                                }
                                _ => None,
                            };
                            let value = current.or_else(|| {
                                fact.last_known
                                    .as_ref()
                                    .map(|v| (&v.value, &v.evidence, false))
                            });
                            let fact_platform = platform.or(match source {
                                SoftwareSource::WindowsWin32
                                | SoftwareSource::WindowsStore
                                | SoftwareSource::WindowsNonStore
                                | SoftwareSource::WindowsSystem => Some(Platform::Windows),
                                SoftwareSource::AppleApplications => Some(Platform::Macos),
                                SoftwareSource::Installations => match fact.evidence.source {
                                    rss_mdm_inventory::Source::MdmWindows => {
                                        Some(Platform::Windows)
                                    }
                                    rss_mdm_inventory::Source::MdmApple => Some(Platform::Macos),
                                    _ => None,
                                },
                            });
                            coverage_unknown |= value.is_some() && fact_platform.is_none();
                            if let (Some(platform), Some((value, evidence, confirmed))) =
                                (fact_platform, value)
                            {
                                arrays.push(ArrayInput {
                                    endpoint: endpoint.clone(),
                                    source,
                                    platform,
                                    evidence: evidence.clone(),
                                    value: value.clone(),
                                    confirmed,
                                });
                            }
                        }
                    }
                }
            }
        }
        coverage_unknown |= !known;
        unknown |= coverage_unknown;
        if arrays.len() > 4096 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        Ok(Some(ObjectProgress {
            object,
            matched,
            unknown,
            coverage_unknown,
            groups,
            dimensions,
            arrays,
            array: 0,
            scan: None,
            published_after: None,
            quality,
        }))
    }

    async fn save_software_progress(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        progress: Option<&ObjectProgress>,
    ) -> Result<()> {
        let document = progress
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
        if document
            .as_ref()
            .is_some_and(|v| v.to_string().len() > 16 * 1024 * 1024)
        {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move { sqlx::query("UPDATE mdm_assets.software_progress SET document=$3 WHERE tenant_id=$1::uuid AND run=$2").bind(tenant).bind(task).bind(document).execute(c).await?; Ok(()) })).await?;
        Ok(())
    }
}
pub(super) fn object_key(context: AssetContext, object: &crate::objects::ObjectRef) -> String {
    match (context, object) {
        (AssetContext::Endpoint, crate::objects::ObjectRef::Endpoint(id)) => id.clone(),
        _ => object.key(),
    }
}
fn platform(device: &assets::DeviceSummary) -> Option<Platform> {
    let key = rss_mdm_inventory::FieldKey::parse("device.os.name").ok()?;
    match &device.scalars.fields.get(&key)?.state {
        State::Known(Scalar::String(value)) => match value.to_lowercase().as_str() {
            "windows" => Some(Platform::Windows),
            "macos" | "mac os x" => Some(Platform::Macos),
            _ => None,
        },
        _ => None,
    }
}
