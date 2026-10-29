use crate::*;
use rss_mdm_scope::Reference;
use rss_mdm_scope_postgres::{Publication, Run, SourceMember};
use sources::{ScopeInput, SourceSet};

fn fingerprint(revision: u64, input: &ScopeInput) -> transaction::Result<Vec<u8>> {
    transaction::fingerprint(&(revision, &input.definition, &input.sources))
}
impl Scopes {
    async fn capture_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> transaction::Result<()> {
        let head = self.store.head_in(tx, scope, true).await?;
        let tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset coordinate unavailable".into()))
                })
            })
            .await?;
        let mut sources = Vec::new();
        for reference in head.definition.references() {
            let mut source = SourceSet {
                reference: reference.clone(),
                coordinates: rss_mdm_group::SourceCoordinates {
                    member_set: None,
                    member_version: 0,
                    definition_version: 0,
                    authority_version: 0,
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                },
                snapshot: None,
            };
            match reference {
                Reference::Group(id) => {
                    let frozen = group_checked(
                        self.groups
                            .capture_source_in(
                                tx,
                                checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                            )
                            .await?,
                    )?;
                    source.coordinates = frozen.coordinates;
                    if let Some(run) = source.coordinates.member_set {
                        let build = checked(self.groups.build_in(tx, run).await?)?;
                        source.snapshot = group_checked(
                            rss_mdm_inventory_service::objects::ObjectSnapshot::from_group_input(
                                &build.request.input_version,
                            ),
                        )?;
                    }
                }
                Reference::Device(device) => {
                    source.coordinates.authority_version =
                        self.device_authority_in(tx, &device, watermark).await?;
                }
            }
            sources.push(source);
        }
        let input = ScopeInput {
            definition: head.definition,
            sources,
            as_of: self.clock.unix_seconds()?,
        };
        let digest = fingerprint(head.revision, &input)?;
        self.store
            .create_run_in(
                tx,
                &Run {
                    id,
                    scope,
                    definition_revision: head.revision,
                    watermark,
                    input: checked_input(serde_json::to_value(input))?,
                    fingerprint: digest,
                    phase: "sources".into(),
                    source_index: 0,
                    source_cursor: None,
                    evaluation_cursor: None,
                    object_count: 0,
                    member_count: 0,
                },
            )
            .await?;
        Ok(())
    }
    pub async fn advance_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> transaction::Result<()> {
        self.store.admit_in(tx).await?;
        let task = self.store.task_in(tx, id).await?;
        self.store.lock_scope_in(tx, task.scope).await?;
        if task.completed {
            return Ok(());
        }
        let Some(run) = self.store.run_in(tx, id).await? else {
            return self.capture_in(tx, id, task.scope).await;
        };
        let input: ScopeInput = stored(serde_json::from_value(run.input.clone()))?;
        if run.scope != task.scope
            || fingerprint(run.definition_revision, &input)? != run.fingerprint
        {
            return Err(Error::Unavailable(Failure::Storage).into());
        }
        let head = self.store.head_in(tx, task.scope, true).await?;
        if head.revision != run.definition_revision {
            return Err(Error::Conflict.into());
        }
        for source in &input.sources {
            if let Reference::Group(id) = source.reference {
                let frozen = rss_mdm_group::GroupSource {
                    group: checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                    coordinates: source.coordinates.clone(),
                };
                if !group_checked(self.groups.source_ready_in(tx, &frozen).await?)? {
                    return Ok(());
                }
            }
        }
        match run.phase.as_str() {
            "sources" => self.source_page_in(tx, &run, &input).await,
            "evaluate" => {
                let targets = input
                    .sources
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| input.definition.targets.contains(&s.reference))
                    .map(|(i, _)| i as i32)
                    .collect();
                self.store
                    .evaluate_page_in(tx, &run, targets, input.sources.len())
                    .await?;
                Ok(())
            }
            "project" => {
                let publication = Publication {
                    scope: run.scope,
                    run: id,
                    definition_revision: run.definition_revision,
                    previous_resolution: head.resolution,
                };
                if self.projection.advance_in(tx, &publication).await? {
                    self.store.phase_in(tx, id, "ready").await?;
                }
                Ok(())
            }
            "ready" => {
                for source in &input.sources {
                    if let Reference::Group(id) = source.reference {
                        let frozen = rss_mdm_group::GroupSource {
                            group: checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                            coordinates: source.coordinates.clone(),
                        };
                        if !group_checked(self.groups.source_current_in(tx, &frozen).await?)? {
                            return Err(Error::Conflict.into());
                        }
                    }
                }
                let publication = Publication {
                    scope: run.scope,
                    run: id,
                    definition_revision: run.definition_revision,
                    previous_resolution: head.resolution,
                };
                let changed = self.projection.publish_in(tx, &publication).await?;
                self.store.publish_in(tx, &publication, changed).await?;
                self.dependents
                    .publication_recorded_in(tx, run.scope, id)
                    .await?;
                self.finish_in(tx, id, None).await?;
                let mut successor = false;
                for source in &input.sources {
                    match &source.reference {
                        Reference::Group(id) => {
                            let current = group_checked(
                                self.groups
                                    .capture_source_in(
                                        tx,
                                        checked_input(rss_mdm_group::GroupId::parse(
                                            &id.to_string(),
                                        ))?,
                                    )
                                    .await?,
                            )?;
                            successor |= current.coordinates != source.coordinates;
                        }
                        Reference::Device(device) => {
                            successor |= self.device_authority_in(tx, device, i64::MAX).await?
                                != source.coordinates.authority_version;
                        }
                    }
                }
                if successor {
                    self.enqueue_in(tx, Uuid::new_v4(), run.scope).await?;
                }
                Ok(())
            }
            "published" => self.finish_in(tx, id, None).await,
            "superseded" => self.finish_in(tx, id, Some("superseded")).await,
            _ => Err(Error::Unavailable(Failure::Storage).into()),
        }
    }
    async fn device_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        watermark: i64,
    ) -> transaction::Result<u64> {
        let tenant = self.tenant;
        let device = device.to_owned();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_registration_service::device::coordinates::authority_at_on(
                        c, tenant, &device, watermark,
                    )
                    .await
                })
            })
            .await?)
    }

    async fn source_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        input: &ScopeInput,
    ) -> transaction::Result<()> {
        let Some(source) = input.sources.get(run.source_index) else {
            self.store.phase_in(tx, run.id, "evaluate").await?;
            return Ok(());
        };
        let mut records = match &source.reference {
            Reference::Device(device) => {
                if run.source_cursor.is_none() {
                    vec![(device.clone(), false, true)]
                } else {
                    vec![]
                }
            }
            Reference::Group(_) => match source.coordinates.member_set {
                None => vec![],
                Some(set) => {
                    let build = checked(self.groups.build_in(tx, set).await?)?;
                    if build.receipt.is_none() {
                        return Err(Error::Unavailable(Failure::Storage).into());
                    }
                    checked(
                        self.groups
                            .build_decisions_in(tx, set, run.source_cursor.clone(), 1000)
                            .await?,
                    )?
                    .into_iter()
                    .map(|d| {
                        (
                            d.device,
                            d.decision == rss_mdm_group_postgres::DecisionValue::Unknown,
                            d.decision != rss_mdm_group_postgres::DecisionValue::NoMatch,
                        )
                    })
                    .collect()
                }
            },
        };
        // Group can stop a nonempty page at its byte budget. Only an empty page proves completion.
        let more = !records.is_empty();
        let cursor = records.last().map(|r| r.0.clone());
        let mut members = Vec::new();
        for (key, unknown, included) in records.drain(..) {
            if !included {
                continue;
            }
            let object = group_checked(rss_mdm_inventory_service::objects::ObjectRef::from_key(
                source.coordinates.asset_context,
                &key,
            ))?;
            let reader = self.objects.clone();
            let tenant = self.tenant;
            let object_key = object.key();
            let input = if let Some(snapshot) = &source.snapshot {
                let snapshot = snapshot.id;
                tx.with_connection(move |c| {
                    Box::pin(async move { reader.lookup(c, tenant, snapshot, &object).await })
                })
                .await?
            } else {
                let rss_mdm_inventory_service::objects::ObjectRef::Endpoint(endpoint) = object
                else {
                    return Err(Error::Conflict.into());
                };
                tx.with_connection(move |c| {
                    Box::pin(async move { reader.endpoint(c, tenant, &endpoint).await })
                })
                .await?
            };
            members.push(SourceMember {
                object: object_key,
                unknown,
                input: checked_input(serde_json::to_value(input))?,
            });
        }
        self.store
            .stage_sources_in(tx, run.id, run.source_index, members, cursor, more)
            .await?;
        Ok(())
    }
}
