use super::tasks::TaskInput;
use super::*;
use rss_mdm_group_postgres as g;

impl Groups {
    pub async fn ensure_group_followup_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let job = self.read_task_in(tx, task).await?.input;
        let TaskInput::Calculation {
            group: id,
            asset_cut,
            covered_inputs,
            ..
        } = job
        else {
            return Ok(());
        };
        let group = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let current = match self.groups.lock_reference_target_in(tx, group).await? {
            Ok(group) => group,
            Err(g::Rejection::NotFound | g::Rejection::Deleted) => return Ok(()),
            Err(_) => return Err(Error::Conflict.into()),
        };
        if self.group_covers_in(tx, &current, &asset_cut).await?
            && !self.inputs_uncovered_in(tx, id, covered_inputs).await? {
            return Ok(());
        }
        let tenant = self.tenant.to_string();
        let revision = current.revision.get();
        let existing:Option<Uuid>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT j.id FROM mdm_assets.group_tasks j WHERE j.tenant_id=$1::uuid AND j.target=$2::uuid AND j.kind='group' AND NOT j.completed AND j.id<>$3::uuid AND (j.input->>'base_revision')::bigint=$4 AND j.input->>'automatic'='true' ORDER BY j.id LIMIT 1")
                .bind(tenant).bind(id.to_string()).bind(task.to_string()).bind(revision).fetch_optional(c).await
        })).await?;
        if let Some(successor) = existing {
            self.replace_task_in(tx, task, successor).await?;
        } else {
            let patch = if current.kind == g::GroupKind::Static {
                Some(g::MemberPatch {
                    add: vec![],
                    remove: vec![],
                })
            } else {
                None
            };
            let successor = self
                .start_group_job_in(
                    tx,
                    GroupStart {
                        asset_cut: candidate.clone(),
                        authority: vec![],
                        id,
                        task: Uuid::new_v4(),
                        expected: revision as u64,
                        patch,
                        automatic: true,
                        at: checked_input(Timepoint::try_from(
                            self.clock
                                .unix_seconds()
                                .ok_or(Error::Unavailable(Failure::Clock))?,
                        ))?,
                    },
                )
                .await?;
            self.replace_task_in(tx, task, successor.task).await?;
        }
        Ok(())
    }
    pub async fn group_covers_in(
        &self,
        tx: &mut PgTransaction<'_>,
        current: &g::Group,
        asset_cut: &rss_mdm_inventory::AssetCut,
    ) -> Result<bool> {
        let Some(run) = checked(self.groups.current_member_set_in(tx, current.id).await?)? else {
            return Ok(false);
        };
        let built = checked(self.groups.build_in(tx, run).await?)?;
        let before = input_cut(&built.request.input_version)?.to_json();
        let after = asset_cut.to_json();
        let tenant = self.tenant.to_string();
        let group = current.id.to_string();
        let dirty: bool = tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND mdm.asset_visible($3,a.revision) AND (a.kind IN('device','registration','source','credential') OR EXISTS(SELECT FROM mdm_assets.group_fields f WHERE f.tenant_id=a.tenant_id AND f.group_id=$4::uuid AND f.field=ANY(a.fields))))")
                .bind(tenant).bind(before).bind(after).bind(group).fetch_one(c).await
        })).await?;
        let relation_current =
            if let Some(snapshot) = object_snapshot(&built.request.input_version)? {
                let reader = self.objects.clone();
                let tenant = self.tenant;
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(reader.capture(c, tenant, Some(snapshot.id)).await?.id == snapshot.id)
                    })
                })
                .await?
            } else {
                true
            };
        for source in &built.request.sources {
            if !self.source_current_in(tx, source).await? {
                return Ok(false);
            }
            let current = group_checked(self.groups.capture_source_in(tx, source.group).await?)?;
            if current.coordinates.member_version != source.coordinates.member_version
                || current.coordinates.authority_version != source.coordinates.authority_version
                || current.coordinates.definition_version != source.coordinates.definition_version {
                return Ok(false);
            }
        }
        Ok(relation_current && !dirty && built.request.rule_version == current.rule_version)
    }

    pub async fn start_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        start: GroupStart,
    ) -> Result<crate::tasks::JobAccepted> {
        let GroupStart {
            mut asset_cut,
            authority,
            id,
            task,
            expected,
            patch,
            automatic,
            at,
        } = start;
        let group = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
        let current = self.lock_calculation_sources_in(tx, group).await?;
        if current.revision.get() as u64 != expected {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant;
        let sources = self
            .group_sources_in(tx, group, current.rule_version.as_deref())
            .await?;
        let mut changed_objects = None;
        if sources.is_empty()
            && current.asset_context == rss_mdm_group::AssetContext::Endpoint
            && automatic
            && patch.is_none()
            && let Some(previous) = checked(self.groups.current_member_set_in(tx, group).await?)?
        {
            let old = checked(self.groups.build_in(tx, previous).await?)?;
            if old.request.rule_version == current.rule_version {
                let before = input_cut(&old.request.input_version)?.to_json();
                let after = asset_cut.to_json();
                let tenant = self.tenant.to_string();
                let f = before.clone();
                let t = after.clone();
                let catalog_changed:bool=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes a JOIN mdm_assets.group_fields f ON f.tenant_id=a.tenant_id AND f.group_id=$4 AND f.field=ANY(a.fields) WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND mdm.asset_visible($3,a.revision) AND a.kind='catalog')")
                        .bind(tenant).bind(f).bind(t).bind(id).fetch_one(c).await
                })).await?;
                if !catalog_changed {
                    let tenant = self.tenant.to_string();
                    let changed:Vec<String>=tx.with_connection(move|c|Box::pin(async move {
                        sqlx::query_scalar("SELECT DISTINCT coalesce(a.identity->>'device',(SELECT h.device FROM mdm_access.asset_authority_history h WHERE h.tenant_id=a.tenant_id AND h.kind='registration' AND h.identity=a.identity->>'registration' ORDER BY h.revision DESC LIMIT 1)) COLLATE \"C\" AS device FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND mdm.asset_visible($3,a.revision) AND (a.kind IN('device','registration','source','credential') OR EXISTS(SELECT FROM mdm_assets.group_fields f WHERE f.tenant_id=a.tenant_id AND f.group_id=$4 AND f.field=ANY(a.fields))) ORDER BY device LIMIT 1001")
                            .bind(tenant).bind(before).bind(after).bind(id).fetch_all(c).await
                    })).await?;
                    if changed.len() <= 1000 {
                        changed_objects = Some(changed);
                    }
                }
            }
        }
        let prior_snapshot = if current.asset_context
            == rss_mdm_group::AssetContext::AssociatedDevice
            && automatic
            && patch.is_none()
        {
            if let Some(previous) = checked(self.groups.current_member_set_in(tx, group).await?)? {
                let previous = checked(self.groups.build_in(tx, previous).await?)?;
                if previous.request.rule_version == current.rule_version
                    && previous.request.sources == sources
                {
                    object_snapshot(&previous.request.input_version)?
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let prior_cut = prior_snapshot.as_ref().map(|s| s.id);
        let snapshot = if current.asset_context == rss_mdm_group::AssetContext::AssociatedDevice {
            let reader = self.objects.clone();
            Some(
                tx.with_connection(move |c| {
                    Box::pin(async move { reader.capture(c, tenant, prior_cut).await })
                })
                .await?,
            )
        } else {
            None
        };
        if let Some(snapshot) = &snapshot {
            asset_cut = snapshot.asset_cut.clone();
            if let Some(prior) = prior_snapshot {
                let reader = self.objects.clone();
                let from = prior.id;
                let to = snapshot.id;
                let from_cut = prior.asset_cut.to_json();
                let to_cut = snapshot.asset_cut.to_json();
                let catalog_changed=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM mdm.asset_changes a JOIN mdm_assets.group_fields f ON f.tenant_id=a.tenant_id AND f.group_id=$4 AND f.field=ANY(a.fields) WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND mdm.asset_visible($3,a.revision) AND a.kind='catalog')").bind(tenant.to_string()).bind(from_cut).bind(to_cut).bind(id).fetch_one(c).await})).await?;
                if !catalog_changed {
                    changed_objects = Some(
                        tx.with_connection(move |c| {
                            Box::pin(async move { reader.changed(c, tenant, from, to).await })
                        })
                        .await?,
                    );
                }
            }
        }
        let input_version = match &snapshot {
            Some(snapshot) => snapshot.group_input(),
            None => asset_cut.input_version(),
        };
        let covered_inputs = self.covered_inputs_in(tx, id, &asset_cut).await?;
        let job = TaskInput::Calculation {
            covered_inputs,
            authority,
            group: id,
            base_revision: current.revision.get(),
            asset_cut,
            automatic,
        };
        if patch.is_none()
            && let Some(existing) = self
                .reusable_group_job_in(tx, &current, &input_version, &sources)
                .await?
        {
            return Ok(tasks::accepted(existing, &job));
        }
        let request = g::BuildRequest {
            sources,
            id: checked_input(rss_mdm_group::OperationId::parse(&task.to_string()))?,
            group,
            expected: current.revision,
            base_calculation: current.calculation_revision,
            changed_objects,
            rule_version: current.rule_version,
            patch,
            input_version,
            as_of: at,
        };
        checked(self.groups.begin_build_in(tx, &request).await?)?;
        self.enqueue_task_in(tx, task, &job).await
    }

    async fn reusable_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        current: &g::Group,
        input_version: &str,
        sources: &[rss_mdm_group::GroupSource],
    ) -> Result<Option<Uuid>> {
        let tenant = self.tenant.to_string();
        let id = current.id.to_string();
        let rule = current.rule_version.clone();
        let version = input_version.to_owned();
        let frozen = checked_input(serde_json::to_value(sources))?;
        let calculation = current.calculation_revision;
        let result=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT j.id FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(j.tenant_id,j.id) JOIN mdm_group.groups g ON(g.tenant_id,g.id)=(b.tenant_id,b.group_id) WHERE j.tenant_id=$1::uuid AND b.group_id=$2::uuid AND b.rule_version IS NOT DISTINCT FROM $3 AND b.input_version=$4 AND convert_from(b.input,'UTF8')::jsonb->'sources'=$6::jsonb AND j.kind='group' AND j.failure IS NULL AND (b.base_calculation=$5 OR g.member_set=b.id) ORDER BY j.completed DESC,j.id LIMIT 1").bind(tenant).bind(id).bind(rule).bind(version).bind(calculation).bind(frozen).fetch_optional(c).await
        })).await?;
        Ok(result)
    }
    async fn append_group_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: rss_mdm_group::OperationId,
        build: &g::MemberBuild,
        asset_cut: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let current = group_checked(
            self.groups
                .lock_reference_target_in(tx, build.request.group)
                .await?,
        )?;
        if let Some(selector) = current.system_selector {
            let tenant = self.tenant.to_string();
            let after = build.cursor.clone();
            let selected = build.request.changed_objects.clone();
            let rows = tx
                .with_connection_context(&mut (asset_cut,), move |(asset_cut,), c| {
                    Box::pin(async move {
                        Ok(
                            rss_mdm_registration_service::device::endpoints::lifecycle_page_at(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                &tenant,
                                asset_cut,
                                after,
                                selected,
                                1000,
                            )
                            .await,
                        )
                    })
                })
                .await?
                .map_err(|_| Error::Unavailable(Failure::GroupStorage))?;
            let total = build.processed + rows.len();
            let decisions = rows
                .iter()
                .map(|row| {
                    let decision = if !row.managed {
                        g::DecisionValue::NoMatch
                    } else if selector == g::SystemSelector::AllActive {
                        g::DecisionValue::Match
                    } else if row.platform_conflict {
                        g::DecisionValue::Conflict
                    } else if row.platform.is_none() {
                        g::DecisionValue::Missing
                    } else if matches!(
                        (selector, row.platform),
                        (
                            g::SystemSelector::Windows,
                            Some(rss_mdm_agent_wire::runtime::TaskPlatform::Windows)
                        ) | (
                            g::SystemSelector::Macos,
                            Some(rss_mdm_agent_wire::runtime::TaskPlatform::Macos)
                        )
                    ) {
                        g::DecisionValue::Match
                    } else {
                        g::DecisionValue::NoMatch
                    };
                    g::DecisionRecord {
                        device: row.device.clone(),
                        origin: g::DecisionOrigin::System,
                        decision: if matches!(
                            decision,
                            g::DecisionValue::Conflict | g::DecisionValue::Missing
                        ) {
                            g::DecisionValue::Unknown
                        } else {
                            decision
                        },
                        explanations: vec![g::PredicateDecision {
                            context: "lifecycle".into(),
                            path: vec![],
                            outcome: decision,
                        }],
                        provenance: vec![],
                    }
                })
                .collect::<Vec<_>>();
            if !decisions.is_empty() {
                group_checked(
                    self.groups
                        .append_system_page_in(tx, operation, build.cursor.as_deref(), &decisions)
                        .await?,
                )?;
            }
            if rows.len() < 1000 {
                group_checked(self.groups.seal_build_in(tx, operation, total).await?)?;
            }
            return Ok(());
        }
        if build.request.patch.is_some() {
            group_checked(self.groups.advance_static_in(tx, operation).await?)?;
        } else {
            let version = build
                .request
                .rule_version
                .as_deref()
                .ok_or(Error::Unavailable(Failure::Runtime))?;
            let rule = group_checked(
                self.groups
                    .rule_in(tx, build.request.group, version)
                    .await?,
            )?
            .ok_or(Error::Unavailable(Failure::Runtime))?;
            let condition =
                crate::condition_in(tx, self.tenant, build.request.group, version, &rule).await?;
            let snapshot = object_snapshot(&build.request.input_version)?;
            let task = stored(Uuid::parse_str(&operation.to_string()))?;
            let after = build
                .cursor
                .as_ref()
                .map(|s| stored(rss_mdm_group::ObjectKey::new(self.tenant, s)))
                .transpose()?;
            let mut limit = if snapshot.is_some() { 250 } else { 1000 };
            loop {
                let progress = self.evaluation(tx, task).await?;
                let page = self
                    .condition_page_in(
                        tx,
                        crate::input::ConditionPageRequest {
                            cut: asset_cut,
                            snapshot: snapshot.as_ref(),
                            condition: &condition,
                            rule: &rule,
                            after: build.cursor.clone(),
                            limit,
                            selected: build.request.changed_objects.clone(),
                            progress,
                        },
                    )
                    .await;
                let page = match page {
                    Err(Fault::Request(Error::Unavailable(
                        Failure::AssetBytesLimit | Failure::AssetSourceLimit,
                    ))) if limit > 1 => {
                        limit = 1;
                        continue;
                    }
                    result => result?,
                };
                let mut data = match page.evaluation {
                    assets::evaluation::EvaluationStep::Pending(progress) => {
                        self.save_evaluation(tx, task, &progress).await?;
                        return Ok(());
                    }
                    assets::evaluation::EvaluationStep::Ready(facts) => {
                        self.clear_evaluation(tx, task).await?;
                        facts
                    }
                };
                match self
                    .fill_group_sources_in(tx, &build.request.sources, &mut data.objects)
                    .await
                {
                    Err(Fault::Request(Error::Unavailable(Failure::AssetBytesLimit)))
                        if limit > 1 =>
                    {
                        limit = (limit / 2).max(1);
                        continue;
                    }
                    result => result?,
                }
                if !data.objects.is_empty() {
                    let page_input = rss_mdm_group::PageInput {
                        tenant: self.tenant,
                        id: if snapshot.is_some() {
                            "objects"
                        } else {
                            "assets"
                        },
                        version: &build.request.input_version,
                        dictionary_version: rss_mdm_inventory::DICTIONARY,
                        coverage: &data.coverage,
                        objects: &data.objects,
                        after: after.as_ref(),
                    };
                    match self
                        .groups
                        .append_build_page_in(tx, operation, &page_input)
                        .await?
                    {
                        Err(g::Rejection::PageBudgetExceeded) if limit > 1 => {
                            limit = (limit / 2).max(1);
                            continue;
                        }
                        result => {
                            group_checked(result)?;
                        }
                    }
                }
                if !page.more {
                    let total = build
                        .processed
                        .checked_add(page.count)
                        .filter(|n| i64::try_from(*n).is_ok())
                        .ok_or(Error::Unavailable(Failure::AssetObjectLimit))?;
                    group_checked(self.groups.seal_build_in(tx, operation, total).await?)?;
                }
                break;
            }
        }
        Ok(())
    }

    async fn advance_group_difference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: rss_mdm_group::OperationId,
    ) -> Result<()> {
        checked(self.groups.advance_difference_in(tx, operation).await?)?;
        Ok(())
    }
    pub async fn advance_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &TaskInput,
        cursor: Option<String>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let TaskInput::Calculation {
            group: id,
            asset_cut,
            ..
        } = job
        else {
            return Err(Error::Unavailable(Failure::GroupStorage).into());
        };
        let id = *id;
        let operation = checked_input(rss_mdm_group::OperationId::parse(&task.to_string()))?;
        let build = checked(self.groups.build_in(tx, operation).await?)?;
        if build.receipt.is_some() {
            return self
                .propagate_group_in(tx, task, id, cursor, candidate)
                .await;
        }
        self.lock_frozen_sources_in(tx, &build.request).await?;
        for source in &build.request.sources {
            if !self.source_ready_in(tx, source).await? {
                return Ok(());
            }
        }
        if !build.input_sealed {
            return self
                .append_group_input_in(tx, operation, &build, asset_cut)
                .await;
        }
        if !build.ready {
            return self.advance_group_difference_in(tx, operation).await;
        }
        self.publish_group_job_in(tx, task, job, &build, candidate)
            .await
    }
    async fn publish_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &TaskInput,
        build: &g::MemberBuild,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let TaskInput::Calculation {
            group: id,
            asset_cut,
            covered_inputs,
            ..
        } = job
        else {
            return Err(Error::Malformed.into());
        };
        let id = *id;
        let operation = checked_input(rss_mdm_group::OperationId::parse(&task.to_string()))?;
        // The immutable old input remains historical evidence. Newer input cannot
        // be acknowledged by publishing this old result under its former asset_cut.
        let tenant = self.tenant.to_string();
        let frozen_cut = asset_cut.to_json();
        let mut dirty:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND (a.kind IN('device','registration','source','credential') OR EXISTS(SELECT FROM mdm_assets.group_fields f WHERE f.tenant_id=a.tenant_id AND f.group_id=$3 AND f.field=ANY(a.fields))))")
                .bind(tenant).bind(frozen_cut).bind(id).fetch_one(c).await
        })).await?;
        if let Some(snapshot) = object_snapshot(&build.request.input_version)? {
            let reader = self.objects.clone();
            let tenant = self.tenant;
            dirty |= tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(reader.capture(c, tenant, Some(snapshot.id)).await?.id != snapshot.id)
                    })
                })
                .await?;
        }
        for source in &build.request.sources {
            if !self.source_current_in(tx, source).await? {
                return Err(Error::Conflict.into());
            }
            let current = self
                .capture_group_source_in(
                    tx,
                    checked_input(Uuid::parse_str(&source.group.to_string()))?,
                )
                .await?;
            dirty |= current.coordinates.member_version != source.coordinates.member_version
                || current.coordinates.authority_version != source.coordinates.authority_version;
        }
        let previous = checked(
            self.groups
                .current_member_set_in(tx, build.request.group)
                .await?,
        )?;
        let definition_changed = if let Some(previous) = previous {
            checked(self.groups.build_in(tx, previous).await?)?.request.rule_version != build.request.rule_version
        } else { true };
        let previous_cut = if let Some(previous) = previous {
            Some(
                input_cut(
                    &checked(self.groups.build_in(tx, previous).await?)?
                        .request
                        .input_version,
                )?
                .to_json(),
            )
        } else {
            None
        };
        let tenant = self.tenant.to_string();
        let next_cut = asset_cut.to_json();
        let identity_changed:bool=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND kind IN('device','registration','source','credential') AND mdm.asset_visible($3,revision) AND NOT mdm.asset_visible($2,revision))")
                .bind(tenant).bind(previous_cut).bind(next_cut).fetch_one(c).await
        })).await?;
        let old = group_checked(
            self.groups
                .capture_source_in(
                    tx,
                    checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                )
                .await?,
        )?
        .coordinates
        .authority_version;
        let evidence_changed = object_snapshot(&build.request.input_version)?.is_some()
            && build
                .request
                .changed_objects
                .as_ref()
                .is_none_or(|objects| !objects.is_empty());
        let authority = if evidence_changed || identity_changed {
            old.checked_add(1).ok_or(Error::Conflict)?
        } else {
            old
        };
        let receipt = checked(
            self.groups
                .publish_build_in(tx, operation, authority)
                .await?,
        )?;
        let changed =
            receipt.group.member_version > build.request.base_calculation || authority > old || definition_changed;
        if changed {
            rss_mdm_compliance_postgres::group_changed_in(tx, id).await?;
        }
        dirty |= self.inputs_uncovered_in(tx, id, *covered_inputs).await?;
        if dirty {
            let patch = build.request.patch.as_ref().map(|_| g::MemberPatch {
                add: vec![],
                remove: vec![],
            });
            self.start_group_job_in(
                tx,
                GroupStart {
                    asset_cut: candidate.clone(),
                    authority: vec![],
                    id,
                    task: Uuid::new_v4(),
                    expected: receipt.group.revision.get() as u64,
                    patch,
                    automatic: true,
                    at: checked_input(Timepoint::try_from(
                        self.clock
                            .unix_seconds()
                            .ok_or(Error::Unavailable(Failure::Clock))?,
                    ))?,
                },
            )
            .await?;
        }
        if !changed {
            self.finish_task_in(tx, task, None).await?;
        }
        Ok(())
    }

    async fn propagate_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        group: Uuid,
        after: Option<String>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let rows:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT key FROM (SELECT 'group:'||g.id::text AS key FROM mdm_group.groups g JOIN mdm_group.rules s ON(s.tenant_id,s.group_id,s.version)=(g.tenant_id,g.id,g.rule_version) WHERE g.tenant_id=$1::uuid AND NOT g.deleted AND s.group_ids @> ARRAY[$2::uuid]) refs WHERE ($3::text IS NULL OR key>$3 COLLATE \"C\") ORDER BY key COLLATE \"C\" LIMIT 65")
                .bind(tenant).bind(group.to_string()).bind(after).fetch_all(c).await
        })).await?;
        for key in rows.iter().take(64) {
            let (kind, id) = key.split_once(':').ok_or(Error::Conflict)?;
            let id = stored(Uuid::parse_str(id))?;
            if kind == "group" {
                let gid = checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?;
                self.dispatch_group_in(tx, gid, candidate).await?;
            }
        }
        if rows.len() <= 64 {
            self.ensure_group_followup_in(tx, task, candidate).await?;
            return self.finish_task_in(tx, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let cursor = rows[63].clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.group_tasks SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(task.to_string()).bind(cursor).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}

pub(crate) fn object_snapshot(
    version: &str,
) -> Result<Option<rss_mdm_inventory_service::objects::ObjectSnapshot>> {
    group_checked(rss_mdm_inventory_service::objects::ObjectSnapshot::from_group_input(version))
}

pub(crate) fn input_cut(version: &str) -> Result<rss_mdm_inventory::AssetCut> {
    if let Some(snapshot) = object_snapshot(version)? {
        return Ok(snapshot.asset_cut);
    }
    stored(rss_mdm_inventory::AssetCut::from_input_version(version))
}
