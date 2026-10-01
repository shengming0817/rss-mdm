use super::*;
use rss_mdm_group_postgres as g;

impl Planning {
    pub async fn retry_superseded_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<()> {
        let (job, _, _, _, _) = crate::automation::jobs::read_in(tx, task).await?;
        if let JobInput::Scope { scope } = job {
            let next = crate::automation::jobs::enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::Scope { scope },
            )
            .await?;
            let next = stored(serde_json::from_value::<Uuid>(next["task"].clone()))?;
            return crate::automation::jobs::replacement_in(tx, task, next).await;
        }
        let JobInput::Group {
            group: id,
            watermark,
            publish: true,
            automatic: true,
            ..
        } = job
        else {
            return Ok(());
        };
        let group = checked_input(g::GroupId::parse(&id.to_string()))?;
        let current = match self.groups.lock_reference_target_in(tx, group).await? {
            Ok(group) => group,
            Err(g::Rejection::NotFound | g::Rejection::Deleted) => return Ok(()),
            Err(_) => return Err(Error::Conflict.into()),
        };
        if self.group_covers_in(tx, &current, watermark).await? {
            return Ok(());
        }
        let tenant = self.tenant.to_string();
        let revision = current.revision.get();
        let existing:Option<Uuid>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT j.id FROM mdm_automation.automation_jobs j WHERE j.tenant_id=$1::uuid AND j.target=$2 AND j.kind='group' AND NOT j.completed AND j.id<>$3::uuid AND (j.input->>'base_revision')::bigint=$4 AND j.input->>'automatic'='true' ORDER BY j.id LIMIT 1")
                .bind(tenant).bind(id.to_string()).bind(task.to_string()).bind(revision).fetch_optional(c).await
        })).await?;
        if let Some(successor) = existing {
            crate::automation::jobs::replacement_in(tx, task, successor).await?;
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
                        id,
                        task: Uuid::new_v4(),
                        expected: revision as u64,
                        patch,
                        publish: true,
                        automatic: true,
                        at: checked_input(Timepoint::try_from(
                            self.clock
                                .unix_seconds()
                                .map_err(|_| Error::Unavailable(Failure::Clock))?,
                        ))?,
                    },
                )
                .await?;
            crate::automation::jobs::replacement_in(
                tx,
                task,
                stored(serde_json::from_value(successor["task"].clone()))?,
            )
            .await?;
        }
        Ok(())
    }
    pub async fn group_covers_in(
        &self,
        tx: &mut PgTransaction<'_>,
        current: &g::Group,
        watermark: i64,
    ) -> Result<bool> {
        let Some(run) = checked(self.groups.current_member_set_in(tx, current.id).await?)? else {
            return Ok(false);
        };
        let built = checked(self.groups.build_in(tx, run).await?)?;
        let tenant = self.tenant.to_string();
        let reference = format!("group-members.{}", current.id);
        let observed=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT observed_input FROM mdm_planning.source_heads WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(reference).fetch_one(c).await})).await?;
        Ok(observed >= watermark && built.request.rule_version == current.rule_version)
    }

    pub async fn start_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        start: GroupStart,
    ) -> Result<Value> {
        let GroupStart {
            id,
            task,
            expected,
            patch,
            publish,
            automatic,
            at,
        } = start;
        let group = checked_input(g::GroupId::parse(&id.to_string()))?;
        let current = group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
        if current.revision.get() as u64 != expected {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant;
        let mut watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark unavailable".into()))
                })
            })
            .await?;
        let latest_watermark = watermark;
        let mut changed_devices = None;
        if automatic
            && patch.is_none()
            && let Some(previous) = checked(self.groups.current_member_set_in(tx, group).await?)?
        {
            let old = checked(self.groups.build_in(tx, previous).await?)?;
            if old.request.rule_version == current.rule_version {
                let tenant = self.tenant.to_string();
                let reference = format!("group-members.{id}");
                let base=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT observed_input FROM mdm_planning.source_heads WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(reference).fetch_one(c).await})).await?;
                let tenant = self.tenant.to_string();
                watermark=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("SELECT coalesce(max(revision),$3) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT 1000) b").bind(tenant).bind(base).bind(latest_watermark).fetch_one(c).await
                })).await?;
                let tenant = self.tenant.to_string();
                let catalog_changed=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c JOIN mdm_assets.group_fields f ON f.tenant_id=c.tenant_id AND f.group_id=$4 AND f.field=ANY(c.fields) WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND c.revision<=$3 AND c.kind='catalog')").bind(tenant).bind(base).bind(watermark).bind(id).fetch_one(c).await
                })).await?;
                let tenant = self.tenant.to_string();
                if !catalog_changed {
                    changed_devices=Some(tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar::<_,String>("SELECT device FROM (SELECT DISTINCT coalesce(c.identity->>'device',(SELECT h.device FROM mdm_access.asset_authority_history h WHERE h.tenant_id=c.tenant_id AND h.kind='registration' AND h.identity=c.identity->>'registration' AND h.revision<=c.revision ORDER BY h.revision DESC LIMIT 1)) COLLATE \"C\" AS device FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND c.revision<=$3 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=$4::uuid AND f.field=ANY(c.fields)))) changed WHERE device IS NOT NULL ORDER BY device").bind(tenant).bind(base).bind(watermark).bind(id.to_string()).fetch_all(c).await
                })).await?);
                }
            }
        }
        let job = JobInput::Group {
            group: id,
            base_revision: current.revision.get(),
            watermark,
            publish,
            automatic,
        };
        if patch.is_none()
            && let Some(existing) = self
                .reusable_group_job_in(tx, &current, watermark, publish)
                .await?
        {
            return Ok(crate::automation::jobs::accepted(existing, &job));
        }
        let request = g::BuildRequest {
            id: checked_input(g::OperationId::parse(&task.to_string()))?,
            group,
            expected: current.revision,
            base_calculation: current.calculation_revision,
            changed_devices,
            rule_version: current.rule_version,
            patch,
            input_version: format!("assets:{watermark}"),
            as_of: at,
        };
        checked(self.groups.begin_build_in(tx, &request).await?)?;
        if publish && automatic {
            checked(
                self.sources
                    .require_reference_input_in(
                        tx,
                        &format!("group-members.{id}"),
                        latest_watermark as u64,
                    )
                    .await?,
            )?;
        }
        crate::automation::jobs::enqueue_job_in(tx, task, &job).await
    }

    async fn reusable_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        current: &g::Group,
        watermark: i64,
        publish: bool,
    ) -> Result<Option<Uuid>> {
        let tenant = self.tenant.to_string();
        let id = current.id.to_string();
        let rule = current.rule_version.clone();
        let version = format!("assets:{watermark}");
        let calculation = current.calculation_revision;
        let result=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT j.id FROM mdm_automation.automation_jobs j JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(j.tenant_id,j.id) JOIN mdm_group.groups g ON(g.tenant_id,g.id)=(b.tenant_id,b.group_id) WHERE j.tenant_id=$1::uuid AND b.group_id=$2::uuid AND b.rule_version IS NOT DISTINCT FROM $3 AND b.input_version=$4 AND j.kind=$5 AND j.failure IS NULL AND (b.base_calculation=$6 OR g.member_set=b.id) ORDER BY j.completed DESC,j.id LIMIT 1").bind(tenant).bind(id).bind(rule).bind(version).bind(if publish {"group"}else{"group_preview"}).bind(calculation).fetch_optional(c).await
        })).await?;
        Ok(result)
    }
    async fn append_group_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: g::OperationId,
        build: &g::MemberBuild,
        watermark: i64,
    ) -> Result<()> {
        if build.request.patch.is_some() {
            group_checked(self.groups.advance_static_in(tx, operation).await?)?;
        } else {
            let after = build
                .cursor
                .as_ref()
                .map(|s| stored(g::core::ObjectKey::new(self.tenant, s)))
                .transpose()?;
            let mut limit = 1000;
            loop {
                let page = match self
                    .asset_reader
                    .asset_page_in(
                        tx,
                        watermark,
                        build.cursor.clone(),
                        limit,
                        &assets::ReadScope {
                            subject: "group".into(),
                            sensitive: true,
                            devices: build
                                .request
                                .changed_devices
                                .as_ref()
                                .map(|d| d.iter().cloned().collect()),
                        },
                    )
                    .await
                {
                    Err(rss_mdm_inventory_service::transaction::Fault::Request(
                        rss_mdm_inventory_service::Error::Unavailable(
                            rss_mdm_inventory_service::Failure::AssetBytesLimit
                            | rss_mdm_inventory_service::Failure::AssetSourceLimit,
                        ),
                    )) if limit > 1 => {
                        limit = (limit / 2).max(1);
                        continue;
                    }
                    result => result?,
                };
                let total = build.processed + page.devices.len();
                if total > g::MAX_MEMBERS {
                    return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
                }
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
                let data = stored(assets::filter::page(
                    self.tenant,
                    &page.devices,
                    &page.catalog,
                    &rule,
                ))?;
                if !data.objects.is_empty() {
                    let page_input = g::core::PageInput {
                        tenant: self.tenant,
                        id: "assets",
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
                if page.next.is_none() {
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
        task: Uuid,
        operation: g::OperationId,
        watermark: i64,
    ) -> Result<()> {
        let next = checked(self.groups.advance_difference_in(tx, operation).await?)?;
        if !next.devices.is_empty() {
            let tenant = self.tenant.to_string();
            let devices = next.devices;
            tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("WITH latest AS (SELECT (SELECT revision FROM mdm_access.asset_authority_history h WHERE h.tenant_id=$1::uuid AND h.device=d AND h.revision<=$4 ORDER BY revision DESC LIMIT 1) AS revision FROM unnest($3::text[]) d) UPDATE mdm_automation.automation_jobs SET authority_revision=greatest(authority_revision,coalesce((SELECT max(revision) FROM latest),0)) WHERE tenant_id=$1::uuid AND id=$2::uuid")
                        .bind(tenant).bind(task.to_string()).bind(devices).bind(watermark).execute(c).await?;Ok(())
                })).await?;
        }
        Ok(())
    }

    pub async fn advance_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &JobInput,
        cursor: Option<String>,
    ) -> Result<()> {
        let JobInput::Group {
            group: id,
            watermark,
            publish,
            ..
        } = *job
        else {
            return Err(Error::Unavailable(Failure::PlanningStorage).into());
        };
        let operation = checked_input(g::OperationId::parse(&task.to_string()))?;
        let build = checked(self.groups.build_in(tx, operation).await?)?;
        if build.receipt.is_some() {
            return self.propagate_group_in(tx, task, id, cursor).await;
        }
        if !build.input_sealed {
            return self
                .append_group_input_in(tx, operation, &build, watermark)
                .await;
        }
        if !build.ready {
            return self
                .advance_group_difference_in(tx, task, operation, watermark)
                .await;
        }
        if !publish {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        self.publish_group_job_in(tx, task, job, &build).await
    }
    async fn publish_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &JobInput,
        build: &g::MemberBuild,
    ) -> Result<()> {
        let JobInput::Group {
            group: id,
            watermark,
            automatic,
            ..
        } = *job
        else {
            return Err(Error::Malformed.into());
        };
        let operation = checked_input(g::OperationId::parse(&task.to_string()))?;
        // The immutable old input remains historical evidence. Newer input cannot
        // be acknowledged by publishing this old result under its former watermark.
        let tenant = self.tenant.to_string();
        let (dirty,frontier)=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(bool,i64)>("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=$3::uuid AND f.field=ANY(c.fields)))),coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)")
                .bind(tenant).bind(watermark).bind(id.to_string()).fetch_one(c).await
        })).await?;
        let receipt = checked(self.groups.publish_build_in(tx, operation).await?)?;
        crate::compliance::group_changed(tx, id).await?;
        checked(
            self.sources
                .advance_reference_in(
                    tx,
                    &format!("group-members.{id}"),
                    receipt.group.member_version as u64,
                )
                .await?,
        )?;
        // A single statement proved that no relevant fact exists through frontier.
        // Fast-forward unrelated ingress without reevaluating or rewriting the immutable result.
        let covered = if dirty { watermark } else { frontier };
        checked(
            self.sources
                .observe_reference_input_in(tx, &format!("group-members.{id}"), covered as u64)
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let authority:i64=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT authority_revision FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).fetch_one(c).await
        })).await?;
        let old = checked(
            self.sources
                .reference_in(tx, &format!("group-authority.{id}"))
                .await?,
        )?
        .ok_or(Error::Conflict)?;
        checked(
            self.sources
                .advance_reference_in(
                    tx,
                    &format!("group-authority.{id}"),
                    old.max(authority as u64),
                )
                .await?,
        )?;
        if dirty && automatic {
            let patch = build.request.patch.as_ref().map(|_| g::MemberPatch {
                add: vec![],
                remove: vec![],
            });
            self.start_group_job_in(
                tx,
                GroupStart {
                    id,
                    task: Uuid::new_v4(),
                    expected: receipt.group.revision.get() as u64,
                    patch,
                    publish: true,
                    automatic: true,
                    at: checked_input(Timepoint::try_from(
                        self.clock
                            .unix_seconds()
                            .map_err(|_| Error::Unavailable(Failure::Clock))?,
                    ))?,
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn propagate_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        group: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let rows:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT scope::text FROM mdm_planning.scope_sources WHERE tenant_id=$1::uuid AND kind='group' AND target=$2 AND ($3::uuid IS NULL OR scope>$3::uuid) ORDER BY scope LIMIT 65")
                .bind(tenant).bind(group.to_string()).bind(after).fetch_all(c).await
        })).await?;
        for scope in rows.iter().take(64) {
            crate::automation::jobs::enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::Scope {
                    scope: stored(Uuid::parse_str(scope))?,
                },
            )
            .await?;
        }
        if rows.len() <= 64 {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let cursor = rows[63].clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(task.to_string()).bind(cursor).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    pub async fn register_group_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        revision: u64,
    ) -> Result<()> {
        checked(
            self.sources
                .advance_reference_in(tx, &format!("group-definition.{id}"), revision)
                .await?,
        )?;
        if checked(
            self.sources
                .reference_in(tx, &format!("group-members.{id}"))
                .await?,
        )?
        .is_none()
        {
            checked(
                self.sources
                    .advance_reference_in(tx, &format!("group-members.{id}"), 0)
                    .await?,
            )?;
            checked(
                self.sources
                    .advance_reference_in(tx, &format!("group-authority.{id}"), 0)
                    .await?,
            )?;
        }
        Ok(())
    }
}
