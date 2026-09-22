use super::*;
use rss_mdm_group_postgres as g;

impl Management {
    pub(super) async fn retry_superseded_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<()> {
        let (job, _, _, _, _) = self.job_in(tx, task).await?;
        let JobInput::Group {
            group: id,
            watermark,
            publish: true,
            automatic: true,
        } = job
        else {
            return Ok(());
        };
        let group = input(g::GroupId::parse(&id.to_string()))?;
        let current = match self.groups.lock_reference_target_in(tx, group).await? {
            Ok(group) => group,
            Err(g::Rejection::NotFound | g::Rejection::Deleted) => return Ok(()),
            Err(_) => return Err(Error::Conflict.into()),
        };
        if let Some(run) = checked(self.groups.current_member_set_in(tx, group).await?)? {
            let built = checked(self.groups.build_in(tx, run).await?)?;
            let observed = built
                .request
                .input_version
                .strip_prefix("assets:")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
            if observed >= watermark && built.request.rule_version == current.rule_version {
                return Ok(());
            }
        }
        let tenant = self.tenant.to_string();
        let revision = current.revision.get();
        let exists:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_management.automation_jobs j JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id=$1::uuid AND j.target=$2 AND j.kind='group' AND NOT j.completed AND j.id<>$3::uuid AND r.base_revision=$4 AND j.input->>'automatic'='true')")
                .bind(tenant).bind(id.to_string()).bind(task.to_string()).bind(revision).fetch_one(c).await
        })).await?;
        if !exists {
            let patch = if current.kind == g::GroupKind::Static {
                Some(g::MemberPatch {
                    add: vec![],
                    remove: vec![],
                })
            } else {
                None
            };
            self.start_group_job_in(
                tx,
                id,
                Uuid::new_v4(),
                revision as u64,
                patch,
                true,
                true,
                input(Timepoint::try_from(
                    self.clock
                        .unix_seconds()
                        .map_err(|_| Error::Unavailable(Failure::Clock))?,
                ))?,
            )
            .await?;
        }
        Ok(())
    }
    pub(in crate::management) async fn start_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        task: Uuid,
        expected: u64,
        patch: Option<g::MemberPatch>,
        publish: bool,
        automatic: bool,
        at: Timepoint,
    ) -> Result<Value> {
        let group = input(g::GroupId::parse(&id.to_string()))?;
        let current = group_checked(self.groups.lock_reference_target_in(tx, group).await?)?;
        if current.revision.get() as u64 != expected {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark unavailable".into()))
                })
            })
            .await?;
        let request = g::BuildRequest {
            id: input(g::OperationId::parse(&task.to_string()))?,
            group,
            expected: current.revision,
            rule_version: current.rule_version,
            patch,
            input_version: format!("assets:{watermark}"),
            as_of: at,
        };
        checked(self.groups.begin_build_in(tx, &request).await?)?;
        if publish {
            checked(
                self.policies
                    .require_reference_input_in(
                        tx,
                        &format!("group-members.{id}"),
                        watermark as u64,
                    )
                    .await?,
            )?;
        }
        self.enqueue_job_in(
            tx,
            task,
            &JobInput::Group {
                group: id,
                watermark,
                publish,
                automatic,
            },
        )
        .await
    }

    pub(super) async fn advance_group_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        id: Uuid,
        watermark: i64,
        publish: bool,
        automatic: bool,
        cursor: Option<String>,
    ) -> Result<()> {
        let operation = input(g::OperationId::parse(&task.to_string()))?;
        let build = checked(self.groups.build_in(tx, operation).await?)?;
        if build.receipt.is_some() {
            return self.propagate_group_in(tx, task, id, cursor).await;
        }
        if !build.input_sealed {
            if build.request.patch.is_some() {
                checked(self.groups.advance_static_in(tx, operation).await?)?;
            } else {
                let page = self
                    .asset_page_in(
                        tx,
                        watermark,
                        build.cursor.clone(),
                        256,
                        &assets::ReadScope::all(),
                    )
                    .await?;
                let input_page = assets::criteria::snapshot(self.tenant, &page.devices)?;
                let after = build
                    .cursor
                    .as_ref()
                    .map(|s| input(g::core::ObjectKey::new(self.tenant, s)))
                    .transpose()?;
                let total = build.objects + page.devices.len();
                if total > g::MAX_MEMBERS {
                    return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
                }
                if !input_page.objects.is_empty() {
                    let input = g::core::PageInput {
                        tenant: self.tenant,
                        id: "assets",
                        version: &build.request.input_version,
                        dictionary_version: rss_mdm_inventory::DICTIONARY,
                        coverage: &input_page.coverage,
                        objects: &input_page.objects,
                        after: after.as_ref(),
                    };
                    checked(
                        self.groups
                            .append_build_page_in(tx, operation, &input)
                            .await?,
                    )?;
                }
                if page.next.is_none() {
                    checked(self.groups.seal_build_in(tx, operation, total).await?)?;
                }
            }
            return Ok(());
        }
        if !build.ready {
            let next = checked(self.groups.advance_difference_in(tx, operation).await?)?;
            if let Some(last) = next.difference_cursor {
                let tenant = self.tenant.to_string();
                let after = build.difference_cursor;
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query(r#"
                      WITH members AS (
                        SELECT DISTINCT m.object_id FROM mdm_group.member_rows m
                        WHERE m.tenant_id=$1::uuid AND m.matched AND (m.run_id=$2::uuid OR m.run_id=(SELECT member_set FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$3::uuid))
                          AND ($4::text IS NULL OR m.object_id>$4 COLLATE "C") AND m.object_id<=$5 COLLATE "C"
                      ), latest AS (
                        SELECT (SELECT revision FROM mdm_access.asset_authority_history h WHERE h.tenant_id=$1::uuid AND h.device=m.object_id AND h.revision<=$6 ORDER BY revision DESC LIMIT 1) AS revision FROM members m
                      ) UPDATE mdm_management.automation_jobs SET authority_revision=greatest(authority_revision,coalesce((SELECT max(revision) FROM latest),0)) WHERE tenant_id=$1::uuid AND id=$2::uuid
                    "#).bind(tenant).bind(task.to_string()).bind(id.to_string()).bind(after).bind(last).bind(watermark).execute(c).await?;Ok(())
                })).await?;
            }
            return Ok(());
        }
        if !publish {
            return self.finish_job_in(tx, task, None).await;
        }
        // The immutable old input remains historical evidence. Newer input cannot
        // be acknowledged by publishing this old result under its former watermark.
        let tenant = self.tenant.to_string();
        let dirty:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_management.group_fields f WHERE f.tenant_id=c.tenant_id AND f.group_id=$3::uuid AND f.field=ANY(c.fields))))")
                .bind(tenant).bind(watermark).bind(id.to_string()).fetch_one(c).await
        })).await?;
        let receipt = checked(self.groups.publish_build_in(tx, operation).await?)?;
        checked(
            self.policies
                .advance_reference_in(
                    tx,
                    &format!("group-members.{id}"),
                    receipt.group.member_version as u64,
                )
                .await?,
        )?;
        checked(
            self.policies
                .observe_reference_input_in(tx, &format!("group-members.{id}"), watermark as u64)
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let authority:i64=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT authority_revision FROM mdm_management.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).fetch_one(c).await
        })).await?;
        let old = checked(
            self.policies
                .reference_in(tx, &format!("group-authority.{id}"))
                .await?,
        )?
        .ok_or(Error::Conflict)?;
        checked(
            self.policies
                .advance_reference_in(
                    tx,
                    &format!("group-authority.{id}"),
                    old.max(authority as u64),
                )
                .await?,
        )?;
        if dirty && automatic {
            let patch = build.request.patch.map(|_| g::MemberPatch {
                add: vec![],
                remove: vec![],
            });
            self.start_group_job_in(
                tx,
                id,
                Uuid::new_v4(),
                receipt.group.revision.get() as u64,
                patch,
                true,
                true,
                input(Timepoint::try_from(
                    self.clock
                        .unix_seconds()
                        .map_err(|_| Error::Unavailable(Failure::Clock))?,
                ))?,
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
            sqlx::query_scalar("SELECT scope::text FROM mdm_management.scope_sources WHERE tenant_id=$1::uuid AND kind='group' AND target=$2 AND ($3::uuid IS NULL OR scope>$3::uuid) ORDER BY scope LIMIT 65")
                .bind(tenant).bind(group.to_string()).bind(after).fetch_all(c).await
        })).await?;
        for scope in rows.iter().take(64) {
            self.enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::Scope {
                    scope: stored(Uuid::parse_str(scope))?,
                },
            )
            .await?;
        }
        if rows.len() <= 64 {
            return self.finish_job_in(tx, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let cursor = rows[63].clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_management.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(task.to_string()).bind(cursor).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    pub(in crate::management) async fn register_group_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        revision: u64,
        criteria: Option<&assets::Criteria>,
    ) -> Result<()> {
        let mut fields = std::collections::BTreeSet::new();
        fn collect(c: &assets::Criteria, out: &mut std::collections::BTreeSet<String>) {
            match c {
                assets::Criteria::Predicate { field, .. } => {
                    out.insert(field.as_str().to_owned());
                }
                assets::Criteria::And { children } | assets::Criteria::Or { children } => {
                    for c in children {
                        collect(c, out);
                    }
                }
            }
        }
        if let Some(criteria) = criteria {
            collect(criteria, &mut fields);
        }
        let tenant = self.tenant.to_string();
        let fields: Vec<_> = fields.into_iter().collect();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("DELETE FROM mdm_management.group_fields WHERE tenant_id=$1::uuid AND group_id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_management.group_fields SELECT $1::uuid,$2::uuid,f FROM unnest($3::text[]) f").bind(tenant).bind(id.to_string()).bind(fields).execute(c).await?;Ok(())
        })).await?;
        checked(
            self.policies
                .advance_reference_in(tx, &format!("group-definition.{id}"), revision)
                .await?,
        )?;
        if checked(
            self.policies
                .reference_in(tx, &format!("group-members.{id}"))
                .await?,
        )?
        .is_none()
        {
            checked(
                self.policies
                    .advance_reference_in(tx, &format!("group-members.{id}"), 0)
                    .await?,
            )?;
            checked(
                self.policies
                    .advance_reference_in(tx, &format!("group-authority.{id}"), 0)
                    .await?,
            )?;
        }
        Ok(())
    }
}
