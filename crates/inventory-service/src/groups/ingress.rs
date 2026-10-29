//! Independent bounded consumption of committed Inventory inputs.
use super::*;
use sqlx::Row;
impl Groups {
    pub(super) async fn dispatch_inputs_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.group_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query("SELECT consumed,watermark,cursor FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
        })).await?;
        let consumed: i64 = row.try_get("consumed")?;
        let mut watermark: i64 = row.try_get("watermark")?;
        let cursor: Option<String> = row.try_get("cursor")?;
        if consumed == watermark {
            let tenant = self.tenant.to_string();
            watermark=tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) page")
                    .bind(tenant).bind(consumed).fetch_one(c).await
            })).await?;
        }
        if consumed == watermark {
            return Ok(false);
        }
        self.dispatch_groups_in(tx, consumed, watermark, cursor)
            .await?;
        Ok(true)
    }
    async fn dispatch_groups_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let changes = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT kind,identity->>'device' AS device,fields FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT 1001")
                .bind(tenant).bind(consumed).bind(watermark).fetch_all(c).await
        })).await?;
        if changes.len() > 1000 {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let mut devices = std::collections::BTreeSet::new();
        let mut fields = std::collections::BTreeSet::new();
        let mut authority = false;
        for change in changes {
            fields.extend(change.try_get::<Vec<String>, _>("fields")?);
            if matches!(
                change.try_get::<&str, _>("kind")?,
                "device" | "registration" | "source" | "credential"
            ) {
                authority = true;
                devices.insert(change.try_get::<String, _>("device")?);
            }
        }
        let after = cursor
            .as_deref()
            .map(|s| stored(rss_mdm_group::GroupId::parse(s)))
            .transpose()?;
        let mut groups = checked(
            self.groups
                .affected_groups_in(
                    tx,
                    &devices.into_iter().collect::<Vec<_>>(),
                    authority,
                    after,
                    33,
                )
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let fields: Vec<_> = fields.into_iter().collect();
        let affected: Vec<String> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT hit.group_id::text FROM unnest($2::text[]) changed(field) CROSS JOIN LATERAL (SELECT f.group_id FROM mdm_assets.group_fields f WHERE f.tenant_id=$1::uuid AND f.field=changed.field AND ($3::uuid IS NULL OR f.group_id>$3::uuid) ORDER BY f.group_id LIMIT 33) hit ORDER BY hit.group_id::text LIMIT 33")
                .bind(tenant).bind(fields).bind(cursor).fetch_all(c).await
        })).await?;
        for id in affected {
            groups.push(stored(rss_mdm_group::GroupId::parse(&id))?);
        }
        groups.sort_unstable();
        groups.dedup();
        for group in groups.iter().take(32) {
            self.dispatch_group_in(tx, *group, watermark).await?;
        }
        if groups.len() > 32 {
            self.dispatch_cursor_in(tx, consumed, watermark, Some(groups[31].to_string()))
                .await
        } else {
            self.dispatch_cursor_in(tx, watermark, watermark, None)
                .await
        }
    }
    pub(super) async fn dispatch_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: rss_mdm_group::GroupId,
        watermark: i64,
    ) -> Result<()> {
        let current = match self.groups.lock_reference_target_in(tx, group).await? {
            Ok(current) => current,
            Err(
                rss_mdm_group_postgres::Rejection::NotFound
                | rss_mdm_group_postgres::Rejection::Deleted,
            ) => return Ok(()),
            Err(_) => return Err(Error::Conflict.into()),
        };
        if self.group_covers_in(tx, &current, watermark).await? {
            return Ok(());
        }
        let id = stored(Uuid::parse_str(&group.to_string()))?;
        checked(
            self.groups
                .require_input_in(
                    tx,
                    checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                    watermark as u64,
                )
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let revision = current.revision.get();
        let calculation = current.calculation_revision;
        let rule = current.rule_version.clone();
        let pending:bool=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_assets.group_tasks j JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(j.tenant_id,j.id) WHERE j.tenant_id=$1::uuid AND j.kind='group' AND b.group_id=$2::uuid AND NOT j.completed AND b.base_calculation=$3 AND b.rule_version IS NOT DISTINCT FROM $4)").bind(tenant).bind(id.to_string()).bind(calculation).bind(rule).fetch_one(c).await
        })).await?;
        if pending {
            return Ok(());
        }
        self.start_group_job_in(
            tx,
            GroupStart {
                authority: vec![],
                id,
                task: Uuid::new_v4(),
                expected: revision as u64,
                patch: (current.kind == rss_mdm_group_postgres::GroupKind::Static).then(|| {
                    rss_mdm_group_postgres::MemberPatch {
                        add: vec![],
                        remove: vec![],
                    }
                }),
                publish: true,
                automatic: true,
                at: stored(Timepoint::try_from(
                    self.clock
                        .unix_seconds()
                        .ok_or(Error::Unavailable(Failure::Clock))?,
                ))?,
            },
        )
        .await?;
        Ok(())
    }
    async fn dispatch_cursor_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.group_dispatch SET consumed=$2,watermark=$3,cursor=$4 WHERE tenant_id=$1::uuid")
                .bind(tenant).bind(consumed).bind(watermark).bind(cursor).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}

impl Groups {
    pub(super) async fn inputs_pending_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        self.check_task_transaction(tx)?;
        let objects = self.objects.clone();
        let tenant = self.tenant;
        let relation = tx
            .with_connection(move |c| Box::pin(async move { objects.change_head(c, tenant).await }))
            .await?;
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid),0) OR $2>coalesce((SELECT relation_revision FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid),0)")
                .bind(tenant.to_string()).bind(relation).fetch_one(c).await
        })).await?)
    }
    pub(super) async fn advance_inputs_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.advance_relations_in(tx).await?;
        self.dispatch_inputs_in(tx).await?;
        Ok(())
    }
}
