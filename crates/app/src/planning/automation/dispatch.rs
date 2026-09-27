use super::*;
use sqlx::Row;

impl Planning {
    pub(crate) async fn asset_work_pending(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid),0) OR EXISTS(SELECT 1 FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND enabled AND desired IS NULL)")
                .bind(tenant).fetch_one(c).await
        })).await?)
    }
    pub(crate) async fn dispatch_assets_in(
        &self,
        tx: &mut PgTransaction<'_>,
        compliance: &crate::compliance::Compliance,
    ) -> Result<()> {
        if compliance.dispatch_invalidated(tx).await? {
            return Ok(());
        }
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query("SELECT consumed,watermark,cursor::text,phase FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(tenant).fetch_one(c).await
        })).await?;
        let consumed: i64 = row.try_get("consumed")?;
        let mut watermark: i64 = row.try_get("watermark")?;
        let mut cursor: Option<String> = row.try_get("cursor")?;
        let mut phase: String = row.try_get("phase")?;
        if watermark == consumed {
            let tenant = self.tenant.to_string();
            // Each durable batch exposes at most 1,000 committed ingress records
            // to business owners. Its watermark remains fixed across group pages.
            watermark = tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) page")
                    .bind(tenant).bind(consumed).fetch_one(c).await
            })).await?;
            cursor = None;
            phase = "groups".into();
            if watermark == consumed {
                return Ok(());
            }
        }
        if phase == "groups" {
            self.dispatch_groups_in(tx, consumed, watermark, cursor)
                .await
        } else if phase == "compliance" {
            let next = compliance.dispatch_rules(tx, cursor).await?;
            self.dispatch_cursor_in(
                tx,
                if next.is_some() { consumed } else { watermark },
                watermark,
                next.clone(),
                if next.is_some() {
                    "compliance"
                } else {
                    "groups"
                },
            )
            .await
        } else {
            self.dispatch_devices_in(tx, consumed, watermark, cursor)
                .await
        }
    }
    async fn dispatch_devices_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        if cursor.is_none() {
            let tenant = self.tenant.to_string();
            let devices=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar::<_,String>("SELECT DISTINCT identity->>'device' FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 AND kind IN('device','registration','source','credential')").bind(tenant).bind(consumed).bind(watermark).fetch_all(c).await
            })).await?;
            for device in devices {
                crate::planning::policies::reconcile::wake_native_in(tx, &device).await?;
            }
        }
        let tenant = self.tenant.to_string();
        let scopes:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("WITH changed AS (SELECT DISTINCT identity->>'device' AS device FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 AND kind IN('device','registration','source','credential')) SELECT DISTINCT hit.scope::text FROM changed CROSS JOIN LATERAL (SELECT s.scope FROM mdm_planning.scope_sources s WHERE s.tenant_id=$1::uuid AND s.kind='device' AND s.target=changed.device AND ($4::uuid IS NULL OR s.scope>$4::uuid) ORDER BY s.scope LIMIT 33) hit ORDER BY hit.scope::text LIMIT 33")
                    .bind(tenant).bind(consumed).bind(watermark).bind(cursor).fetch_all(c).await
            })).await?;
        for scope in scopes.iter().take(32) {
            crate::automation::jobs::enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::Scope {
                    scope: stored(Uuid::parse_str(scope))?,
                },
            )
            .await?;
        }
        if scopes.len() > 32 {
            self.dispatch_cursor_in(tx, consumed, watermark, Some(scopes[31].clone()), "devices")
                .await
        } else {
            self.dispatch_cursor_in(tx, consumed, watermark, None, "compliance")
                .await
        }
    }
    async fn dispatch_groups_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        use rss_mdm_group_postgres as g;
        let tenant = self.tenant.to_string();
        let changes = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT kind,identity->>'device' AS device,fields FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT 1001")
                .bind(tenant).bind(consumed).bind(watermark).fetch_all(c).await
        })).await?;
        if changes.len() > 1000 {
            return Err(Error::Unavailable(Failure::PlanningStorage).into());
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
            .map(|s| stored(g::GroupId::parse(s)))
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
            sqlx::query_scalar("SELECT DISTINCT hit.group_id::text FROM unnest($2::text[]) changed(field) CROSS JOIN LATERAL (SELECT f.group_id FROM mdm_planning.group_fields f WHERE f.tenant_id=$1::uuid AND f.field=changed.field AND ($3::uuid IS NULL OR f.group_id>$3::uuid) ORDER BY f.group_id LIMIT 33) hit ORDER BY hit.group_id::text LIMIT 33")
                .bind(tenant).bind(fields).bind(cursor).fetch_all(c).await
        })).await?;
        for id in affected {
            groups.push(stored(g::GroupId::parse(&id))?);
        }
        groups.sort_unstable();
        groups.dedup();
        for group in groups.iter().take(32) {
            self.dispatch_group_in(tx, *group, watermark).await?;
        }
        if groups.len() > 32 {
            self.dispatch_cursor_in(
                tx,
                consumed,
                watermark,
                Some(groups[31].to_string()),
                "groups",
            )
            .await
        } else {
            self.dispatch_cursor_in(tx, consumed, watermark, None, "devices")
                .await
        }
    }
    async fn dispatch_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: rss_mdm_group_postgres::GroupId,
        watermark: i64,
    ) -> Result<()> {
        use rss_mdm_group_postgres as g;
        let current = match self.groups.lock_reference_target_in(tx, group).await? {
            Ok(current) => current,
            Err(g::Rejection::NotFound | g::Rejection::Deleted) => return Ok(()),
            Err(_) => return Err(Error::Conflict.into()),
        };
        if self.group_covers_in(tx, &current, watermark).await? {
            return Ok(());
        }
        let id = stored(Uuid::parse_str(&group.to_string()))?;
        checked(
            self.sources
                .require_reference_input_in(tx, &format!("group-members.{id}"), watermark as u64)
                .await?,
        )?;
        let tenant = self.tenant.to_string();
        let revision = current.revision.get();
        let calculation = current.calculation_revision;
        let rule = current.rule_version.clone();
        let pending:bool=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs j JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(j.tenant_id,j.id) WHERE j.tenant_id=$1::uuid AND j.kind='group' AND b.group_id=$2::uuid AND NOT j.completed AND b.base_calculation=$3 AND b.rule_version IS NOT DISTINCT FROM $4)").bind(tenant).bind(id.to_string()).bind(calculation).bind(rule).fetch_one(c).await
        })).await?;
        if pending {
            return Ok(());
        }
        self.start_group_job_in(
            tx,
            GroupStart {
                id,
                task: Uuid::new_v4(),
                expected: revision as u64,
                patch: (current.kind == g::GroupKind::Static).then(|| g::MemberPatch {
                    add: vec![],
                    remove: vec![],
                }),
                publish: true,
                automatic: true,
                at: stored(Timepoint::try_from(
                    self.clock
                        .unix_seconds()
                        .map_err(|_| Error::Unavailable(Failure::Clock))?,
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
        phase: &str,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let phase = phase.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_planning.asset_dispatch SET consumed=$2,watermark=$3,cursor=$4::uuid,phase=$5 WHERE tenant_id=$1::uuid")
                .bind(tenant).bind(consumed).bind(watermark).bind(cursor).bind(phase).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
