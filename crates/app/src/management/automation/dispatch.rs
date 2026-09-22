use super::*;
use sqlx::Row;

impl Management {
    pub(super) async fn asset_work_pending(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_management.asset_dispatch WHERE tenant_id=$1::uuid),0)")
                .bind(tenant).fetch_one(c).await
        })).await?)
    }
    pub(super) async fn dispatch_assets_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query("SELECT consumed,watermark,group_cursor::text,phase FROM mdm_management.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(tenant).fetch_one(c).await
        })).await?;
        let consumed: i64 = row.try_get("consumed")?;
        let mut watermark: i64 = row.try_get("watermark")?;
        let mut cursor: Option<String> = row.try_get("group_cursor")?;
        let mut phase: String = row.try_get("phase")?;
        if watermark == consumed {
            let tenant = self.tenant;
            watermark = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        rss_mdm_inventory_postgres::watermark_in(c, tenant)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("asset watermark unavailable".into())
                            })
                    })
                })
                .await?;
            cursor = None;
            phase = "groups".into();
            if watermark == consumed {
                return Ok(());
            }
        }
        if phase == "groups" {
            self.dispatch_groups_in(tx, consumed, watermark, cursor)
                .await
        } else {
            let tenant = self.tenant.to_string();
            let scopes:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT DISTINCT s.scope::text FROM mdm_management.scope_sources s WHERE s.tenant_id=$1::uuid AND s.kind='device' AND ($4::uuid IS NULL OR s.scope>$4::uuid) AND EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=s.tenant_id AND c.revision>$2 AND c.revision<=$3 AND c.kind IN('device','registration','source','credential') AND c.identity->>'device'=s.target) ORDER BY s.scope::text LIMIT 33")
                    .bind(tenant).bind(consumed).bind(watermark).bind(cursor).fetch_all(c).await
            })).await?;
            for scope in scopes.iter().take(32) {
                self.enqueue_job_in(
                    tx,
                    Uuid::new_v4(),
                    &JobInput::Scope {
                        scope: stored(Uuid::parse_str(scope))?,
                    },
                )
                .await?;
            }
            if scopes.len() > 32 {
                self.dispatch_cursor_in(
                    tx,
                    consumed,
                    watermark,
                    Some(scopes[31].clone()),
                    "devices",
                )
                .await
            } else {
                self.dispatch_cursor_in(tx, watermark, watermark, None, "groups")
                    .await
            }
        }
    }
    async fn dispatch_groups_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query(r#"
                  SELECT g.id::text,g.revision,g.kind,
                    EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=g.tenant_id AND c.revision>$2 AND c.revision<=$3 AND c.kind IN('device','registration','source','credential')) AS authority
                  FROM mdm_group.groups g WHERE g.tenant_id=$1::uuid AND NOT g.deleted AND ($4::uuid IS NULL OR g.id>$4::uuid)
                  AND NOT EXISTS(SELECT 1 FROM mdm_management.automation_jobs j WHERE j.tenant_id=g.tenant_id AND j.kind='group' AND j.target=g.id::text AND NOT j.completed AND j.input->>'automatic'='true' AND (j.input->>'watermark')::bigint >= $3)
                  AND EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=g.tenant_id AND c.revision>$2 AND c.revision<=$3 AND (
                    (g.kind='dynamic' AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_management.group_fields f WHERE f.tenant_id=g.tenant_id AND f.group_id=g.id AND f.field=ANY(c.fields))))
                    OR (g.kind='static' AND c.kind IN('device','registration','source','credential') AND coalesce((SELECT m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=g.tenant_id AND m.group_id=g.id AND m.object_id=c.identity->>'device' AND r.phase='published' ORDER BY m.revision DESC LIMIT 1),false))
                  )) ORDER BY g.id LIMIT 33
                "#).bind(tenant).bind(consumed).bind(watermark).bind(cursor).fetch_all(c).await
            })).await?;
        for row in rows.iter().take(32) {
            let id = stored(Uuid::parse_str(row.try_get("id")?))?;
            let patch = if row.try_get::<&str, _>("kind")? == "static" {
                Some(rss_mdm_group_postgres::MemberPatch {
                    add: vec![],
                    remove: vec![],
                })
            } else {
                None
            };
            let revision = row.try_get::<i64, _>("revision")? as u64;
            self.start_group_job_in(
                tx,
                GroupStart {
                    id,
                    task: Uuid::new_v4(),
                    expected: revision,
                    patch,
                    publish: true,
                    automatic: true,
                    at: input(Timepoint::try_from(
                        self.clock
                            .unix_seconds()
                            .map_err(|_| Error::Unavailable(Failure::Clock))?,
                    ))?,
                },
            )
            .await?;
        }
        if rows.len() > 32 {
            self.dispatch_cursor_in(
                tx,
                consumed,
                watermark,
                Some(rows[31].try_get("id")?),
                "groups",
            )
            .await
        } else {
            self.dispatch_cursor_in(tx, consumed, watermark, None, "devices")
                .await
        }
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
            sqlx::query("UPDATE mdm_management.asset_dispatch SET consumed=$2,watermark=$3,group_cursor=$4::uuid,phase=$5 WHERE tenant_id=$1::uuid")
                .bind(tenant).bind(consumed).bind(watermark).bind(cursor).bind(phase).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
