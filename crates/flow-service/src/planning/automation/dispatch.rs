use super::*;
use sqlx::Row;

impl Planning {
    pub async fn asset_work_pending(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid),0)")
                .bind(tenant).fetch_one(c).await
        })).await?)
    }
    pub async fn dispatch_assets_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query("SELECT consumed,watermark,cursor,phase FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE")
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
            phase = "devices".into();
            if watermark == consumed {
                return Ok(());
            }
        }
        match phase.as_str() {
            "devices" => {
                self.dispatch_devices_in(tx, consumed, watermark, cursor)
                    .await
            }
            "scopes" => {
                self.dispatch_scopes_in(tx, consumed, watermark, cursor)
                    .await
            }
            _ => Err(Error::Unavailable(Failure::PlanningStorage).into()),
        }
    }
    async fn dispatch_devices_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let devices = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, String>(
                        r#"WITH changed AS (
                    SELECT DISTINCT coalesce(c.identity->>'device',r.device) COLLATE "C" AS device
                    FROM mdm.asset_changes c LEFT JOIN mdm_access.registrations r
                      ON r.tenant_id=c.tenant_id AND r.id::text=c.identity->>'registration'
                    WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND c.revision<=$3
                      AND (c.kind IN('device','registration','source','credential')
                        OR 'channel.agent.installation'=ANY(c.fields))
                ) SELECT device FROM changed WHERE device IS NOT NULL
                    AND ($4::text IS NULL OR device>$4::text COLLATE "C")
                    ORDER BY device COLLATE "C" LIMIT 33"#,
                    )
                    .bind(tenant)
                    .bind(consumed)
                    .bind(watermark)
                    .bind(cursor)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        let source = std::sync::Arc::new(crate::planning::execution_source::ExecutionSource::new(
            self.objects.clone(),
        ));
        for device in devices.iter().take(32) {
            // Wake effects and the page cursor commit together. A retry reads
            // the durable cursor rather than repeating an acknowledged page.
            rss_mdm_execution_service::wake::wake_native_in(
                &self.reconcile_messaging,
                source.clone(),
                tx,
                device,
            )
            .await?;
        }
        if devices.len() > 32 {
            self.dispatch_cursor_in(
                tx,
                consumed,
                watermark,
                Some(devices[31].clone()),
                "devices",
            )
            .await
        } else {
            self.dispatch_cursor_in(tx, consumed, watermark, None, "scopes")
                .await
        }
    }
    async fn dispatch_scopes_in(
        &self,
        tx: &mut PgTransaction<'_>,
        consumed: i64,
        watermark: i64,
        cursor: Option<String>,
    ) -> Result<()> {
        let cursor = cursor
            .as_deref()
            .map(|s| stored(Uuid::parse_str(s)))
            .transpose()?;
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
            self.dispatch_cursor_in(tx, consumed, watermark, Some(scopes[31].clone()), "scopes")
                .await
        } else {
            self.dispatch_cursor_in(tx, watermark, watermark, None, "devices")
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
            sqlx::query("UPDATE mdm_planning.asset_dispatch SET consumed=$2,watermark=$3,cursor=$4::text,phase=$5 WHERE tenant_id=$1::uuid")
                .bind(tenant).bind(consumed).bind(watermark).bind(cursor).bind(phase).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
