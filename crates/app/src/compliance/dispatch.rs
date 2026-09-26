use super::*;
/// Invalidate dependent rules in the group mutation/publication transaction.
pub(crate) async fn group_changed(tx: &mut PgTransaction<'_>, group: Uuid) -> Result<()> {
    let tenant = tx.tenant_id();
    let t = tenant.to_string();
    let affected=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_compliance.rules r SET desired=NULL WHERE r.tenant_id=$1::uuid AND r.enabled AND EXISTS(SELECT 1 FROM mdm_compliance.groups g WHERE (g.tenant_id,g.rule_id)=(r.tenant_id,r.id) AND g.group_id=$2::uuid)")
            .bind(t).bind(group.to_string()).execute(c).await.map(|r|r.rows_affected())
    })).await?;
    if affected > 0 {
        // One durable wake in the changing transaction, not a polling wake on each bridge tick.
        rss_reconcile_postgres::messaging::wake_in(
            tx,
            &crate::planning::automation::asset_target(tenant),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    }
    Ok(())
}

impl Compliance {
    pub(crate) async fn dispatch(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        crate::transaction::lock(tx).await?;
        let t = self.tenant();
        // Rule/group writes are durable invalidations even when the asset watermark is unchanged.
        let missing:Option<String>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT id::text FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND enabled AND desired IS NULL ORDER BY id LIMIT 1").bind(t.to_string()).fetch_optional(c).await})).await?;
        if let Some(id) = missing {
            let rule = self.rule(tx, stored(Uuid::parse_str(&id))?).await?;
            self.enqueue(tx, &rule).await?;
            return Ok(());
        }
        let state=tx.with_connection(move|c|Box::pin(async move{
   sqlx::query("INSERT INTO mdm_compliance.dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(t.to_string()).execute(&mut *c).await?;
   sqlx::query("SELECT consumed,watermark,cursor::text FROM mdm_compliance.dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(t.to_string()).fetch_one(c).await
  })).await?;
        let consumed: i64 = state.try_get("consumed")?;
        let mut watermark: i64 = state.try_get("watermark")?;
        let cursor: Option<String> = state.try_get("cursor")?;
        if consumed == watermark {
            watermark=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) p").bind(t.to_string()).bind(consumed).fetch_one(c).await})).await?;
        }
        if consumed == watermark {
            return Ok(());
        }
        let after = cursor.map(|s| stored(Uuid::parse_str(&s))).transpose()?;
        let rows = tx
            .with_connection(move |c| Box::pin(async move { pg::rules(c, t, after, 33).await }))
            .await?;
        for r in rows.iter().take(32).filter(|r| r.enabled) {
            self.refresh_rule(tx, r).await?;
        }
        let next = if rows.len() > 32 {
            Some(rows[31].id.to_string())
        } else {
            None
        };
        let consumed = if next.is_some() { consumed } else { watermark };
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_compliance.dispatch SET consumed=$2,watermark=$3,cursor=$4::uuid WHERE tenant_id=$1::uuid").bind(t.to_string()).bind(consumed).bind(watermark).bind(next).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
}

impl Compliance {
    async fn refresh_rule(&self, tx: &mut PgTransaction<'_>, r: &pg::Rule) -> Result<()> {
        let needs = if let Some(task) = r.desired {
            let (job, _, _, _, _) = crate::automation::jobs::read_in(tx, task).await?;
            match job {
                crate::automation::JobInput::Compliance { input } => {
                    !self.fresh(tx, r, &input).await?
                }
                _ => return Err(Error::Unavailable(Failure::ComplianceStorage).into()),
            }
        } else {
            true
        };
        if needs {
            self.enqueue(tx, r).await?;
        }

        Ok(())
    }
}
