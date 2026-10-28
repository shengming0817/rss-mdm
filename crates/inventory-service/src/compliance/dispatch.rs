use super::*;
/// Persist invalidation in the Group mutation transaction; the owner discovers it durably.
pub async fn group_changed(tx: &mut PgTransaction<'_>, group: Uuid) -> Result<()> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { pg::invalidate_group(c, tenant, group).await })
    })
    .await?;
    crate::wake::task(tx, "compliance").await?;
    Ok(())
}
impl Compliance {
    pub async fn dispatch_invalidated(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        crate::transaction::lock(tx).await?;
        let t = self.tenant();
        let id = tx
            .with_connection(move |c| Box::pin(async move { pg::next_invalidated(c, t).await }))
            .await?;
        if let Some(id) = id {
            let rule = self.rule(tx, id).await?;
            self.enqueue(tx, &rule).await?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Exactly one rule per transaction; Compliance owns its durable cursor.
    pub async fn dispatch_rules(
        &self,
        tx: &mut PgTransaction<'_>,
        cursor: Option<String>,
    ) -> Result<Option<String>> {
        crate::transaction::lock(tx).await?;
        let t = self.tenant();
        let after = cursor.map(|s| stored(Uuid::parse_str(&s))).transpose()?;
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    pg::rules::<crate::assets::InventoryCondition>(c, t, after, 2).await
                })
            })
            .await?;
        if let Some(rule) = rows.first()
            && rule.enabled
        {
            self.refresh_rule(tx, rule).await?;
        }
        Ok((rows.len() > 1).then(|| rows[0].id.to_string()))
    }
    async fn refresh_rule(&self, tx: &mut PgTransaction<'_>, r: &Rule) -> Result<()> {
        let needs = if let Some(task) = r.desired {
            let task = self.read_task_in(tx, task).await?;
            !self.fresh(tx, r, &task.input).await?
        } else {
            true
        };
        if needs {
            self.enqueue(tx, r).await?;
        }
        Ok(())
    }
}

impl Compliance {
    pub(super) async fn dispatch_inputs_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        crate::transaction::lock(tx).await?;
        if self.dispatch_invalidated(tx).await? {
            return Ok(true);
        }
        let t = self.tenant();
        let (consumed, mut watermark, mut cursor) = tx
            .with_connection(move |c| Box::pin(async move { pg::tasks::lock_dispatch(c, t).await }))
            .await?;
        if consumed == watermark {
            watermark=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) page").bind(t.to_string()).bind(consumed).fetch_one(c).await})).await?;
            cursor = None;
            if watermark == consumed {
                return Ok(false);
            }
        }
        let next = self.dispatch_rules(tx, cursor).await?;
        let consumed = if next.is_none() { watermark } else { consumed };
        tx.with_connection(move |c| {
            Box::pin(async move {
                pg::tasks::save_dispatch(c, t, consumed, watermark, next.as_deref()).await
            })
        })
        .await?;
        Ok(true)
    }
}
