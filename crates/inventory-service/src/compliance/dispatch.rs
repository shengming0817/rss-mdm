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
    pub async fn dispatch_invalidated(
        &self,
        tx: &mut PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<bool> {
        let t = self.tenant();
        let id = tx
            .with_connection(move |c| Box::pin(async move { pg::next_invalidated(c, t).await }))
            .await?;
        if let Some(id) = id {
            let rule = self.rule(tx, id).await?;
            self.enqueue(tx, &rule, candidate).await?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Exactly one rule per transaction; Compliance owns its durable cursor.
    pub async fn dispatch_rules(
        &self,
        tx: &mut PgTransaction<'_>,
        cursor: Option<String>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<Option<String>> {
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
            self.refresh_rule(tx, rule, candidate).await?;
        }
        Ok((rows.len() > 1).then(|| rows[0].id.to_string()))
    }
    async fn refresh_rule(
        &self,
        tx: &mut PgTransaction<'_>,
        r: &Rule,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        let needs = if let Some(task) = r.desired {
            let task = self.read_task_in(tx, task).await?;
            !self.fresh(tx, r, &task.input).await?
        } else {
            true
        };
        if needs {
            self.enqueue(tx, r, candidate).await?;
        }
        Ok(())
    }
}

impl Compliance {
    pub(super) async fn dispatch_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        if self.dispatch_invalidated(tx, candidate).await? {
            return Ok(true);
        }
        let t = self.tenant();
        let cut = candidate.to_json();
        let Some(page) = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::lock_dispatch(c, t, cut).await })
            })
            .await?
        else {
            return Ok(false);
        };
        let cut = stored(rss_mdm_inventory::AssetCut::from_json(page.to_cut.clone()))?;
        let next = self.dispatch_rules(tx, page.cursor.clone(), &cut).await?;
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::save_dispatch(c, t, &page, next.as_deref()).await })
        })
        .await?;
        Ok(true)
    }
}

impl Compliance {
    pub(super) async fn inputs_pending_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::inputs_pending(c, tenant).await })
            })
            .await?)
    }
    pub(super) async fn advance_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        self.dispatch_inputs_in(tx, candidate).await?;
        Ok(())
    }
}
