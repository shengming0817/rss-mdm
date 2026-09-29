use super::*;
/// Invalidate and wake atomically with the group mutation, without a second checkpoint.
pub(crate) async fn group_changed(tx: &mut PgTransaction<'_>, group: Uuid) -> Result<()> {
    let tenant = tx.tenant_id();
    let affected = tx
        .with_connection(move |c| {
            Box::pin(async move { pg::invalidate_group(c, tenant, group).await })
        })
        .await?;
    if affected > 0 {
        rss_reconcile_postgres::messaging::wake_in(
            tx,
            &crate::planning::automation::asset_target(tenant),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Automation).await?;
    }
    Ok(())
}
impl Compliance {
    pub(crate) async fn dispatch_invalidated(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
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
    /// Exactly one rule per transaction; the shared dispatcher owns its durable cursor.
    pub(crate) async fn dispatch_rules(
        &self,
        tx: &mut PgTransaction<'_>,
        cursor: Option<String>,
    ) -> Result<Option<String>> {
        crate::transaction::lock(tx).await?;
        let t = self.tenant();
        let after = cursor.map(|s| stored(Uuid::parse_str(&s))).transpose()?;
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::rules::<crate::assets::Criteria>(c, t, after, 2).await })
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
