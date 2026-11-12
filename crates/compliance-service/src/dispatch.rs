use super::*;
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
    pub(crate) async fn dispatch_inputs_in(
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
        let mut page = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::lock_dispatch(c, t, cut).await })
            })
            .await?;
        let cut = stored(rss_mdm_inventory::AssetCut::from_json(page.to_cut.clone()))?;
        let from = page
            .from_cut
            .clone()
            .map(rss_mdm_inventory::AssetCut::from_json)
            .transpose()
            .map_err(|_| Error::Unavailable(Failure::ComplianceStorage))?;
        if page.through.is_none() {
            page.through = self
                .asset_reader
                .changes_page_in(tx, from.as_ref(), &cut, page.event_after, None, 1000)
                .await?
                .last()
                .map(|change| change.revision);
            tx.with_connection_context(&mut (&page,), move |(page,), c| {
                Box::pin(async move { pg::tasks::open_dispatch_page(c, t, page).await })
            })
            .await?;
        }
        if page.through.is_none() {
            return Ok(false);
        }
        let changes = self
            .asset_reader
            .changes_page_in(
                tx,
                from.as_ref(),
                &cut,
                page.event_after,
                page.through,
                1000,
            )
            .await?;
        let authority = changes.iter().any(|c| c.kind.changes_authority());
        let fields = changes
            .iter()
            .flat_map(|c| c.fields.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let global = changes.iter().any(|c| c.identity.device.is_none());
        let devices = changes
            .iter()
            .filter_map(|c| c.identity.device)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let after = page.cursor;
        let rules = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    pg::affected_rules::<rss_mdm_inventory_service::assets::InventoryCondition>(
                        c, t, after, &fields, authority,
                    )
                    .await
                })
            })
            .await?;
        if let Some(rule) = rules.first() {
            let groups = rule.definition.groups();
            if global
                || groups.is_empty()
                || !checked(
                    self.groups
                        .input_candidate_groups_in(tx, &groups, &devices)
                        .await?,
                )?
                .is_empty()
            {
                self.refresh_rule(tx, rule, &cut).await?;
            }
        }
        let next = (rules.len() > 1).then(|| rules[0].id);
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::save_dispatch(c, t, &page, next).await })
        })
        .await?;
        Ok(true)
    }
}

impl Compliance {
    pub(crate) async fn inputs_pending_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant();
        let state = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::input_state(c, tenant).await })
            })
            .await?;
        let from = state
            .from_cut
            .map(rss_mdm_inventory::AssetCut::from_json)
            .transpose()
            .map_err(|_| Error::Unavailable(Failure::ComplianceStorage))?;
        Ok(state.invalidated
            || self
                .asset_reader
                .changes_exist_in(tx, from.as_ref(), None)
                .await?)
    }
    pub(crate) async fn advance_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<()> {
        self.dispatch_inputs_in(tx, candidate).await?;
        Ok(())
    }
}
