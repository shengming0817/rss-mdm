//! Device relation revisions feed Group-owned recalculation in the claimed transaction.
use super::*;
impl Groups {
    pub(super) async fn advance_relations_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.check_task_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let (after, cursor, pending) = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.group_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query_as::<_, (i64, Option<Uuid>, Option<i64>)>("SELECT relation_revision,relation_cursor,relation_pending_revision FROM mdm_assets.group_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
        })).await?;
        let revision = match pending {
            Some(revision) => revision,
            None => {
                let objects = self.objects.clone();
                let tenant = self.tenant;
                tx.with_connection(move |c| {
                    Box::pin(async move { objects.change_head(c, tenant).await })
                })
                .await?
            }
        };
        if revision == after {
            return Ok(());
        }
        if revision < after {
            return Err(Error::Unavailable(Failure::AssetsStorage).into());
        }
        let tenant = self.tenant.to_string();
        let groups=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted AND asset_context='associated_device' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 33").bind(tenant).bind(cursor).fetch_all(c).await})).await?;
        let objects = self.objects.clone();
        let owner_tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(objects.capture(c, owner_tenant, None).await?.watermark) })
            })
            .await?;
        for group in groups.iter().take(32) {
            self.dispatch_group_in(
                tx,
                checked_input(rss_mdm_group::GroupId::parse(&group.to_string()))?,
                watermark,
            )
            .await?;
        }
        let more = groups.len() > 32;
        let next = more.then(|| groups[31]);
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_assets.group_dispatch SET relation_revision=CASE WHEN $3 THEN relation_revision ELSE $2 END,relation_cursor=$4,relation_pending_revision=CASE WHEN $3 THEN $2 END WHERE tenant_id=$1::uuid").bind(tenant).bind(revision).bind(more).bind(next).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
}
