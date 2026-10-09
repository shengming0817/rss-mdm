//! Fixed Audit windows feed the existing Group/Scope/Policy jobs.
use super::*;
impl Planning {
    pub(super) async fn forward_relation_changes(&self) -> std::result::Result<u64, Error> {
        let tenant = self.tenant.to_string();
        let checkpoint=self.runtime.local_tx(self.tenant,deadline(),|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
                sqlx::query_as::<_,(i64,Option<i64>,Option<Uuid>,Option<i64>,Option<i64>)>("SELECT relation_after,relation_through,relation_cursor,relation_page_after,relation_page_through FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::PlanningStorage)))?;
        let (after, through, cursor, page_after, page_through) = checkpoint;
        let window = if page_after.is_some() {
            rss_mdm_inventory_service::objects::ChangeWindow {
                after: page_after.unwrap_or(after) as u64,
                through: page_through.map(|v| v as u64),
                changed: true,
            }
        } else {
            self.objects
                .changes(self.tenant, after as u64, through.map(|v| v as u64))
                .await
                .map_err(|_| Error::Unavailable(Failure::PlanningStorage))?
        };
        if window.after == after as u64 && !window.changed {
            return Ok(0);
        }
        self.runtime.local_tx_with_context(self.tenant,deadline(),(self,window),|(service,window),tx|Box::pin(async move {
            service.audit_store.lock_in(tx).await.map_err(PgError::from)?;
            let owner_tenant=tx.tenant_id();
            tx.with_connection(move|c|Box::pin(async move {rss_mdm_inventory_postgres::lock_watermark_in(c,owner_tenant).await})).await?;
            let tenant=tx.tenant_id().to_string();
            let expected=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT relation_after=$2 AND relation_cursor IS NOT DISTINCT FROM $3 AND relation_through IS NOT DISTINCT FROM $4 AND relation_page_after IS NOT DISTINCT FROM $5 AND relation_page_through IS NOT DISTINCT FROM $6 FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).bind(after).bind(cursor).bind(through).bind(page_after).bind(page_through).fetch_one(c).await})).await?;
            if !expected {return Ok(0);}
            let tenant=tx.tenant_id().to_string();
            let groups=if window.changed {tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted AND asset_context='associated_device' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 33").bind(tenant).bind(cursor).fetch_all(c).await})).await?}else{vec![]};
            for group in groups.iter().take(32) {
                let current=service.groups.lock_reference_target_in(tx,rss_mdm_group_postgres::GroupId::parse(&group.to_string()).map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?).await?.map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?;
                service.start_group_job_in(tx,GroupStart{id:*group,task:Uuid::new_v4(),expected:current.revision.get() as u64,patch:None,publish:true,automatic:true,at:rss_contract::Timepoint::try_from(service.clock.unix_seconds().map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?).map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?}).await.map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?;
            }
            let more=groups.len()>32;let next=more.then(||groups[31]);let tenant=tx.tenant_id().to_string();let next_after=window.after as i64;let next_through=window.through.map(|v|v as i64);
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.asset_dispatch SET relation_after=CASE WHEN $4 THEN relation_after ELSE $2 END,relation_through=CASE WHEN $4 THEN relation_through ELSE $3 END,relation_cursor=$5,relation_page_after=CASE WHEN $4 THEN $2 END,relation_page_through=CASE WHEN $4 THEN $3 END WHERE tenant_id=$1::uuid").bind(tenant).bind(next_after).bind(next_through).bind(more).bind(next).execute(c).await?;Ok(())})).await?;
            Ok(groups.len().min(32) as u64)
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::PlanningStorage)))
    }
}
