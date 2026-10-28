//! The device owner’s committed relation revision feeds existing Group/Scope/Policy jobs.
use super::*;
impl Planning {
    pub(super) async fn forward_relation_changes(&self) -> std::result::Result<u64, Error> {
        let tenant = self.tenant.to_string();
        let checkpoint=self.runtime.local_tx(self.tenant,deadline(),|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
                sqlx::query_as::<_,(i64,Option<Uuid>,Option<i64>)>("SELECT relation_revision,relation_cursor,relation_pending_revision FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::PlanningStorage)))?;
        let (after, cursor, pending) = checkpoint;
        let revision = match pending {
            Some(revision) => revision,
            None => i64::try_from(
                self.objects
                    .relation_revision(self.tenant)
                    .await
                    .map_err(|_| Error::Unavailable(Failure::PlanningStorage))?,
            )
            .map_err(|_| Error::Unavailable(Failure::PlanningStorage))?,
        };
        if revision == after {
            return Ok(0);
        }
        if revision < after {
            return Err(Error::Unavailable(Failure::PlanningStorage));
        }
        self.runtime.local_tx_with_context(self.tenant,deadline(),(self,revision),|(service,revision),tx|Box::pin(async move {
            service.audit_store.bind_in(tx).await.map_err(PgError::from)?;

            let tenant=tx.tenant_id().to_string();
            let expected=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT relation_revision=$2 AND relation_cursor IS NOT DISTINCT FROM $3 AND relation_pending_revision IS NOT DISTINCT FROM $4 FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).bind(after).bind(cursor).bind(pending).fetch_one(c).await})).await?;
            if !expected {return Ok(0);}
            let tenant=tx.tenant_id().to_string();
            let groups=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted AND asset_context='associated_device' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 33").bind(tenant).bind(cursor).fetch_all(c).await})).await?;
            for group in groups.iter().take(32) {
                let current=service.groups.lock_reference_target_in(tx,rss_mdm_group::GroupId::parse(&group.to_string()).map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?).await?.map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?;
                service.start_group_job_in(tx,GroupStart{id:*group,task:Uuid::new_v4(),expected:current.revision.get() as u64,patch:None,publish:true,automatic:true,at:rss_contract::Timepoint::try_from(service.clock.unix_seconds().map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?).map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?}).await.map_err(|_|PgError::from(sqlx::Error::Protocol("relation input unavailable".into())))?;
            }
            let more=groups.len()>32;let next=more.then(||groups[31]);let tenant=tx.tenant_id().to_string();let revision=*revision;
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.asset_dispatch SET relation_revision=CASE WHEN $3 THEN relation_revision ELSE $2 END,relation_cursor=$4,relation_pending_revision=CASE WHEN $3 THEN $2 END WHERE tenant_id=$1::uuid").bind(tenant).bind(revision).bind(more).bind(next).execute(c).await?;Ok(())})).await?;
            Ok(groups.len().min(32) as u64)
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::Unavailable(Failure::PlanningStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::PlanningStorage)))
    }
}
