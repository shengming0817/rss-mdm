use super::*;
impl Planning {
    pub async fn ingress_ready(&self) -> bool {
        self.runtime.local_tx(self.tenant,deadline(),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid AND failure IS NOT NULL)").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(|ready|ready, |_|false, |_|false, |_|false, |_|false, |_|false)
    }
    pub async fn clear_ingress_failure_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_planning.asset_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn fail_ingress_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let generation: Option<i64> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("INSERT INTO mdm_planning.asset_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=asset_dispatch.failure_generation+1 WHERE asset_dispatch.failure IS NULL RETURNING failure_generation")
                .bind(tenant).fetch_optional(c).await
        })).await?;
        if let Some(generation) = generation {
            let audit = RequestAudit::new(self.tenant.to_string(), "automation_failed");
            audit.identify_service("service:asset-automation");
            audit.target("asset_ingress");
            let fact = rss_mdm_audit_integration::Fact::business(
                &audit,
                &format!("asset-ingress:{generation}:failed"),
                &generation.to_be_bytes(),
                200,
                "failed",
                None,
            )
            .map_err(Error::from)?;
            let result = self
                .audit_store
                .append_in(tx, &fact, false)
                .await
                .map_err(Error::from);
            audit.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
        }
        Ok(())
    }
}
