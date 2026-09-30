use super::*;
impl Planning {
    /// Read the actual product ingress checkpoint; storage failure is not a paused ingress.
    pub async fn ingress_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<IngressHealth, HealthFailure> {
        self.runtime.local_tx(self.tenant, health_deadline(cutoff), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                use sqlx::Row;
                let row = sqlx::query("SELECT consumed,watermark,failure FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid")
                    .bind(tenant).fetch_optional(c).await?;
                row.map_or(Ok(IngressHealth { consumed: 0, watermark: 0, suspended: false }), |r| {
                    Ok(IngressHealth { consumed: r.try_get::<i64,_>("consumed")? as u64,
                        watermark: r.try_get::<i64,_>("watermark")? as u64,
                        suspended: r.try_get::<Option<String>,_>("failure")?.is_some() })
                })
            })).await
        })).await.fold(Ok, |_| Err(HealthFailure::Storage), |_| Err(HealthFailure::Storage),
            |_| Err(HealthFailure::SettlementUnknown), |_| Err(HealthFailure::SettlementUnknown),
            |_| Err(HealthFailure::Deadline))
    }
    /// Counts describe retained product job states, not managed task health or device effects.
    pub async fn queue_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<[u64; 6], HealthFailure> {
        self.runtime.local_tx(self.tenant, health_deadline(cutoff), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                let row: (i64,i64,i64,i64,i64,i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND NOT forwarded LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND forwarded LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND completed LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded LIMIT 1001) q)")
                    .bind(tenant).fetch_one(c).await?;
                Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64,row.5 as u64])
            })).await
        })).await.fold(Ok, |_| Err(HealthFailure::Storage), |_| Err(HealthFailure::Storage),
            |_| Err(HealthFailure::SettlementUnknown), |_| Err(HealthFailure::SettlementUnknown),
            |_| Err(HealthFailure::Deadline))
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

/// Current durable input checkpoint; an absent row means no ingress has been dispatched yet.
#[derive(Clone, Copy, Debug)]
pub struct IngressHealth {
    pub consumed: u64,
    pub watermark: u64,
    pub suspended: bool,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum HealthFailure {
    #[error("storage unavailable")]
    Storage,
    #[error("deadline")]
    Deadline,
    #[error("settlement unknown")]
    SettlementUnknown,
}
#[derive(Clone, Copy, Debug)]
pub enum BridgeOutcome {
    Succeeded,
    StorageUnavailable,
    Deadline,
    SettlementUnknown,
    Rejected,
}
#[derive(Clone, Copy, Debug)]
pub struct BridgeObservation {
    pub outcome: BridgeOutcome,
    pub observed_at: Option<i64>,
}
#[allow(clippy::disallowed_methods, reason = "monotonic read budget boundary")]
fn health_deadline(
    cutoff: std::time::Instant,
) -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        cutoff.saturating_duration_since(std::time::Instant::now()),
    )
}
