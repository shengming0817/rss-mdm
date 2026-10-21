//! Bounded host observations, distinct from sampling or maintenance success.
use crate::{Error, Service};
use rss_request_context::Deadline;
use rss_timeseries::*;
use std::{num::NonZeroU64, sync::Arc};
pub struct Diagnostics {
    pub running: bool,
    pub pending: u64,
    pub unknown: u64,
    pub blocked: u64,
    pub maintenance: u64,
}
struct ProbeAuthority(DefinitionId);
impl Authority for ProbeAuthority {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::DefinitionRead(id)
                if id.scope == self.0.scope
                    && id.key == self.0.key
                    && id.version == self.0.version =>
            {
                Ok(())
            }
            _ => Err(rss_timeseries::Error::Unauthorized),
        }
    }
}
impl Service {
    /// Read counts up to 4097 and probe the actual configured backend within one cutoff.
    pub async fn diagnostics(
        self: &Arc<Self>,
        cutoff: std::time::Instant,
    ) -> Result<Diagnostics, Error> {
        let remaining = cutoff
            .checked_duration_since(std::time::Instant::now())
            .ok_or(Error::Storage)?;
        let deadline = Deadline::from_timeout(&crate::backend::SystemClock, remaining)
            .map_err(|_| Error::Storage)?;
        let probe = DefinitionId {
            scope: Scope::new(self.tenant, Id::new("mdm.telemetry")?),
            key: Id::new("health.probe")?,
            version: NonZeroU64::new(1).expect("positive version"),
        };
        self.backend
            .definition(
                &Authorized::<DefinitionId>::verify(&ProbeAuthority(probe.clone()), probe)?,
                deadline,
            )
            .await?;
        let tenant = self.tenant;
        let budget = rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            cutoff
                .checked_duration_since(std::time::Instant::now())
                .ok_or(Error::Storage)?,
        );
        let counts=self.runtime.local_tx(tenant,budget,move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                let mut counts=[0u64;4];
                for (index,state) in ["pending","unknown","blocked"].into_iter().enumerate() {
                    let value:i64=sqlx::query_scalar("SELECT count(*) FROM(SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND delivery=$2 LIMIT 4097) q")
                        .bind(tenant.to_string()).bind(state).fetch_one(&mut *c).await?;
                    counts[index]=value as u64;
                }
                let value:i64=sqlx::query_scalar("SELECT count(*) FROM(SELECT 1 FROM mdm_telemetry.maintenance WHERE tenant_id=$1::uuid AND (result IS NULL OR result->>'state'<>'complete') LIMIT 4097) q")
                    .bind(tenant.to_string()).fetch_one(&mut *c).await?;
                let due:i64=sqlx::query_scalar("SELECT count(*) FROM(SELECT 1 FROM mdm_telemetry.retention_targets WHERE tenant_id=$1::uuid AND phase<2 AND due_at<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint LIMIT 4097) q").bind(tenant.to_string()).fetch_one(c).await?;
                counts[3]=(value+due).min(4097) as u64;Ok(counts)
            })).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))?;
        Ok(Diagnostics {
            running: self.running.load(std::sync::atomic::Ordering::Acquire),
            pending: counts[0],
            unknown: counts[1],
            blocked: counts[2],
            maintenance: counts[3],
        })
    }
}
