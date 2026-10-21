//! Bounded policy scheduling. RSS owns cutoffs, dependency barriers and pruning progress.
use crate::{Error, Service};
use rss_request_context::{Deadline, TenantId};
use rss_timeseries::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{num::NonZeroU32, sync::Arc};

pub(crate) async fn register(
    c: &mut PgConnection,
    tenant: TenantId,
    batch: &Batch,
    now: i64,
) -> Result<(), Error> {
    let mut seen = std::collections::BTreeSet::new();
    for sample in batch.samples() {
        let input = sample.input();
        let series = &input.series;
        let key = Sha256::digest(serde_json::to_vec(&(&input.stream, series.digest()?))?).to_vec();
        if !seen.insert(key.clone()) {
            continue;
        }
        sqlx::query("INSERT INTO mdm_telemetry.retention_targets(tenant_id,id,device,field,version,resource,stream,dimensions,due_at,next_check,phase) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$9,0) ON CONFLICT DO NOTHING")
            .bind(tenant.to_string()).bind(key).bind(series.subject().as_str()).bind(series.definition().spec().key.as_str())
            .bind(series.definition().spec().version as i64).bind(series.resource().as_str()).bind(serde_json::to_value(&input.stream)?)
            .bind(serde_json::to_value(series.dimensions())?).bind(now.saturating_add(3_600_000_000)).execute(&mut *c).await?;
    }
    Ok(())
}
struct PolicyAuthority<'a>(&'a MaintenanceRequest);
impl Authority for PolicyAuthority<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::Maintain(request) if request.binding()? == self.0.binding()? => Ok(()),
            _ => Err(rss_timeseries::Error::Unauthorized),
        }
    }
}
impl Service {
    pub(crate) async fn retain(self: &Arc<Self>) -> Result<(), Error> {
        let service = self.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            step(&service, c).await.map_err(|_| {
                                sqlx::Error::Protocol("retention step unconfirmed".into())
                            })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn step(service: &Service, c: &mut PgConnection) -> Result<(), Error> {
    let tenant = service.tenant;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *c)
            .await?;
    // Select before locking: intake takes the device fence before touching the target row.
    let candidate:Option<(Vec<u8>,String)>=sqlx::query_as("SELECT id,device FROM mdm_telemetry.retention_targets WHERE tenant_id=$1::uuid AND phase<2 AND next_check<=$2 ORDER BY next_check,id LIMIT 1")
        .bind(tenant.to_string()).bind(now).fetch_optional(&mut *c).await?;
    let Some((id, device)) = candidate else {
        return Ok(());
    };
    rss_mdm_registration_service::device::store::lock_channel(
        c,
        &tenant.to_string(),
        &device,
        rss_mdm_inventory::Channel::Agent,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let row=sqlx::query("SELECT field,version,resource,stream,dimensions,due_at,phase FROM mdm_telemetry.retention_targets WHERE tenant_id=$1::uuid AND id=$2 AND phase<2 AND next_check<=$3 FOR UPDATE")
        .bind(tenant.to_string()).bind(&id).bind(now).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let field: String = row.try_get("field")?;
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND device=$2 AND $3=ANY(fields) AND delivery<>'published')")
        .bind(tenant.to_string()).bind(&device).bind(&field).fetch_one(&mut *c).await?;
    let due: i64 = row.try_get("due_at")?;
    let phase: i16 = row.try_get("phase")?;
    let mut next_due = due;
    let mut next_phase = phase;
    let mut next_check = now.saturating_add(30_000_000);
    let result = if pending {
        json!({"state":"blocked","reason":"accepted_batches_pending"})
    } else {
        let version =
            u64::try_from(row.try_get::<i64, _>("version")?).map_err(|_| Error::Storage)?;
        let key = rss_mdm_inventory::FieldKey::parse(&field).map_err(|_| Error::Storage)?;
        let versions = rss_mdm_inventory_postgres::time_series_versions_in(
            c,
            tenant,
            key,
            version.saturating_sub(1),
            version,
        )
        .await
        .map_err(|_| Error::Storage)?;
        let original = versions.first().ok_or(Error::Storage)?;
        let reference = &original
            .time_series
            .as_ref()
            .ok_or(Error::Storage)?
            .retention;
        let policy = rss_mdm_inventory_postgres::retention_policy_in(
            c,
            tenant,
            &reference.key,
            reference.revision,
        )
        .await
        .map_err(|_| Error::Storage)?
        .ok_or(Error::Storage)?;
        let stream: Stream = serde_json::from_value(row.try_get("stream")?)?;
        let definition = original
            .time_series_definition(stream.scope().clone())
            .map_err(|_| Error::Storage)?;
        let series = Series::new(
            definition,
            Id::new(device)?,
            Id::new(row.try_get::<String, _>("resource")?)?,
            serde_json::from_value(row.try_get("dimensions")?)?,
        )?;
        let selection = Selection::Exact { stream, series };
        let raw = Timestamp::new(
            due.saturating_sub(i64::from(policy.raw_seconds) * 1_000_000)
                .max(0),
        )?;
        let action = if phase == 0 {
            MaintenanceAction::AdvanceCutoff {
                selection,
                before: raw,
            }
        } else {
            MaintenanceAction::Prune {
                selection,
                raw_before: raw,
                summaries_before: Timestamp::new(
                    due.saturating_sub(i64::from(policy.summary_seconds) * 1_000_000)
                        .max(0),
                )?,
            }
        };
        // The persisted due time and phase fix the original logical operation through unknown outcomes.
        let identity = format!(
            "retention:{:x}",
            Sha256::digest(serde_json::to_vec(&(&id, due, phase))?)
        );
        let request = MaintenanceRequest::new(
            Id::new(identity)?,
            action,
            MaintenanceBudget {
                rows: NonZeroU32::new(4096).unwrap(),
                buckets: NonZeroU32::new(64).unwrap(),
            },
        )?;
        let authorized =
            Authorized::<MaintenanceRequest>::verify(&PolicyAuthority(&request), request.clone())?;
        let cutoff = Deadline::from_timeout(
            &crate::backend::SystemClock,
            std::time::Duration::from_secs(6),
        )
        .map_err(|_| Error::Storage)?;
        match service.backend.maintain(&authorized, None, cutoff).await {
            Err(_) | Ok(Outcome::Unknown) => json!({"state":"unknown"}),
            Ok(Outcome::Accepted(progress) | Outcome::Replay(progress)) => match progress {
                MaintenanceProgress::Blocked { reason } => {
                    json!({"state":"blocked","reason":reason})
                }
                MaintenanceProgress::More { processed, .. } => {
                    json!({"state":"more","processed":processed})
                }
                MaintenanceProgress::Complete { processed, .. } => {
                    if phase == 0 {
                        next_phase = 1;
                    } else {
                        next_phase = 0;
                        next_due = now.saturating_add(3_600_000_000);
                        next_check = next_due;
                    }
                    json!({"state":"complete","processed":processed})
                }
            },
        }
    };
    sqlx::query("UPDATE mdm_telemetry.retention_targets SET due_at=$3,next_check=$4,phase=$5,result=$6 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant.to_string()).bind(id).bind(next_due).bind(next_check).bind(next_phase).bind(result).execute(c).await?;
    Ok(())
}
