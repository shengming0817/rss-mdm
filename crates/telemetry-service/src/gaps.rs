//! Registration-scoped device diagnostics with a finite replay window.
use crate::{Error, Service};
use rss_mdm_agent_wire::runtime::{
    TELEMETRY_GAP_MAX_BYTES, TELEMETRY_GAP_WINDOW_MICROS, TelemetryGapReceipt, TelemetryGapReport,
};
use rss_mdm_registration_service::device::{DevicePrincipal, Purpose, store};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const FUTURE_MICROS: i64 = 300 * 1_000_000;
const REGISTRATION_REPORTS: i64 = 4096;
const TENANT_REPORTS: i64 = 100_000;

async fn authenticate_on(
    service: &Service,
    c: &mut PgConnection,
    principal: &DevicePrincipal,
) -> Result<(), Error> {
    if principal.tenant() != service.tenant
        || principal.channel() != rss_mdm_inventory::Channel::Agent
        || principal.purpose() != Purpose::Primary
    {
        return Err(Error::Denied);
    }
    store::revalidate_management(c, principal)
        .await
        .map_err(|_| Error::Denied)?;
    Ok(())
}

async fn receive_on(
    service: &Service,
    c: &mut PgConnection,
    principal: &DevicePrincipal,
    input: &TelemetryGapReport,
    wire_bytes: usize,
) -> Result<TelemetryGapReceipt, Error> {
    input.validate().map_err(|_| Error::Invalid)?;
    authenticate_on(service, c, principal).await?;
    if input.registration_id != principal.registration()
        || i64::try_from(input.generation).ok() != Some(principal.generation())
    {
        return Err(Error::Denied);
    }
    let bytes = serde_json::to_vec(input)?;
    let accounted = wire_bytes.max(bytes.len());
    if accounted > TELEMETRY_GAP_MAX_BYTES.min(service.request_bytes()) {
        return Err(Error::Capacity);
    }
    // Serialize capacity admission across replicas; registration fencing precedes this lock.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2817))")
        .bind(service.tenant.to_string())
        .execute(&mut *c)
        .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *c)
            .await?;
    let expires = input
        .created_at
        .checked_add(TELEMETRY_GAP_WINDOW_MICROS)
        .ok_or(Error::Invalid)?;
    // Check before replay so pruning cannot resurrect an expired report identity.
    if expires <= now || input.created_at > now.saturating_add(FUTURE_MICROS) {
        return Err(Error::Invalid);
    }
    let digest = Sha256::digest(&bytes).to_vec();
    if let Some(row) = sqlx::query("SELECT registration,generation,input_digest,received_at FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid AND id=$2")
        .bind(service.tenant.to_string()).bind(input.report_id).fetch_optional(&mut *c).await? {
        if row.try_get::<Uuid,_>("registration")? != principal.registration()
            || row.try_get::<i64,_>("generation")? != principal.generation()
            || row.try_get::<Vec<u8>,_>("input_digest")? != digest {
            return Err(Error::Conflict);
        }
        return Ok(TelemetryGapReceipt { report_id: input.report_id, received_at: row.try_get("received_at")?, replayed: true });
    }
    // Expired rows still occupy capacity until bounded maintenance removes them.
    let row = sqlx::query("SELECT count(*) AS total,count(*) FILTER(WHERE registration=$2) AS registered FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid")
        .bind(service.tenant.to_string()).bind(principal.registration()).fetch_one(&mut *c).await?;
    if row.try_get::<i64, _>("total")? >= TENANT_REPORTS
        || row.try_get::<i64, _>("registered")? >= REGISTRATION_REPORTS
    {
        return Err(Error::Capacity);
    }
    crate::admission::admit_rate_on(service, c, now, accounted).await?;
    sqlx::query("INSERT INTO mdm_telemetry.gap_reports(tenant_id,id,device,registration,generation,input_digest,report,received_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(service.tenant.to_string()).bind(input.report_id).bind(principal.device()).bind(principal.registration()).bind(principal.generation()).bind(digest).bind(serde_json::to_value(input)?).bind(now).bind(expires).execute(c).await?;
    Ok(TelemetryGapReceipt {
        report_id: input.report_id,
        received_at: now,
        replayed: false,
    })
}

impl Service {
    /// Durably admit device-reported loss evidence, independent of policy or field coverage.
    pub async fn receive_gap(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        input: &TelemetryGapReport,
        wire_bytes: usize,
    ) -> Result<TelemetryGapReceipt, Error> {
        let rejection = Arc::new(Mutex::new(None));
        let rejected = rejection.clone();
        let service = self.clone();
        let principal = principal.clone();
        let input = input.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            receive_on(&service, c, &principal, &input, wire_bytes)
                                .await
                                .map_err(|error| {
                                    *rejected.lock().expect("gap rejection") = Some(error);
                                    sqlx::Error::Protocol("telemetry gap rejected".into())
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
                |_| {
                    Err(rejection
                        .lock()
                        .expect("gap rejection")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }

    /// Recover a receipt under the current credential for the same registration incarnation.
    pub async fn gap_status(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        id: Uuid,
    ) -> Result<TelemetryGapReceipt, Error> {
        let service = self.clone();
        let principal = principal.clone();
        self.runtime.local_tx(self.tenant,crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                Ok(async {
                    authenticate_on(&service,c,&principal).await?;
                    let received:Option<i64>=sqlx::query_scalar("SELECT received_at FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND registration=$4 AND generation=$5 AND expires_at>floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
                        .bind(service.tenant.to_string()).bind(id).bind(principal.device()).bind(principal.registration()).bind(principal.generation()).fetch_optional(c).await?;
                    Ok(TelemetryGapReceipt {report_id:id,received_at:received.ok_or(Error::NotFound)?,replayed:true})
                }.await)
            })).await
        })).await.fold(|v|v,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
    }

    /// Prune at most 256 expired receipts independently of timeseries backend maintenance.
    /// DELETE owns row locking; a locking SELECT would require an UPDATE grant.
    pub(crate) async fn prune_gaps(self: &Arc<Self>) -> Result<(), Error> {
        let tenant = self.tenant;
        self.runtime.local_tx(tenant,crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("WITH expired AS (SELECT tenant_id,id FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid AND expires_at<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint ORDER BY expires_at,id LIMIT 256) DELETE FROM mdm_telemetry.gap_reports g USING expired e WHERE g.tenant_id=e.tenant_id AND g.id=e.id")
                    .bind(tenant.to_string()).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
    }
}
