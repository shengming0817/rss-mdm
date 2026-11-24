//! Registration-scoped device diagnostics with a finite replay window.
use crate::{Error, Service};
use rss_mdm_agent_wire::runtime::{
    TELEMETRY_GAP_MAX_BYTES, TELEMETRY_GAP_WINDOW_MICROS, TelemetryGapReceipt, TelemetryGapReport,
};
use rss_mdm_registration_service::device::{DevicePrincipal, Purpose, store};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;

const FUTURE_MICROS: i64 = 300 * 1_000_000;
const REGISTRATION_REPORTS: i64 = 4096;
const TENANT_REPORTS: i64 = 100_000;

async fn authenticate_on(c: &mut PgConnection, principal: &DevicePrincipal) -> Result<(), Error> {
    if principal.channel() != Some(rss_mdm_inventory::Channel::Agent)
        || principal.purpose() != Purpose::Primary
    {
        return Err(Error::Denied);
    }
    store::revalidate_management(rss_mdm_install_support::StorageProfile::Mdm, c, principal)
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
    authenticate_on(c, principal).await?;
    if input.device_id != *principal.device() {
        return Err(Error::Denied);
    }
    let bytes = serde_json::to_vec(input)?;
    let accounted = wire_bytes.max(bytes.len());
    if accounted > TELEMETRY_GAP_MAX_BYTES.min(service.request_bytes()) {
        return Err(Error::Capacity);
    }
    // Serialize capacity admission across replicas; registration fencing precedes this lock.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2817))")
        .bind(principal.binding().tenant().to_string())
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
    if let Some(row) = sqlx::query("SELECT device, input_digest, received_at FROM mdm_telemetry.gap_reports WHERE tenant_id = CAST($1 AS uuid) AND id = $2")
        .bind(principal.binding().tenant().to_string()).bind(input.report_id).fetch_optional(&mut *c).await? {
        if row.try_get::<uuid::Uuid, _>("device").and_then(|id| rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e))))? != *principal.device()
            || row.try_get::<Vec<u8>,_>("input_digest")? != digest {
            return Err(Error::Conflict);
        }
        return Ok(TelemetryGapReceipt { report_id: input.report_id, received_at: row.try_get("received_at")?, replayed: true });
    }
    // Expired rows still occupy capacity until bounded maintenance removes them.
    let row = sqlx::query("SELECT count(*) AS total, count(*) FILTER (WHERE device = $2) AS registered FROM mdm_telemetry.gap_reports WHERE tenant_id = CAST($1 AS uuid)")
        .bind(principal.binding().tenant().to_string()).bind(principal.device().into_uuid()).fetch_one(&mut *c).await?;
    if row.try_get::<i64, _>("total")? >= TENANT_REPORTS
        || row.try_get::<i64, _>("registered")? >= REGISTRATION_REPORTS
    {
        return Err(Error::Capacity);
    }
    crate::admission::admit_rate_on(principal.binding(), service, c, now, accounted).await?;
    sqlx::query("INSERT INTO mdm_telemetry.gap_reports (tenant_id, id, device, input_digest, report, received_at, expires_at) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7)")
        .bind(principal.binding().tenant().to_string()).bind(input.report_id).bind(principal.device().into_uuid()).bind(digest).bind(serde_json::to_value(input)?).bind(now).bind(expires).execute(c).await?;
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
        request: crate::IntakeRequest,
    ) -> Result<TelemetryGapReceipt, Error> {
        request.audit.operation(
            input.report_id,
            "agent_telemetry_gap_upload",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let service = self.clone();
        let device = principal.clone();
        let input = input.clone();
        // Keep the PostgreSQL transaction frame inside the intake owner.
        Box::pin(self.intake(principal.binding(), request, move |c| {
            Box::pin(async move { receive_on(&service, c, &device, &input, wire_bytes).await })
        }))
        .await
    }

    /// Recover a receipt under the current credential for the same registration incarnation.
    pub async fn gap_status(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        id: Uuid,
    ) -> Result<TelemetryGapReceipt, Error> {
        let principal = principal.clone();
        self.runtime.local_tx(principal.binding(),crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                Ok(async {
                    authenticate_on(c,&principal).await?;
                    let received:Option<i64>=sqlx::query_scalar("SELECT received_at FROM mdm_telemetry.gap_reports WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $3 AND device = $4 AND expires_at > CAST(floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000000) AS bigint)")
                        .bind(principal.binding().tenant().to_string()).bind(id).bind(principal.device().into_uuid()).bind(principal.device().into_uuid()).fetch_optional(c).await?;
                    Ok(TelemetryGapReceipt {report_id:id,received_at:received.ok_or(Error::NotFound)?,replayed:true})
                }.await)
            })).await
        })).await.fold(|v|v,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
    }

    /// Prune expired gap receipts and the tenant\'s bounded stream checkpoints.
    /// DELETE owns row locking; a locking SELECT would require an UPDATE grant.
    pub(crate) async fn prune_expired(
        self: &Arc<Self>,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<(), Error> {
        let tenant = binding.tenant();
        self.runtime.local_tx(binding,crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("DELETE FROM mdm_telemetry.stream_checks WHERE tenant_id=$1::uuid AND expires_at<=clock_timestamp()").bind(tenant.to_string()).execute(&mut *c).await?;
                sqlx::query("WITH expired AS (SELECT tenant_id,id FROM mdm_telemetry.gap_reports WHERE tenant_id=$1::uuid AND expires_at<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint ORDER BY expires_at,id LIMIT 256) DELETE FROM mdm_telemetry.gap_reports g USING expired e WHERE g.tenant_id=e.tenant_id AND g.id=e.id")
                    .bind(tenant.to_string()).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
    }
}
