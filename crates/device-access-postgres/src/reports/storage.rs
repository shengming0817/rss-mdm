use super::*;
use crate::database::db;
use rss_observation::{Batch, Body, Change as Fact, Coverage, Id, Policy, State};
use sqlx::Row;

pub(super) async fn replay(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    kind: Kind,
    sequence: i64,
    operation: Option<Uuid>,
    document: &serde_json::Value,
) -> Result<Option<Receipt>, Error> {
    let rows=sqlx::query("SELECT sequence, operation, document, receipt FROM rss_da.report_history WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3 AND (sequence = $4 OR (CAST($5 AS uuid) IS NOT NULL AND operation = $5))")
        .bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(kind.name()).bind(sequence).bind(operation).fetch_all(c).await.map_err(db)?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let r = &rows[0];
    if r.try_get::<i64, _>("sequence").map_err(db)? != sequence
        || r.try_get::<Option<Uuid>, _>("operation").map_err(db)? != operation
        || r.try_get::<serde_json::Value, _>("document").map_err(db)? != *document
    {
        return Err(Error::Conflict);
    }
    Ok(Some(
        serde_json::from_value(r.try_get("receipt").map_err(db)?).map_err(|_| Error::Corrupt)?,
    ))
}
/// The current registration lock serializes both streams; Observation owns monotonic snapshot rules.
pub(super) async fn receive(
    c: &mut PgConnection,
    service: &Service,
    p: &DevicePrincipal,
    kind: Kind,
    sequence: i64,
    operation: Option<Uuid>,
    document: &serde_json::Value,
) -> Result<Change<Receipt>, Error> {
    let bytes = serde_json::to_vec(document).map_err(|_| Error::Malformed)?;
    if bytes.len() > service.report_limits.body_bytes as usize {
        return Err(Error::Capacity);
    }
    if let Some(value) = replay(c, p, kind, sequence, operation, document).await? {
        return Ok(Change {
            value,
            replay: true,
        });
    }
    let now = crate::platform_sso::store::now(c).await?;
    let previous:Option<String>=sqlx::query_scalar("SELECT integrity FROM rss_da.report_heads WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3")
        .bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(kind.name()).fetch_optional(&mut *c).await.map_err(db)?;
    let state = previous
        .map(|v| State::decode(&v).map_err(|_| Error::Corrupt))
        .transpose()?
        .unwrap_or_else(State::initial);
    let id = |s: String| Id::new(s).map_err(|_| Error::Malformed);
    let batch = Batch::new(
        id(sequence.to_string())?,
        u64::try_from(sequence).map_err(|_| Error::Malformed)?,
        rss_contract::Timepoint::try_from(0).map_err(|_| Error::Malformed)?,
        Coverage::new(
            id(kind.name().into())?,
            id("1".into())?,
            id("rss.da.diagnostic".into())?,
            id("json".into())?,
        ),
        Body::Snapshot(vec![Fact::upsert(id("report".into())?, bytes.clone())]),
    )
    .map_err(|_| Error::Malformed)?;
    let policy = Policy::new(1, 1, u64::from(service.report_limits.stale_seconds))
        .map_err(|_| Error::Configuration)?;
    let decision = state
        .advance(&batch, now as u64, &policy)
        .map_err(|_| Error::Corrupt)?;
    if !decision.outcome().is_applicable() {
        return Err(Error::Conflict);
    }
    // Tenant-wide bounded intake. Exact retries never spend quota or refresh receipt time.
    let accepted:Option<i64>=sqlx::query_scalar("INSERT INTO rss_da.report_budget(tenant_id,minute,reports,bytes) VALUES($1::uuid,$2,1,$3) ON CONFLICT(tenant_id) DO UPDATE SET minute=excluded.minute,reports=CASE WHEN rss_da.report_budget.minute=excluded.minute THEN rss_da.report_budget.reports+1 ELSE 1 END,bytes=CASE WHEN rss_da.report_budget.minute=excluded.minute THEN rss_da.report_budget.bytes+excluded.bytes ELSE excluded.bytes END WHERE rss_da.report_budget.minute<>excluded.minute OR (rss_da.report_budget.reports<$4 AND rss_da.report_budget.bytes+excluded.bytes<=$5) RETURNING reports")
        .bind(p.tenant().to_string()).bind(now/60).bind(bytes.len() as i64).bind(i64::from(service.report_limits.reports_per_minute)).bind(i64::from(service.report_limits.bytes_per_minute)).fetch_optional(&mut *c).await.map_err(db)?;
    if accepted.is_none() {
        return Err(Error::Capacity);
    }
    let value = Receipt {
        sequence,
        received_at: now,
        evidence: da::EvidenceLevel::Reported,
    };
    let receipt = serde_json::to_value(&value).map_err(|_| Error::Corrupt)?;
    sqlx::query("INSERT INTO rss_da.report_history (tenant_id, device, kind, sequence, operation, received_at, document, receipt) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, $7, $8)")
        .bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(kind.name()).bind(sequence).bind(operation).bind(now).bind(document).bind(&receipt).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO rss_da.report_heads (tenant_id, device, kind, integrity, document, receipt) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, device, kind) DO UPDATE SET integrity = excluded.integrity, document = excluded.document, receipt = excluded.receipt")
        .bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(kind.name()).bind(decision.state().encode().map_err(|_|Error::Corrupt)?).bind(document).bind(receipt).execute(&mut *c).await.map_err(db)?;
    sqlx::query("DELETE FROM rss_da.report_history WHERE ctid IN (SELECT ctid FROM rss_da.report_history WHERE tenant_id=$1::uuid AND received_at<=$2 ORDER BY received_at LIMIT 1000)").bind(p.tenant().to_string()).bind(now-i64::from(service.report_limits.history_seconds)).execute(&mut *c).await.map_err(db)?;
    sqlx::query("DELETE FROM rss_da.report_history WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3 AND (received_at <= $4 OR sequence IN (SELECT sequence FROM rss_da.report_history WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND kind = $3 ORDER BY sequence DESC OFFSET $5))")
        .bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(kind.name()).bind(now-i64::from(service.report_limits.history_seconds)).bind(i64::from(service.report_limits.history_count)).execute(&mut *c).await.map_err(db)?;
    Ok(Change {
        value,
        replay: false,
    })
}
