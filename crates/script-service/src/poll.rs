//! Offers and cancellation pages have independent progress coordinates.
use crate::{Result, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub async fn offer_candidates(
    tx: &mut PgTransaction<'_>,
    device: String,
    now: i64,
    after: Option<(i64, Uuid)>,
) -> Result<Vec<(i64, Uuid)>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        let after_at = after.map(|v|v.0); let after_id = after.map(|v|v.1);
        let rows=sqlx::query("SELECT id,available_at FROM mdm_script.runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution'='not_started' AND state->>'cancellation'='none' AND gateway_accepted AND available_at<=$3 AND deadline>$3 AND (state->'delivery'->>'kind'='queued' OR (state->'delivery'->>'leaseUntil')::bigint<=$3) AND ($4::bigint IS NULL OR (available_at,id)>($4,$5::uuid)) ORDER BY available_at,id LIMIT 128")
            .bind(&tenant).bind(&device).bind(now).bind(after_at).bind(after_id).fetch_all(&mut *c).await?;
        rows.into_iter().map(|r| Ok((r.try_get("available_at")?,r.try_get("id")?))).collect()
    })).await?)
}

pub async fn cancellations(
    tx: &mut PgTransaction<'_>,
    device: String,
    after: Option<Uuid>,
) -> Result<Vec<wire::TaskCancellation>> {
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT id,state->'delivery'->>'attempt' AS attempt FROM mdm_script.runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'cancellation'='requested' AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4")
            .bind(tenant).bind(&device).bind(after).bind(wire::MAX_TASK_CANCELLATIONS as i64).fetch_all(c).await
    })).await?;
    rows.into_iter()
        .map(|row| {
            stored(wire::TaskCancellation::new(
                row.try_get("id")?,
                stored(Uuid::parse_str(&row.try_get::<String, _>("attempt")?))?,
            ))
        })
        .collect()
}
