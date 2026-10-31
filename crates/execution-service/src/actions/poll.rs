//! Offers and cancellation pages have independent progress coordinates.
use crate::{Result, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub async fn offer_candidates(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    now: i64,
) -> Result<Vec<(i64, Uuid)>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.agent_admission(tenant_id,registration) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration).execute(&mut *c).await?;
        let cursor=sqlx::query("SELECT offer_after_at,offer_after_id FROM mdm_commands.agent_admission WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(&tenant).bind(registration).fetch_one(&mut *c).await?;
        let after_at:Option<i64>=cursor.try_get("offer_after_at")?;
        let after_id:Option<Uuid>=cursor.try_get("offer_after_id")?;
        let rows=sqlx::query("SELECT id,available_at FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'execution'='not_started' AND state->>'cancellation'='none' AND gateway_accepted AND available_at<=$3 AND deadline>$3 AND (state->'delivery'->>'kind'='queued' OR (state->'delivery'->>'leaseUntil')::bigint<=$3) AND ($4::bigint IS NULL OR (available_at,id)>($4,$5::uuid)) ORDER BY available_at,id LIMIT 128")
            .bind(&tenant).bind(registration).bind(now).bind(after_at).bind(after_id).fetch_all(&mut *c).await?;
        rows.into_iter().map(|r| Ok((r.try_get("available_at")?,r.try_get("id")?))).collect()
    })).await?)
}

/// Advance only over inspected candidates; an early successful Offer must not skip its page.
pub async fn offered_through(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    after: Option<(i64, Uuid)>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.agent_admission SET offer_after_at=$3,offer_after_id=$4 WHERE tenant_id=$1::uuid AND registration=$2")
          .bind(tenant).bind(registration).bind(after.map(|v|v.0)).bind(after.map(|v|v.1)).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}

pub async fn cancellations(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    after: Option<Uuid>,
) -> Result<Vec<wire::TaskCancellation>> {
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT id,state->'delivery'->>'attempt' AS attempt FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'cancellation'='requested' AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4")
            .bind(tenant).bind(registration).bind(after).bind(wire::MAX_TASK_CANCELLATIONS as i64).fetch_all(c).await
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
