//! Offers and cancellation pages have independent progress coordinates.
use crate::commands::{Result, corrupt};
use rss_mdm_agent_wire as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub(super) async fn offer_candidates(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    now: i64,
) -> Result<Vec<String>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT id::text FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state->>'execution'='not_started' AND state->>'cancellation'='none' AND gateway_accepted AND available_at<=$3 AND deadline>$3 AND (state->'delivery'->>'kind'='queued' OR (state->'delivery'->>'leaseUntil')::bigint<=$3) ORDER BY available_at,id LIMIT 128")
            .bind(tenant).bind(registration.to_string()).bind(now).fetch_all(c).await
    })).await?)
}
pub(super) async fn cancellations(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Vec<wire::TaskCancellation>> {
    let tenant = tx.tenant_id().to_string();
    let registration = registration.to_string();
    let rows = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.action_polls(tenant_id,registration) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING").bind(&tenant).bind(&registration).execute(&mut *c).await?;
        let rows = sqlx::query("SELECT id::text,state->'delivery'->>'attempt' AS attempt FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state->>'cancellation'='requested' AND id>coalesce((SELECT cancellation_after FROM mdm_commands.action_polls WHERE tenant_id=$1::uuid AND registration=$2::uuid),'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT $3")
            .bind(&tenant).bind(&registration).bind(wire::MAX_TASK_CANCELLATIONS as i64).fetch_all(&mut *c).await?;
        let next = rows.last().map(|row| row.try_get::<String,_>("id")).transpose()?;
        sqlx::query("UPDATE mdm_commands.action_polls SET cancellation_after=$3::uuid WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration).bind(next).execute(c).await?;
        Ok(rows)
    })).await?;
    rows.into_iter()
        .map(|row| {
            Ok(wire::TaskCancellation {
                task_id: corrupt(Uuid::parse_str(&row.try_get::<String, _>("id")?))?,
                attempt_id: corrupt(Uuid::parse_str(&row.try_get::<String, _>("attempt")?))?,
            })
        })
        .collect()
}
