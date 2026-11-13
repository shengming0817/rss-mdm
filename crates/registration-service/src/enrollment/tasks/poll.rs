//! Offers and cancellation pages have independent progress coordinates.
use crate::enrollment::tasks::{Result, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub async fn offer_candidates(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
    now: i64,
    after: Option<(i64, Uuid)>,
) -> Result<Vec<(i64, Uuid)>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                let after_at = after.map(|v| v.0);
                let after_id = after.map(|v| v.1);
                let rows = sqlx::query(
                    crate::storage_profile::sql(profile).enrollment_tasks_poll_offer_candidates_1,
                )
                .bind(&tenant)
                .bind(device.into_uuid())
                .bind(now)
                .bind(after_at)
                .bind(after_id)
                .fetch_all(&mut *c)
                .await?;
                rows.into_iter()
                    .map(|r| Ok((r.try_get("available_at")?, r.try_get("id")?)))
                    .collect()
            })
        })
        .await?)
}

pub async fn cancellations(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
    after: Option<Uuid>,
) -> Result<Vec<wire::TaskCancellation>> {
    let tenant = tx.tenant_id().to_string();
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    crate::storage_profile::sql(profile).enrollment_tasks_poll_cancellations_1,
                )
                .bind(tenant)
                .bind(device.into_uuid())
                .bind(after)
                .bind(wire::MAX_TASK_CANCELLATIONS as i64)
                .fetch_all(c)
                .await
            })
        })
        .await?;
    rows.into_iter()
        .map(|row| {
            stored(wire::TaskCancellation::new(
                row.try_get("id")?,
                stored(Uuid::parse_str(&row.try_get::<String, _>("attempt")?))?,
            ))
        })
        .collect()
}
