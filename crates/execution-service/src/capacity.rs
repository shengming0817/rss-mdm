//! Concrete owners are summed by App under Registration's device lifecycle fence.
use rss_transactional_messaging_postgres::PgTransaction;
pub trait DeviceCapacity: Send + Sync {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>>;
}
pub async fn active_count_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$3")
        .bind(tenant.to_string()).bind(device).bind(now).fetch_one(c).await
}
pub async fn owned_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[uuid::Uuid],
) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(tenant.to_string())
    .bind(ids)
    .fetch_all(c)
    .await
}
