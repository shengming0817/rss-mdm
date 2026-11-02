//! Read-only provenance for current optional Agent events; no MDM Policy execution writes DA.
pub async fn parent_current_on(
    c: &mut sqlx::PgConnection,
    device: &str,
    registration: uuid::Uuid,
    generation: i64,
    id: uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_da.access_runs WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND state->>'execution'='running' AND state->>'startedAt' IS NOT NULL)")
        .bind(id).bind(device).bind(registration).bind(generation).fetch_one(c).await
}
