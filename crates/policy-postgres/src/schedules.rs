//! Persisted Policy schedules and explicit triggers, interpreted by the application.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use uuid::Uuid;
/// Bounded unexpired triggers for an immutable publication.
pub async fn triggers_in(
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    now: i64,
) -> Result<Vec<(Uuid, i64)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT id,created_at FROM mdm_policy.triggers WHERE tenant_id=$1::uuid AND version=$2 AND deadline>$3 ORDER BY created_at DESC,id DESC LIMIT 64").bind(tenant).bind(version).bind(now).fetch_all(c).await})).await
}
/// A bounded page of enabled retirement publications.
pub async fn retirement_in(
    tx: &mut PgTransaction<'_>,
    after: Option<Uuid>,
) -> Result<Vec<(Uuid, Uuid, Value)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT p.id,v.id,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='unmanage_device' AND ($2::uuid IS NULL OR p.id>$2) ORDER BY p.id LIMIT 64").bind(tenant).bind(after).fetch_all(c).await})).await
}

/// Whether a bounded calendar discovery page is due.
pub async fn scan_due_in(tx: &mut PgTransaction<'_>, now: i64) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT coalesce((SELECT next_scan_at FROM mdm_policy.schedule_scan WHERE tenant_id=$1::uuid),0)<=$2").bind(tenant).bind(now).fetch_one(c).await
    })).await
}
/// Resume a calendar discovery cycle under the initiating RSS claim.
pub async fn scan_cursor_in(tx: &mut PgTransaction<'_>) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_policy.schedule_scan(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
        sqlx::query_scalar("SELECT after_policy FROM mdm_policy.schedule_scan WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
    })).await
}
/// Advance only with the occurrence work created by this page.
pub async fn complete_scan_in(
    tx: &mut PgTransaction<'_>,
    after: Option<Uuid>,
    next: i64,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_policy.schedule_scan SET after_policy=$2,next_scan_at=$3 WHERE tenant_id=$1::uuid").bind(tenant).bind(after).bind(next).execute(c).await?;
        Ok(())
    })).await
}
