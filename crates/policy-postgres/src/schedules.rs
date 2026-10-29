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
