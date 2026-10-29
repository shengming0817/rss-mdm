//! Policy reference facts consumed under the Scope initiating transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;
/// Whether any current Policy refers to the Scope, including rollout stages.
pub async fn used_in(tx: &mut PgTransaction<'_>, scope: Uuid) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
  sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ((definition->>'scope')::uuid=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE (stage->>'scope')::uuid=$2)))").bind(tenant).bind(scope).fetch_one(c).await
 })).await
}

/// A stable bounded page of Policies referring to a Scope or rollout stage.
pub async fn dependents_in(
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    after: Option<String>,
) -> Result<Vec<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (definition->>'scope'=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE stage->>'scope'=$2)) AND id>coalesce($3::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 65").bind(tenant).bind(scope.to_string()).bind(after).fetch_all(c).await})).await
}
