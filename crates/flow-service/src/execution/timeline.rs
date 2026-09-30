//! Read-only associations from persisted execution identities, never current success inference.
use sqlx::PgConnection;
use uuid::Uuid;
pub async fn devices_in(
    c: &mut PgConnection,
    tenant: &str,
    operation: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT device FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2 UNION SELECT device FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 UNION SELECT device FROM mdm_planning.remote_operation_targets WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY device LIMIT 10001")
        .bind(tenant).bind(operation).fetch_all(c).await
}

/// Immutable request-to-operation and scheduled-run-to-parent associations.
pub async fn related_operations_in(
    c: &mut PgConnection,
    tenant: &str,
    actor: &str,
    id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT operation FROM mdm_commands.requests WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3 UNION SELECT remote_operation FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$3 AND remote_operation IS NOT NULL LIMIT 2")
        .bind(tenant).bind(actor).bind(id).fetch_all(c).await
}
