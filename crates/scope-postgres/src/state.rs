//! Scope state has one SQL kernel; writers enter through its lock-taking admission.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

/// Current Scope admission is evaluated by the Scope-owned SQL authority.
pub async fn admission_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::query_scalar("SELECT mdm_scope.scope_admission($2,NULL) WHERE nullif(current_setting('rss.tenant_id',true),'')::uuid=$1::uuid")
        .bind(tenant.to_string()).bind(scope).fetch_one(c).await
}
/// The same owner state kernel used after locked execution admission.
pub async fn state_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::query_scalar("SELECT mdm_scope.scope_state($2,NULL) WHERE nullif(current_setting('rss.tenant_id',true),'')::uuid=$1::uuid")
        .bind(tenant.to_string()).bind(scope).fetch_one(c).await
}
