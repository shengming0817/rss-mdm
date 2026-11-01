//! Scope state has one SQL kernel; writers enter through its lock-taking admission.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

/// Current Scope admission is evaluated by the Scope-owned SQL authority.
pub async fn admission_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).state_admission_on_1)
        .bind(tenant.to_string())
        .bind(scope)
        .fetch_one(c)
        .await
}
/// The same owner state kernel used after locked execution admission.
pub async fn state_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).state_state_on_1)
        .bind(tenant.to_string())
        .bind(scope)
        .fetch_one(c)
        .await
}
