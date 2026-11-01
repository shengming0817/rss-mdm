//! Exact Policy publications consumed by the telemetry application.
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;
/// Read and hold the current enabled publication through the caller's transaction.
pub async fn current_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<Option<(rss_mdm_policy::Definition, Value)>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).telemetry_current_on_1)
        .bind(policy)
        .execute(&mut *c)
        .await?;
    let row: Option<(Value, Value)> =
        sqlx::query_as(crate::storage_profile::sql(profile).telemetry_current_on_2)
            .bind(tenant.to_string())
            .bind(policy)
            .bind(version)
            .fetch_optional(c)
            .await?;
    row.map(|(definition, frozen)| {
        Ok((
            serde_json::from_value(definition)
                .map_err(|_| sqlx::Error::Protocol("invalid Policy definition".into()))?,
            frozen,
        ))
    })
    .transpose()
}
/// Interpret an already issued version independently of the current Policy head.
pub async fn historical_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<Option<Value>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).telemetry_historical_on_1)
        .bind(tenant.to_string())
        .bind(policy)
        .bind(version)
        .fetch_optional(c)
        .await
}
/// Bounded current candidates; the caller performs device-specific admission.
pub async fn candidates_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<Vec<(Uuid, Uuid, Value)>, sqlx::Error> {
    sqlx::query_as(crate::storage_profile::sql(profile).telemetry_candidates_on_1)
        .bind(tenant.to_string())
        .fetch_all(c)
        .await
}
/// Fence delivery to the exact current publication without changing historical receipt validity.
pub async fn is_current_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    version: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).telemetry_is_current_on_1)
        .bind(policy)
        .execute(&mut *c)
        .await?;
    Ok(sqlx::query_scalar::<_, bool>(
        crate::storage_profile::sql(profile).telemetry_is_current_on_2,
    )
    .bind(tenant.to_string())
    .bind(policy)
    .bind(version)
    .fetch_optional(c)
    .await?
        == Some(true))
}
