//! Bounded Policy candidate reads for their owning applications.
use rss_request_context::TenantId;
use sqlx::{PgConnection, postgres::PgRow};
use uuid::Uuid;
/// Native interest for an exact current device assignment.
pub async fn native_interests_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    devices: &[rss_mdm_agent_wire::DeviceId],
    kinds: &[&str],
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).candidates_native_interests_on_1)
        .bind(tenant.to_string())
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(kinds)
        .fetch_all(c)
        .await
        .and_then(|ids: Vec<Uuid>| {
            ids.into_iter()
                .map(|id| {
                    rss_mdm_agent_wire::DeviceId::try_from(id)
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })
                .collect()
        })
}
/// Bounded configuration candidates and the Scope-owned channel projection.
pub async fn configuration_candidates_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    devices: &[rss_mdm_agent_wire::DeviceId],
    after: Option<&(Uuid, rss_mdm_agent_wire::DeviceId)>,
) -> Result<Vec<PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).candidates_configuration_candidates_on_1)
        .bind(tenant.to_string())
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(after.map(|v| v.0))
        .bind(after.map(|v| v.1.into_uuid()))
        .fetch_all(c)
        .await
}
/// One bounded action-kind candidate page, including a lookahead row.
pub async fn candidates_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    after: Uuid,
    kind: &str,
) -> Result<Vec<PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).candidates_candidates_on_1)
        .bind(tenant.to_string())
        .bind(after)
        .bind(kind)
        .fetch_all(c)
        .await
}
