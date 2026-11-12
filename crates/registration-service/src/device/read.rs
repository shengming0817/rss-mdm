//! Read projections owned by this capability; the caller owns the transaction.
pub async fn find(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<Option<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_find_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_optional(c)
        .await
        .and_then(|id| id.map(crate::database::device_id).transpose())
}

pub async fn active_sources(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<rss_mdm_agent_wire::DeviceId>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).device_read_active_sources_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .fetch_all(c)
        .await
}

pub async fn exists(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_exists_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_one(c)
        .await
}

pub async fn live_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<rss_mdm_agent_wire::DeviceId>,
    cut: &rss_mdm_inventory::AssetCut,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_live_at_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(cut.to_json())
        .fetch_all(c)
        .await
        .and_then(crate::database::device_ids)
}

#[allow(
    clippy::too_many_arguments,
    reason = "directory projection retains product, tenant, fact time and signed cursor coordinates"
)]
pub async fn page_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    cut: &rss_mdm_inventory::AssetCut,
    after: Option<rss_mdm_agent_wire::DeviceId>,
    all: bool,
    allowed: Vec<rss_mdm_agent_wire::DeviceId>,
    limit: i64,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_page_at_1)
        .bind(tenant)
        .bind(cut.to_json())
        .bind(after.map(|id| id.into_uuid()))
        .bind(all)
        .bind(allowed.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(limit)
        .fetch_all(c)
        .await
        .and_then(crate::database::device_ids)
}

pub async fn sources_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<rss_mdm_agent_wire::DeviceId>,
    cut: &rss_mdm_inventory::AssetCut,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).device_read_sources_at_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(cut.to_json())
        .fetch_all(c)
        .await
}

pub async fn registered(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_registered_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_one(c)
        .await
}

/// Active registry coordinates only; protocol capabilities remain with their channel.
pub async fn active_channel_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<rss_mdm_agent_wire::DeviceId>,
    channel: rss_mdm_inventory::Channel,
    purpose: super::Purpose,
) -> Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_active_channel_in_1)
        .bind(tenant)
        .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
        .bind(channel.as_str())
        .bind(purpose.as_str())
        .fetch_all(c)
        .await
        .and_then(crate::database::device_ids)
}

/// Read-only worker hints; a mutating caller must recheck under the channel lock.
pub async fn active_sources_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[rss_mdm_agent_wire::DeviceId],
    source: rss_mdm_inventory::ReportSource,
) -> Result<std::collections::BTreeSet<rss_mdm_agent_wire::DeviceId>, crate::Error> {
    let devices: Vec<rss_mdm_agent_wire::DeviceId> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_active_sources_in_1)
            .bind(tenant)
            .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
            .bind(source.as_str())
            .fetch_all(c)
            .await
            .and_then(crate::database::device_ids)
            .map_err(crate::database::db)?;
    Ok(devices.into_iter().collect())
}
pub async fn lock_active_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, crate::Error> {
    super::store::lock_channel(profile, c, tenant, device, source.channel()).await?;
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_enabled_source_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_one(c)
        .await
        .map_err(crate::database::db)
}

/// Check the complete current registration/source authority without renewing any proof.
pub async fn enabled_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_enabled_source_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_one(c)
        .await
}
pub async fn inactive_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: rss_mdm_agent_wire::DeviceId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_inactive_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_one(c)
        .await
}

/// Immutable registration association for historical facts; revocation does not erase it.
pub async fn timeline_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_timeline_device_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_optional(c)
        .await
        .and_then(|id| id.map(crate::database::device_id).transpose())
}

/// Persisted enrollment/grant association remains usable after resume or cancellation.
pub async fn timeline_enrollment_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
) -> Result<Option<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_timeline_enrollment_in_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
        .and_then(|id| id.map(crate::database::device_id).transpose())
}
