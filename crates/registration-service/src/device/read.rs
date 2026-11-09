//! Read projections owned by this capability; the caller owns the transaction.
pub async fn find(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_find_1)
        .bind(tenant)
        .bind(device)
        .fetch_optional(c)
        .await
}

pub async fn active_sources(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).device_read_active_sources_1)
        .bind(tenant)
        .bind(devices)
        .fetch_all(c)
        .await
}

pub async fn exists(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_exists_1)
        .bind(tenant)
        .bind(device)
        .fetch_one(c)
        .await
}

pub async fn live_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    cut: &rss_mdm_inventory::AssetCut,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_live_at_1)
        .bind(tenant)
        .bind(devices)
        .bind(cut.to_json())
        .fetch_all(c)
        .await
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
    after: Option<String>,
    all: bool,
    allowed: Vec<String>,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_page_at_1)
        .bind(tenant)
        .bind(cut.to_json())
        .bind(after)
        .bind(all)
        .bind(allowed)
        .bind(limit)
        .fetch_all(c)
        .await
}

pub async fn sources_at(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    cut: &rss_mdm_inventory::AssetCut,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query(crate::storage_profile::sql(profile).device_read_sources_at_1)
        .bind(tenant)
        .bind(devices)
        .bind(cut.to_json())
        .fetch_all(c)
        .await
}

pub async fn registered(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_registered_1)
        .bind(tenant)
        .bind(device)
        .fetch_one(c)
        .await
}

/// Active registry coordinates only; protocol capabilities remain with their channel.
pub async fn active_channel_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    devices: Vec<String>,
    channel: rss_mdm_inventory::Channel,
    purpose: super::Purpose,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_active_channel_in_1)
        .bind(tenant)
        .bind(devices)
        .bind(channel.as_str())
        .bind(purpose.as_str())
        .fetch_all(c)
        .await
}

/// Read-only worker hints; a mutating caller must recheck under the channel lock.
pub async fn active_sources_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
    source: rss_mdm_inventory::ReportSource,
) -> Result<std::collections::BTreeSet<String>, crate::Error> {
    let devices: Vec<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_active_sources_in_1)
            .bind(tenant)
            .bind(devices)
            .bind(source.as_str())
            .fetch_all(c)
            .await
            .map_err(crate::database::db)?;
    Ok(devices.into_iter().collect())
}
pub async fn lock_active_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, crate::Error> {
    super::store::lock_channel(profile, c, tenant, device, source.channel()).await?;
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_enabled_source_in_1)
        .bind(tenant)
        .bind(device)
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
    device: String,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_enabled_source_in_1)
        .bind(tenant)
        .bind(device)
        .bind(source.as_str())
        .fetch_one(c)
        .await
}
pub async fn inactive_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    device: String,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_inactive_in_1)
        .bind(tenant)
        .bind(device)
        .fetch_one(c)
        .await
}

/// Immutable registration association for historical facts; revocation does not erase it.
pub async fn timeline_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_timeline_device_in_1)
        .bind(tenant)
        .bind(device)
        .fetch_optional(c)
        .await
}

/// Persisted enrollment/grant association remains usable after resume or cancellation.
pub async fn timeline_enrollment_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_timeline_enrollment_in_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
}
