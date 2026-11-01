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
) -> Result<Vec<(String, uuid::Uuid, i64)>, sqlx::Error> {
    sqlx::query_as(crate::storage_profile::sql(profile).device_read_active_channel_in_1)
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
    ids: &[uuid::Uuid],
    source: rss_mdm_inventory::ReportSource,
) -> Result<std::collections::BTreeMap<uuid::Uuid, (String, i64)>, crate::Error> {
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, i64)>(
        crate::storage_profile::sql(profile).device_read_active_sources_in_1,
    )
    .bind(tenant)
    .bind(ids)
    .bind(source.as_str())
    .fetch_all(c)
    .await
    .map_err(crate::database::db)?;
    Ok(rows
        .into_iter()
        .map(|(id, device, generation)| (id, (device, generation)))
        .collect())
}
pub async fn lock_active_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Option<(String, i64)>, crate::Error> {
    let Some((device, _)) = active_sources_in(profile, c, tenant, &[id], source)
        .await?
        .remove(&id)
    else {
        return Ok(None);
    };
    super::store::lock_channel(profile, c, tenant, &device, source.channel()).await?;
    sqlx::query_as::<_, (String, i64)>(
        crate::storage_profile::sql(profile).device_read_lock_active_source_in_1,
    )
    .bind(tenant)
    .bind(id)
    .bind(source.as_str())
    .fetch_optional(c)
    .await
    .map_err(crate::database::db)
}

/// Check the complete current registration/source authority without renewing any proof.
pub async fn enabled_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    registration: uuid::Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_enabled_source_in_1)
        .bind(tenant)
        .bind(registration)
        .bind(source.as_str())
        .fetch_one(c)
        .await
}
pub async fn stale_registration_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    registration: uuid::Uuid,
    device: String,
    generation: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_stale_registration_in_1)
        .bind(tenant)
        .bind(registration)
        .bind(device)
        .bind(generation)
        .fetch_one(c)
        .await
}

/// Immutable registration association for historical facts; revocation does not erase it.
pub async fn timeline_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_read_timeline_device_in_1)
        .bind(tenant)
        .bind(id)
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

/// Execution coordinates belong to the root registration, while operations retain their wire registration.
pub async fn management_root_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: String,
    registration: uuid::Uuid,
    generation: i64,
) -> Result<(uuid::Uuid, i64), crate::Error> {
    sqlx::query_as(crate::storage_profile::sql(profile).device_read_management_root_in_1)
        .bind(tenant)
        .bind(registration)
        .bind(generation)
        .fetch_optional(c)
        .await
        .map_err(crate::database::db)?
        .ok_or(crate::Error::Conflict)
}
