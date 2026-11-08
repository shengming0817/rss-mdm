//! Enrollment interprets shared Agent facts.
use crate::participants::agent::{Binding, Store};
pub async fn agent_binding_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    device: String,
) -> crate::enrollment::tasks::transaction::Result<Option<Binding>> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(agent_binding_on(profile, c, tenant, store, device).await) })
    })
    .await?
}
pub async fn agent_binding_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: std::sync::Arc<dyn Store>,
    device: String,
) -> crate::enrollment::tasks::transaction::Result<Option<Binding>> {
    if store.storage_profile() != profile {
        return Err(crate::Error::Forbidden.into());
    }
    Ok(store.binding(c, tenant.to_string(), device).await?)
}

pub struct RegisteredAgent {
    pub device: String,
    pub binding: Binding,
}
pub async fn agent_targets_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    devices: Vec<String>,
) -> crate::enrollment::tasks::transaction::Result<Vec<RegisteredAgent>> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(agent_targets_on(profile, c, tenant, store, devices).await) })
    })
    .await?
}
pub async fn agent_targets_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: std::sync::Arc<dyn Store>,
    devices: Vec<String>,
) -> crate::enrollment::tasks::transaction::Result<Vec<RegisteredAgent>> {
    let devices = crate::device::read::active_channel_in(
        profile,
        c,
        tenant.to_string(),
        devices,
        rss_mdm_inventory::Channel::Agent,
        crate::Purpose::Primary,
    )
    .await?;
    let ids = devices.clone();
    let bindings = store.bindings(c, tenant.to_string(), ids).await?;
    Ok(devices
        .into_iter()
        .filter_map(|device| {
            bindings
                .get(&device)
                .cloned()
                .map(|binding| RegisteredAgent { device, binding })
        })
        .collect())
}

pub async fn profile_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &super::Transactions,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    device: String,
) -> super::Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let Some(binding) = agent_binding_in(profile, tx, service.agent_store.clone(), device).await?
    else {
        return Ok(None);
    };
    let platform = match binding.platform.as_str() {
        "windows" => rss_mdm_policy::Platform::Windows,
        "macos" => rss_mdm_policy::Platform::Macos,
        _ => return Ok(None),
    };
    let architecture = match binding.architecture.as_str() {
        "x86_64" => rss_mdm_policy::Architecture::X86_64,
        "aarch64" => rss_mdm_policy::Architecture::Aarch64,
        _ => return Ok(None),
    };
    Ok(Some((platform, architecture)))
}
