//! Enrollment interprets shared Agent facts.
use crate::participants::agent::{Binding, Store};
use uuid::Uuid;
pub async fn agent_binding_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    registration: Uuid,
) -> crate::enrollment::tasks::transaction::Result<Option<Binding>> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(agent_binding_on(c, tenant, store, registration).await) })
    })
    .await?
}
pub async fn agent_binding_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: std::sync::Arc<dyn Store>,
    registration: Uuid,
) -> crate::enrollment::tasks::transaction::Result<Option<Binding>> {
    Ok(store.binding(c, tenant.to_string(), registration).await?)
}

pub struct RegisteredAgent {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub binding: Binding,
}
pub async fn agent_targets_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    devices: Vec<String>,
) -> crate::enrollment::tasks::transaction::Result<Vec<RegisteredAgent>> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(agent_targets_on(c, tenant, store, devices).await) })
    })
    .await?
}
pub async fn agent_targets_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: std::sync::Arc<dyn Store>,
    devices: Vec<String>,
) -> crate::enrollment::tasks::transaction::Result<Vec<RegisteredAgent>> {
    let registrations = crate::device::read::active_channel_in(
        c,
        tenant.to_string(),
        devices,
        rss_mdm_inventory::Channel::Agent,
        crate::Purpose::Primary,
    )
    .await?;
    let ids = registrations.iter().map(|(_, id, _)| *id).collect();
    let bindings = store.bindings(c, tenant.to_string(), ids).await?;
    Ok(registrations
        .into_iter()
        .filter_map(|(device, registration, generation)| {
            bindings
                .get(&registration)
                .cloned()
                .map(|binding| RegisteredAgent {
                    device,
                    registration,
                    generation,
                    binding,
                })
        })
        .collect())
}

pub async fn profile_in(
    service: &super::Transactions,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    registration: Uuid,
) -> super::Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    let Some(binding) = agent_binding_in(tx, service.agent_store.clone(), registration).await?
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
