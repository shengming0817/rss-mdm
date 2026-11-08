//! Facts required by task business owners; protocol persistence belongs to Agent.
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, crate::deployment::Error>> + Send + 'a>>;
#[derive(Clone)]
pub struct Binding {
    pub execution_context: rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<rss_mdm_agent_wire::runtime::Capability>,
}
impl Binding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1)
    }

    pub fn software(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.is_software())
    }

    pub fn task(&self) -> bool {
        self.software()
    }
}
pub trait Store: Send + Sync {
    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        context: &'a rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Pending<'a, ()>;
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        devices: Vec<String>,
    ) -> Pending<'a, std::collections::BTreeMap<String, Binding>>;
    /// Original task bytes visible to this transaction, independent of current execution eligibility.
    fn payload<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        run: Uuid,
        attempt: Uuid,
    ) -> Pending<'a, rss_mdm_agent_wire::runtime::TaskPayload>;
    fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>>;
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
    ) -> Pending<'a, Option<Binding>> {
        Box::pin(async move {
            Ok(self
                .bindings(c, tenant, vec![device.clone()])
                .await?
                .remove(&device))
        })
    }
}
pub async fn agent_binding_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    device: String,
) -> crate::deployment::transaction::Result<Option<Binding>> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(agent_binding_on(c, tenant, store, device).await) })
    })
    .await?
}
pub async fn agent_binding_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    store: std::sync::Arc<dyn Store>,
    device: String,
) -> crate::deployment::transaction::Result<Option<Binding>> {
    Ok(store.binding(c, tenant.to_string(), device).await?)
}

pub async fn agent_context_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    device: String,
    context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
) -> crate::deployment::transaction::Result<()> {
    let tenant = tx.tenant_id().to_string();
    let context = context.clone();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(store.update_context(c, tenant, device, &context).await) })
    })
    .await??;
    Ok(())
}

pub struct RegisteredAgent {
    pub device: String,
    pub binding: Binding,
}
pub async fn agent_targets_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    devices: Vec<String>,
) -> crate::deployment::transaction::Result<Vec<RegisteredAgent>> {
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
) -> crate::deployment::transaction::Result<Vec<RegisteredAgent>> {
    let devices = rss_mdm_registration_service::device::read::active_channel_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant.to_string(),
        devices,
        rss_mdm_inventory::Channel::Agent,
        rss_mdm_registration_service::Purpose::Primary,
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
