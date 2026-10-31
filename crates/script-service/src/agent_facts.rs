//! Facts required by task business owners; protocol persistence belongs to Agent.
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, crate::Error>> + Send + 'a>>;
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
    pub fn script(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::TaskExecuteV1)
    }
    pub fn software(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.is_software())
    }
    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::MdmEnrollmentV1)
    }
    pub fn native_collection(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryNativeV1)
    }
    pub fn task(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceUnmanageV1)
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceAccessV1)
            || self.script()
            || self.software()
            || self.enrollment()
            || self.native_collection()
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::CredentialsWindowsV1)
    }
}
pub trait Store: Send + Sync {
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, Binding>>;
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
        registration: Uuid,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>>;
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, Option<Binding>> {
        Box::pin(async move {
            Ok(self
                .bindings(c, tenant, vec![registration])
                .await?
                .remove(&registration))
        })
    }
}
pub async fn agent_binding_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Store>,
    registration: Uuid,
) -> crate::transaction::Result<Option<Binding>> {
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
) -> crate::transaction::Result<Option<Binding>> {
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
) -> crate::transaction::Result<Vec<RegisteredAgent>> {
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
) -> crate::transaction::Result<Vec<RegisteredAgent>> {
    let registrations = rss_mdm_registration_service::device::read::active_channel_in(
        c,
        tenant.to_string(),
        devices,
        rss_mdm_inventory::Channel::Agent,
        rss_mdm_registration_service::Purpose::Primary,
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
