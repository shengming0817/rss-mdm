//! Facts required by task business owners; protocol persistence belongs to Agent.
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, super::Error>> + Send + 'a>>;
#[derive(Clone)]
pub struct Binding {
    pub platform: String,
    pub architecture: String,
    pub execution_context: rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    pub capabilities: Vec<rss_mdm_agent_wire::runtime::Capability>,
}
impl Binding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1)
    }

    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::MdmEnrollmentV1)
    }
}
pub trait Store: Send + Sync {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile;
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
) -> Result<Option<Binding>, super::Error> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(store.binding(c, tenant, registration).await) })
    })
    .await?
}
