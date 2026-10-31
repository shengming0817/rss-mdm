//! Enrollment materials bind to the initiating runtime, including Policy participants.
use crate::enrollment::tasks::{Error, agent_facts};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;

/// Application composition sums the concrete owners under the existing device lock.
pub trait DeviceCapacity: Send + Sync {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<Box<dyn Future<Output = crate::enrollment::tasks::Result<bool>> + Send + 'a>>;
}

pub struct Materials {
    pub inventory: Arc<dyn super::Inventory>,
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<dyn crate::enrollment::tasks::scope::Sources>,
    pub capacity: Arc<dyn DeviceCapacity>,
    pub instance: String,
}
pub struct Transactions {
    pub(crate) inventory: Arc<dyn super::Inventory>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<dyn crate::enrollment::tasks::scope::Sources>,
    pub(crate) capacity: Arc<dyn DeviceCapacity>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
}
impl Transactions {
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<Materials>,
    ) -> std::result::Result<Self, Error> {
        let reconcile_messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            crate::enrollment::tasks::transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            inventory: materials.inventory.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            instance: materials.instance.clone(),
            agent_store: materials.agent_store.clone(),
            source: materials.source.clone(),
            capacity: materials.capacity.clone(),
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> crate::enrollment::tasks::Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
}

pub struct Service {
    pub(crate) transactions: Transactions,
    pub(crate) sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
}
impl Service {
    pub fn new(
        transactions: Transactions,
        sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    ) -> Self {
        Self {
            transactions,
            sessions,
        }
    }
}
