//! Collection execution borrows process resources and binds each initiating runtime.
use super::{agent_facts, participants::*};
use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub struct Materials {
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<dyn TargetAdmission>,
    pub native: Arc<dyn NativeDelivery>,
    pub capacity: Arc<dyn DeviceCapacity>,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<dyn TargetAdmission>,
    pub(crate) native: Arc<dyn NativeDelivery>,
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
    ) -> Result<Self, Error> {
        let reconcile_messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            crate::transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable(Failure::PlanningStorage))?;
        Ok(Self {
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                rss_mdm_install_support::StorageProfile::Mdm,
                runtime.clone(),
                tenant,
            ),
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            agent_store: materials.agent_store.clone(),
            source: materials.source.clone(),
            native: materials.native.clone(),
            capacity: materials.capacity.clone(),
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> crate::transaction::Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
}
pub struct CollectionService {
    pub(crate) transactions: Transactions,
}
impl CollectionService {
    pub fn new(transactions: Transactions) -> Self {
        Self { transactions }
    }
}
