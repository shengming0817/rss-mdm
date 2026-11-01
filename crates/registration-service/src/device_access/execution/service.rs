//! Owner resources bind to the initiating runtime without retaining another business service.
use super::*;
use crate::device_access::participants::{AccessRecovery, PlatformFacts};
use crate::participants::{capacity::DeviceCapacity, scope::Sources};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
pub struct Materials {
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<dyn Sources>,
    pub capacity: Arc<dyn DeviceCapacity>,
    pub recovery: Option<Arc<dyn AccessRecovery>>,
    pub platform: Arc<dyn PlatformFacts>,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<dyn Sources>,
    pub(crate) capacity: Arc<dyn DeviceCapacity>,
    pub(crate) recovery: Option<Arc<dyn AccessRecovery>>,
    pub(crate) platform: Arc<dyn PlatformFacts>,
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
        runtime
            .local_tx(tenant, transaction::deadline(), |tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            let valid: bool = sqlx::query_scalar(include_str!("admission.sql"))
                                .fetch_one(c)
                                .await?;
                            if !valid {
                                return Err(sqlx::Error::Protocol("task owner admission".into()));
                            }
                            Ok(())
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                |_| Ok(()),
                |_| Err(Error::Unavailable),
                |_| Err(Error::Unavailable),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable),
            )?;
        let reconcile_messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            agent_store: materials.agent_store.clone(),
            source: materials.source.clone(),
            capacity: materials.capacity.clone(),
            recovery: materials.recovery.clone(),
            platform: materials.platform.clone(),
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
}
pub struct Service {
    pub(crate) transactions: Transactions,
}
impl Service {
    pub fn new(transactions: Transactions) -> Self {
        Self { transactions }
    }
}
