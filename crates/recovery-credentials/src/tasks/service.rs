//! Owner resources bind to the initiating runtime without retaining another business service.
use super::*;
use rss_mdm_registration_service::participants::{capacity::DeviceCapacity, scope::Sources};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
pub struct Materials {
    /// Fixed process mode; disabled hosts may only settle existing executions.
    pub accepting: bool,
    pub product: Option<Arc<dyn super::product::Product>>,
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<dyn Sources>,
    pub capacity: Arc<dyn DeviceCapacity>,
    pub recovery_credentials: Arc<crate::Protection>,
}
pub struct Transactions {
    pub(crate) accepting: bool,
    pub(crate) product: Option<Arc<dyn super::product::Product>>,
    profile: rss_mdm_install_support::StorageProfile,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<dyn Sources>,
    pub(crate) capacity: Arc<dyn DeviceCapacity>,
    pub(crate) recovery_credentials: Arc<crate::Protection>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
}
impl Transactions {
    pub fn accepts_new_work(&self) -> bool {
        self.accepting
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub async fn bind(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<Materials>,
    ) -> std::result::Result<Self, Error> {
        if materials.agent_store.storage_profile() != rss_mdm_install_support::StorageProfile::Mdm
            || materials.source.storage_profile() != materials.agent_store.storage_profile()
            || (profile == rss_mdm_install_support::StorageProfile::Da)
                != materials.product.is_some()
            || materials
                .product
                .as_ref()
                .is_some_and(|p| p.storage_profile() != profile)
        {
            return Err(Error::Forbidden);
        }
        runtime
            .local_tx(tenant, transaction::deadline(), |tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            crate::verify_agent_authority(profile, c).await?;
                            let valid: bool = sqlx::query_scalar(
                                crate::storage_profile::sql(profile).task_admission,
                            )
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
            accepting: materials.accepting,
            product: materials.product.clone(),
            profile,
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                materials.source.storage_profile(),
                runtime.clone(),
                tenant,
            ),
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            agent_store: materials.agent_store.clone(),
            source: materials.source.clone(),
            capacity: materials.capacity.clone(),
            recovery_credentials: materials.recovery_credentials.clone(),
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
    /// Freeze this process to settlement of previously created executions.
    pub fn settlement_only(mut self) -> Self {
        self.transactions.accepting = false;
        self
    }
    pub fn accepts_new_work(&self) -> bool {
        self.transactions.accepting
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.transactions.profile()
    }
    pub fn new(transactions: Transactions) -> Self {
        Self { transactions }
    }
}
