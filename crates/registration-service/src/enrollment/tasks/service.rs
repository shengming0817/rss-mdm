//! Enrollment materials bind to the initiating runtime, including Policy participants.
use crate::enrollment::tasks::Error;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;

use crate::participants::{agent as agent_facts, capacity::DeviceCapacity};
pub struct Materials {
    pub inventory: Arc<dyn super::Inventory>,
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<dyn crate::participants::scope::Sources>,
    pub capacity: Arc<dyn DeviceCapacity>,
    pub instance: String,
}
pub struct Transactions {
    profile: rss_mdm_install_support::StorageProfile,
    pub(crate) inventory: Arc<dyn super::Inventory>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<dyn crate::participants::scope::Sources>,
    pub(crate) capacity: Arc<dyn DeviceCapacity>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
}
impl Transactions {
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
        if materials.inventory.storage_profile() != profile
            || materials.agent_store.storage_profile() != profile
            || materials.source.storage_profile() != profile
        {
            return Err(Error::Forbidden);
        }
        runtime
            .local_tx(
                tenant,
                crate::enrollment::tasks::transaction::deadline(),
                |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(
                                async move { crate::verify_common_authority(profile, c).await },
                            )
                        })
                        .await
                    })
                },
            )
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
            crate::enrollment::tasks::transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            profile,
            inventory: materials.inventory.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                profile,
                runtime.clone(),
                tenant,
            ),
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
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> crate::enrollment::tasks::Result<()> {
        self.transactions.validate_in(tx)
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.transactions.profile()
    }
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
