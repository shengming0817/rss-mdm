//! Application composition for inventory queries and compliance, independent of Flow services.
use crate::{Error, Failure};
use std::sync::Arc;
pub(crate) struct Services {
    pub(crate) assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub(crate) compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
}
impl Services {
    pub(crate) async fn new(
        inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: rss_request_context::TenantId,
        key: &[u8],
        clock: Arc<dyn crate::clock::Clock>,
    ) -> Result<Self, Error> {
        let messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            rss_mdm_inventory_service::transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable(Failure::FlowConnection))?;
        let groups = Arc::new(
            rss_mdm_group_postgres::GroupStore::new(
                runtime.clone(),
                tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::FlowConnection))?,
        );
        Ok(Self {
            assets: Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
                inventory,
                audit_store.clone(),
                runtime.clone(),
                tenant,
                Arc::new(crate::clock::InventoryClock(clock.clone())),
                key,
                messaging.clone(),
            )),
            compliance: Arc::new(rss_mdm_inventory_service::compliance::Compliance::new(
                rss_mdm_inventory_service::compliance::Dependencies {
                    audit_store,
                    runtime,
                    tenant,
                    clock: Arc::new(crate::clock::InventoryClock(clock)),
                    groups,
                    reconcile_messaging: messaging,
                    cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
                },
            )),
        })
    }
}
