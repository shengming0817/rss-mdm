//! Application composition for inventory queries and compliance, independent of Flow services.
use crate::{Error, Failure};
use std::sync::Arc;
pub(crate) struct Services {
    pub(crate) groups: Arc<rss_mdm_group_service::Groups>,
    pub(crate) assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub(crate) compliance: Arc<rss_mdm_compliance_service::Compliance>,
}
impl Services {
    pub(crate) async fn new(
        inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
        read_pool: sqlx::PgPool,
        runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        probe: rss_transactional_messaging::fence::ExecutionBinding,
        key: &[u8],
        clock: Arc<dyn crate::clock::Clock>,
    ) -> Result<Self, Error> {
        runtime
            .local_tx(probe, crate::identity::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_inventory_service::admit_storage_in(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                probe.tenant(),
                            )
                            .await?;
                            rss_mdm_compliance_service::admit_storage_in(c, probe.tenant()).await?;
                            Ok(())
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Database)),
                |_| Err(Error::Unavailable(Failure::Database)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::Database)),
            )?;
        let messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            probe,
            rss_mdm_inventory_service::transaction::deadline(),
        ))
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
        let groups = Arc::new(
            rss_mdm_group_postgres::GroupStore::new(
                runtime.clone(),
                probe,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?,
        );
        let group_service = Arc::new(
            rss_mdm_group_service::Groups::new(rss_mdm_group_service::Dependencies {
                read_pool: read_pool.clone(),
                reconcile_messaging: messaging.clone(),
                objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                probe,
                groups: groups.clone(),
                cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
                audit_store: audit_store.clone(),
                runtime: runtime.clone(),
                clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
            })
            .await?,
        );
        Ok(Self {
            groups: group_service,
            assets: Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
                rss_mdm_inventory_service::assets::AssetDependencies {
                    read_pool: read_pool.clone(),
                    inventory,
                    audit_store: audit_store.clone(),
                    runtime: runtime.clone(),
                    probe,
                    clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
                    cursor_key: key.to_vec(),
                    reconcile_messaging: messaging.clone(),
                    software_sources: rss_mdm_inventory_service::assets::software::Sources {
                        objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
                        groups: groups.source_reader(),
                    },
                },
            )),
            compliance: Arc::new(rss_mdm_compliance_service::Compliance::new(
                rss_mdm_compliance_service::Dependencies {
                    read_pool,
                    audit_store,
                    runtime,
                    probe,
                    clock: Arc::new(crate::clock::InventoryClock(clock)),
                    groups,
                    reconcile_messaging: messaging,
                    cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
                },
            )),
        })
    }
}
