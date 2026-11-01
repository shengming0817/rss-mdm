//! Explicit collection owner composition over shared host resources.
use super::host_storage::Storage;
use crate::Error;
use std::sync::Arc;
pub(crate) async fn assemble(
    config: &crate::config::Config,
    storage: &Storage,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    protection: Arc<rss_mdm_native_protection::Protector>,
) -> Result<
    (
        Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    ),
    Error,
> {
    let collections = Arc::new(
        rss_mdm_inventory_service::collection::execution::CollectionService::new(
            rss_mdm_inventory_service::collection::execution::Transactions::bind(
                storage.runtime.clone(),
                storage.tenant,
                storage.audit.clone(),
                Arc::new(
                    rss_mdm_inventory_service::collection::execution::Materials {
                        agent_store: Arc::new(super::agent_facts::AgentFacts),
                        source: Arc::new(super::collection_ports::Source(source.clone())),
                        capacity: Arc::new(super::capacity::Capacity),
                        native: Arc::new(super::collection_ports::Delivery {
                            protection: protection.clone(),
                        }),
                    },
                ),
            )
            .await?,
        ),
    );
    let collection_work = Arc::new(
        rss_mdm_inventory_service::collection::execution::worker::Worker::new(
            collections.clone(),
            storage.reconcile.clone(),
            storage.worker_budget.clone(),
            config.background.device_concurrency,
        )?,
    );
    Ok((collections, collection_work))
}
