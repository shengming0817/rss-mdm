//! Concrete participants needed by this consumer's existing cases.
use crate::{assembly, authority_t2_support::Context, command_runtime_t2_support::Prepared};
use anyhow::Result;
use std::sync::Arc;
pub(super) struct Fixture {
    pub(super) resources: Prepared,
    pub(super) software: crate::assembly::software::Assembly,
}
impl Fixture {
    pub(super) async fn open(c: &Context) -> Result<Self> {
        Self::open_with(c, |_| {}).await
    }
    pub(super) async fn open_with(
        c: &Context,
        configure: fn(&mut serde_json::Value),
    ) -> Result<Self> {
        let resources = Prepared::open(c, configure).await?;
        let result: Result<_> = async {
            let config = &resources.config;
            let storage = &resources.storage;
            let protection = &resources.protection;
            let source = &resources.source;

            let authority = Arc::new(
                rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
                    instance: config.identity.instance_id.clone(),
                    source: Arc::new(assembly::software_sources::Source(source.clone())),
                    inventory: Arc::new(assembly::software_sources::Inventory),
                    lifecycle: Arc::new(assembly::software_sources::Lifecycle),
                    protection: protection.clone(),
                    software_distribution: config.software_distribution,
                },
            );
            let registration = assembly::registration::assemble(
                storage.discovery_pool.clone(),
                config,
                &resources.background,
                storage.runtime.clone(),
                c.execution(),
                storage.audit.clone(),
                protection.clone(),
                source.clone(),
                authority.clone(),
                None,
                resources.sessions.clone(),
                storage.reconcile.clone(),
                storage.worker_budget.clone(),
            )
            .await?;
            let software = assembly::software::assemble(
                storage.discovery_pool.clone(),
                config,
                &resources.background,
                storage.runtime.clone(),
                c.execution(),
                storage.audit.clone(),
                protection.clone(),
                Arc::new(assembly::software_sources::Source(source.clone())),
                Arc::new(assembly::software_sources::Inventory),
                Arc::new(assembly::software_sources::Lifecycle),
                Arc::new(rss_mdm_software_service::preparation::Preparation::new(
                    rss_mdm_software_service::catalog::Reader::new(),
                    Default::default(),
                )),
                authority,
                registration.native_materials.clone(),
                resources.channels.clone(),
                resources.sessions.clone(),
                storage.read_pool.clone(),
                storage.reconcile.clone(),
                storage.worker_budget.clone(),
            )
            .await?;

            Ok((software,))
        }
        .await;
        let (resources, (software,)) = resources.finish(result).await?;
        Ok(Self {
            resources,
            software,
        })
    }
    pub(super) async fn close(self) -> Result<()> {
        self.resources.close().await
    }
}
