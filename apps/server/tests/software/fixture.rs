//! Concrete participants needed by this consumer's existing cases.
use crate::{assembly, authority_t2_support::Context, command_runtime_t2_support::Prepared};
use anyhow::Result;
use std::sync::Arc;
pub(in crate::assembly) struct Fixture {
    pub(in crate::assembly) resources: Prepared,
    pub(in crate::assembly) software: crate::assembly::software::Assembly,
}
impl Fixture {
    pub(in crate::assembly) async fn open(c: &Context) -> Result<Self> {
        Self::open_with(c, |_| {}).await
    }
    pub(in crate::assembly) async fn open_with(
        c: &Context,
        configure: fn(&mut serde_json::Value),
    ) -> Result<Self> {
        Self::with_endpoints(c, Prepared::open(c, configure).await?, None).await
    }
    pub(in crate::assembly) async fn with_endpoints(
        c: &Context,
        resources: Prepared,
        endpoints: Option<std::collections::BTreeMap<String, String>>,
    ) -> Result<Self> {
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
                endpoints,
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
    pub(in crate::assembly) async fn close(self) -> Result<()> {
        self.resources.close().await
    }
}
