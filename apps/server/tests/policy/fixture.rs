//! Concrete participants needed by this consumer's existing cases.
use crate::{assembly, authority_t2_support::Context, command_runtime_t2_support::Prepared};
use anyhow::Result;
use std::sync::Arc;
pub(crate) struct Fixture {
    pub(crate) resources: Prepared,
    pub(crate) software: crate::assembly::software::Assembly,
    pub(crate) registration: crate::assembly::registration::Assembly,
    pub(crate) materials: Arc<crate::assembly::policy::EventInputs>,
}
impl Fixture {
    pub(crate) async fn open(c: &Context, signing: bool) -> Result<Self> {
        let resources = Prepared::open(c, signing, |_| {}).await?;
        let result: Result<_> = async {
            let config = &resources.config;
            let storage = &resources.storage;
            let protection = &resources.protection;
            let source = &resources.source;

            let authority = Arc::new(
                rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
                    tenant: storage.tenant,
                    instance: config.identity.instance_id.clone(),
                    source: Arc::new(assembly::software_sources::Source(source.clone())),
                    inventory: Arc::new(assembly::software_sources::Inventory),
                    lifecycle: Arc::new(assembly::software_sources::Lifecycle),
                    protection: protection.clone(),
                    software_distribution: config.software_distribution,
                },
            );
            let registration = assembly::registration::assemble(
                config,
                storage.runtime.clone(),
                storage.tenant,
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
                config,
                storage.runtime.clone(),
                storage.tenant,
                storage.audit.clone(),
                protection.clone(),
                Arc::new(assembly::software_sources::Source(source.clone())),
                Arc::new(assembly::software_sources::Inventory),
                Arc::new(assembly::software_sources::Lifecycle),
                Arc::new(rss_mdm_software_service::preparation::Preparation::new(
                    rss_mdm_software_service::catalog::Reader::new(storage.tenant),
                    Default::default(),
                )),
                authority,
                registration.native_materials.clone(),
                resources.channels.clone(),
                resources.signing.loaded_key().is_some(),
                resources.sessions.clone(),
                storage.read_pool.clone(),
                storage.reconcile.clone(),
                storage.worker_budget.clone(),
            )
            .await?;

            let materials = Arc::new(assembly::policy::EventInputs {
                source: source.clone(),
                protection: protection.clone(),
                instance: config.identity.instance_id.clone(),
            });
            Ok((software, registration, materials))
        }
        .await;
        let (resources, (software, registration, materials)) = resources.finish(result).await?;
        Ok(Self {
            resources,
            software,
            registration,
            materials,
        })
    }
    pub(crate) async fn close(self) -> Result<()> {
        self.resources.close().await
    }
}
