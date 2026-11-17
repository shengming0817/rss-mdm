//! Concrete participants needed by this consumer's existing cases.
use crate::{assembly, authority_t2_support::Context, command_runtime_t2_support::Prepared};
use anyhow::Result;
use std::sync::Arc;
pub(super) struct Fixture {
    pub(super) resources: Prepared,
    pub(super) service: Arc<rss_mdm_device_service::control::Service>,
    pub(super) task_reads: Arc<assembly::task_reads::Reads>,
    pub(super) devices: Arc<rss_mdm_registration_service::DeviceService>,
}
impl Fixture {
    pub(super) async fn open(c: &Context) -> Result<Self> {
        let resources = Prepared::open(c, |_| {}).await?;
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

            let configuration = assembly::policy::configuration(
                &resources.background,
                storage.runtime.clone(),
                storage.audit.clone(),
                c.execution(),
                protection.clone(),
                None,
            )
            .await?;
            let (service, queries) = assembly::device_control::assemble(
                config,
                storage,
                protection.clone(),
                None,
                software.transactions.clone(),
                configuration.clone(),
                rss_device_command_postgres::CommandClock::Postgres,
            )
            .await?;
            let task_reads = assembly::task_reads::assemble(
                config,
                storage,
                protection.clone(),
                None,
                false,
                source.clone(),
                configuration,
                software.queries.clone(),
                registration.materials,
                queries,
            );
            let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(
                c.database.registration(),
                c.audit.clone(),
            ));
            Ok((service, task_reads, devices))
        }
        .await;
        let (resources, (service, task_reads, devices)) = resources.finish(result).await?;
        Ok(Self {
            resources,
            service,
            task_reads,
            devices,
        })
    }
    pub(super) async fn close(self) -> Result<()> {
        self.resources.close().await
    }
}
