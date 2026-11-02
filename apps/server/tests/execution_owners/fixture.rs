//! Concrete participants needed by this consumer's existing cases.
use crate::{assembly, authority_t2_support::Context, command_runtime_t2_support::Prepared};
use anyhow::Result;
use std::sync::Arc;
pub(super) struct Fixture {
    pub(super) resources: Prepared,
    pub(super) service: Arc<rss_mdm_device_service::control::Service>,
    pub(super) software: crate::assembly::software::Assembly,
    pub(super) registration: crate::assembly::registration::Assembly,
    pub(super) access_execution: crate::assembly::access_execution::Assembly,
    pub(super) scripts: Arc<rss_mdm_script_service::ScriptService>,
    pub(super) collections:
        Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
    pub(super) self_service: Arc<crate::assembly::self_service::Requests>,
    pub(super) script_work: Arc<rss_mdm_script_service::worker::Worker>,
    pub(super) collection_work:
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    pub(super) task_reads: Arc<crate::assembly::task_reads::Reads>,
}
impl Fixture {
    pub(super) async fn open(c: &Context, signing: bool) -> Result<Self> {
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

            let configuration = assembly::policy::configuration(
                storage.runtime.clone(),
                storage.audit.clone(),
                storage.tenant,
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
            let access_execution = Box::pin(assembly::access_execution::assemble(
                storage.runtime.clone(),
                storage.tenant,
                storage.audit.clone(),
                None,
                storage.reconcile.clone(),
                storage.worker_budget.clone(),
                config.background.device_concurrency,
                config.device_access.is_some(),
            ))
            .await?;
            let (scripts, script_work) = assembly::script::assemble(
                config,
                storage,
                source.clone(),
                resources.sessions.clone(),
            )
            .await?;
            let (collections, collection_work) =
                assembly::collection::assemble(config, storage, source.clone(), protection.clone())
                    .await?;
            let self_service = Arc::new(assembly::self_service::Requests::new(
                storage.runtime.clone(),
                storage.tenant,
                storage.audit.clone(),
                config.identity.instance_id.clone(),
                &[7; 32],
            ));
            let task_reads = assembly::task_reads::assemble(
                config,
                storage,
                protection.clone(),
                None,
                resources.signing.loaded_key().is_some(),
                false,
                source.clone(),
                configuration.clone(),
                software.queries.clone(),
                registration.materials.clone(),
                queries,
            );
            Ok((
                service,
                software,
                registration,
                access_execution,
                scripts,
                collections,
                self_service,
                script_work,
                collection_work,
                task_reads,
            ))
        }
        .await;
        let (
            resources,
            (
                service,
                software,
                registration,
                access_execution,
                scripts,
                collections,
                self_service,
                script_work,
                collection_work,
                task_reads,
            ),
        ) = resources.finish(result).await?;
        Ok(Self {
            resources,
            service,
            software,
            registration,
            access_execution,
            scripts,
            collections,
            self_service,
            script_work,
            collection_work,
            task_reads,
        })
    }
    pub(super) async fn close(self) -> Result<()> {
        self.resources.close().await
    }
}
