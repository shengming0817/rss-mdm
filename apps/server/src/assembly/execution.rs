//! Host assembly of execution storage, recovery and content adapters.
use crate::{Error, Failure};
use rss_mdm_device_service::control::{Service, deadline};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{sync::Arc, time::Duration};
pub(crate) struct ContentResource(pub Arc<rss_mdm_content_service::Store>);
impl rss_runtime::ManagedResource for ContentResource {
    fn name(&self) -> &str {
        "content-store"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
pub(crate) async fn open_content(
    config: &crate::config::Config,
    protection: Arc<rss_mdm_native_protection::Protector>,
) -> std::result::Result<Option<Arc<rss_mdm_content_service::Store>>, Error> {
    let Some(c) = config.content.as_ref() else {
        return Ok(None);
    };
    let bad = || Error::Configuration(crate::ConfigIssue::Execution);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(crate::background::CONTENT_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(6))
        .connect_with(config.business_databases.content.options()?)
        .await
        .map_err(|_| bad())?;
    match rss_mdm_content_service::Store::open(
        protection,
        c,
        &config.identity.tenant_id,
        Arc::new(crate::lifecycle::RuntimeTimer),
        pool.clone(),
    )
    .await
    {
        Ok(store) => Ok(Some(store)),
        Err(e) => {
            pool.close().await;
            Err(e.into())
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit host capabilities avoid a second assembly container"
)]
pub(crate) async fn open(
    config: &crate::config::Config,
    protection: Arc<rss_mdm_native_protection::Protector>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
    exports: std::collections::BTreeMap<
        String,
        Arc<rss_mdm_software_service::publication::PublicationService>,
    >,
    command_clock: rss_device_command_postgres::CommandClock,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    cursor_key: Vec<u8>,
) -> std::result::Result<Assembly, Error> {
    let bad = || Error::Configuration(crate::ConfigIssue::Execution);
    let database = &config.execution.database;
    let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| bad())?;
    let binding = ExecutionBinding::new(
        StorageIdentity::new(
            config.storage_binding.target,
            config.storage_binding.lineage,
        )
        .map_err(|_| bad())?,
        vec![(
            tenant,
            Epoch::new(config.storage_binding.epoch).map_err(|_| bad())?,
        )],
    )
    .map_err(|_| bad())?;
    let pg = PgConfig::new(
        &database.host,
        database.port,
        &database.name,
        &database.user,
        PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
        PgPrivateCa::from_pem(crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec())
            .map_err(|_| bad())?,
    )
    .with_pool_limits(0, config.background.execution_connections());
    let runtime = Arc::new(
        PgRuntime::connect(pg, crate::lifecycle::RuntimeTimer, binding)
            .await
            .map_err(|_| Error::Unavailable(Failure::CommandStorage))?,
    );
    let task_signing_audit = audit_store.clone();
    let recovery_materials = config
        .recovery_credentials
        .as_ref()
        .map(crate::recovery_credentials::Config::open)
        .transpose()?;
    let credential_receipts = recovery_materials.as_ref().map(|protection| {
        Arc::new(
            rss_mdm_recovery_credentials::native_receipts::NativeReceipts::new(protection.clone()),
        )
    });
    let result = async {
        let channels = Arc::new(crate::channel_status::Channels::new(config));
        let providers = crate::device_pki::prepare(&config.device_pki, &channels)?;
        let loaded_signing = crate::task_signing::prepare(
            config.task_signing.as_ref(),
            &config.access_database,
            tenant,
            &protection,
            &channels,
        )
        .await?;
        let signing = Arc::new(rss_mdm_task_trust::Signing::new(tenant, loaded_signing)?);
        let task_trust = Arc::new(rss_mdm_task_trust::Service::new(
            tenant,
            signing.clone(),
            protection.clone(),
            task_signing_audit.clone(),
            Arc::new(rss_mdm_agent_channel::signature_retirement::PendingSignatures),
        )?);
        let bootstrap = channels
            .material(
                crate::channel_status::ChannelName::AgentBootstrap,
                config.agent_pki.bootstrap_materials(
                    &config.identity.instance_id,
                    &providers,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                ),
            )?
            .flatten();
        let bootstrap_urls = bootstrap.as_ref().map(|_| {
            config
                .device_pki
                .iter()
                .filter(|p| p.purpose == rss_mdm_agent_wire::pki::Purpose::AgentBootstrap)
                .filter_map(|p| {
                    p.scep_url
                        .as_ref()
                        .map(|url| (p.issuer.clone(), url.clone()))
                })
                .collect()
        });
        let (
            service,
            scripts,
            collections,
            script_work,
            collection_work,
            software_owner,
            registration_owner,
            access_execution,
            credential_execution,
            self_service,
            queries,
            materials,
            configuration,
            read_pool,
        ) = assemble(
            config,
            protection.clone(),
            task_signing_audit.clone(),
            content.clone(),
            exports,
            runtime.clone(),
            channels.clone(),
            signing.clone(),
            bootstrap_urls,
            sessions,
            recovery_materials,
            command_clock,
            cursor_key.clone(),
        )
        .await?;
        let task_reads = Arc::new(super::task_reads::Reads {
            content_available: config.content.is_some(),
            configuration: configuration.clone(),
            software: software_owner.queries.clone(),
            enrollment: registration_owner.materials.clone(),
            entries: config.enrollment_entries.clone(),
            signing_enabled: signing.loaded_key().is_some(),
            recovery_enabled: credential_execution.is_some(),
            clock: Arc::new(crate::lifecycle::RuntimeTimer),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            tenant,
            read_pool: read_pool.clone(),
            source: materials.source.clone(),
            scripts: rss_mdm_script_service::inputs::Inputs::bind(
                runtime.clone(),
                tenant,
                content.clone(),
                signing.loaded_key().is_some(),
            ),
            collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs::bind(
                runtime.clone(),
                tenant,
                content.clone(),
                Arc::new(super::collection_ports::Delivery {
                    protection: protection.clone(),
                }),
            ),
            execution: queries.clone(),
        });
        Ok(Assembly {
            credential_receipts,
            access_execution,
            credential_execution,
            task_reads,
            software: software_owner,
            registration: registration_owner,
            configuration,
            read_pool,
            signing,
            task_trust,
            materials,
            channels,
            providers,
            bootstrap,
            service,
            scripts,
            collections,
            script_work,
            collection_work,
            self_service,
            queries,
            protection,
            content,
            runtime: runtime.clone(),
        })
    }
    .await;
    if result.is_err() {
        runtime.close().await;
    }
    result
}

/// Compose execution from the host's already prepared capabilities; no platform preparation.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit host capabilities avoid a second assembly container"
)]
pub(crate) async fn assemble(
    config: &crate::config::Config,
    protection: Arc<rss_mdm_native_protection::Protector>,
    task_signing_audit: Arc<rss_mdm_audit_integration::AuditStore>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
    exports: std::collections::BTreeMap<
        String,
        Arc<rss_mdm_software_service::publication::PublicationService>,
    >,
    runtime: Arc<PgRuntime>,
    channels: Arc<crate::channel_status::Channels>,
    signing: Arc<rss_mdm_task_trust::Signing>,
    bootstrap: Option<std::collections::BTreeMap<String, String>>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    command_clock: rss_device_command_postgres::CommandClock,
    cursor_key: Vec<u8>,
) -> Result<
    (
        Arc<Service>,
        Arc<rss_mdm_script_service::ScriptService>,
        Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
        Arc<rss_mdm_script_service::worker::Worker>,
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
        super::software::Assembly,
        super::registration::Assembly,
        super::access_execution::Assembly,
        Option<super::credential_execution::Assembly>,
        Arc<super::self_service::Requests>,
        Arc<rss_mdm_device_service::control::queries::Queries>,
        Arc<super::policy::EventInputs>,
        Arc<rss_mdm_policy_service::configuration::Transactions>,
        sqlx::PgPool,
    ),
    Error,
> {
    let tenant = TenantId::parse(&config.identity.tenant_id)
        .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?;
    config.enrollment_entries.validate()?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit_store = Arc::new(
        task_signing_audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let (outbox, store, reconcile, read_pool) = super::host_storage::open(
        runtime.clone(),
        config.execution.database.options()?,
        tenant,
        &protection,
        command_clock,
        rss_mdm_device_service::control::messaging_domain(),
    )
    .await?;
    let source = Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
        Arc::new(rss_mdm_device_service::planning::PlanningObjects),
    ));
    let agent_store: Arc<dyn rss_mdm_device_service::control::agent_facts::Store> =
        Arc::new(super::agent_facts::AgentFacts);
    let windows_results: Arc<dyn rss_mdm_device_service::control::windows_results::Store> =
        Arc::new(super::windows_results::WindowsResults(
            rss_mdm_windows_channel::results::Results {
                protection: protection.clone(),
            },
        ));
    let apple_store = Arc::new(super::apple_facts::AppleFacts(
        rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        },
    ));
    let software = Arc::new(rss_mdm_software_service::preparation::Preparation::new(
        rss_mdm_software_service::catalog::Reader::new(tenant),
        exports
            .into_iter()
            .map(|(name, service)| (name, Arc::new(service.exports())))
            .collect(),
    ));
    let configuration = super::policy::configuration(
        runtime.clone(),
        audit_store.clone(),
        tenant,
        protection.clone(),
        content.clone(),
    )
    .await?;
    let queries = Arc::new(rss_mdm_device_service::control::queries::Queries::new(
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        rss_mdm_device_service::control::queries::Dependencies {
            read_pool: read_pool.clone(),
            protection: protection.clone(),
            windows_results: windows_results.clone(),
            apple_results: apple_store.clone(),

            runtime: runtime.clone(),
            tenant,
        },
    ));
    let configuration_cleanup =
        Arc::new(super::configuration_cleanup::Cleanup(configuration.clone()));

    let scripts = Arc::new(rss_mdm_script_service::ScriptService::new(
        rss_mdm_script_service::Transactions::bind(
            runtime.clone(),
            tenant,
            audit_store.clone(),
            Arc::new(rss_mdm_script_service::Materials {
                agent_store: Arc::new(super::agent_facts::AgentFacts),
                source: source.clone(),
                capacity: Arc::new(super::capacity::Capacity),
                instance: config.identity.instance_id.clone(),
            }),
        )
        .await
        .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?,
        sessions.clone(),
    ));
    let collections = Arc::new(
        rss_mdm_inventory_service::collection::execution::CollectionService::new(
            rss_mdm_inventory_service::collection::execution::Transactions::bind(
                runtime.clone(),
                tenant,
                audit_store.clone(),
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
    let worker_budget = Arc::new(tokio::sync::Semaphore::new(
        config.background.device_concurrency,
    ));
    let software_source = Arc::new(super::software_sources::Source(source.clone()));
    let software_inventory = Arc::new(super::software_sources::Inventory);
    let software_lifecycle = Arc::new(super::software_sources::Lifecycle);
    let authority = Arc::new(
        rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
            tenant,
            instance: config.identity.instance_id.clone(),
            source: software_source.clone(),
            inventory: software_inventory.clone(),
            lifecycle: software_lifecycle.clone(),
            protection: protection.clone(),
            software_distribution: config.software_distribution,
        },
    );
    let registration_owner = super::registration::assemble(
        config,
        runtime.clone(),
        tenant,
        audit_store.clone(),
        protection.clone(),
        source.clone(),
        authority.clone(),
        bootstrap.clone(),
        sessions.clone(),
        reconcile.clone(),
        worker_budget.clone(),
    )
    .await?;
    // Keep independent owner startup futures off the enclosing host startup stack.
    let access_execution = Box::pin(super::access_execution::assemble(
        runtime.clone(),
        tenant,
        audit_store.clone(),
        protection.clone(),
        source.clone(),
        recovery_credentials.clone(),
        reconcile.clone(),
        worker_budget.clone(),
        config.background.device_concurrency,
    ))
    .await?;
    let credential_execution = if let Some(credentials) = recovery_credentials.clone() {
        Some(
            Box::pin(super::credential_execution::assemble(
                config,
                runtime.clone(),
                tenant,
                audit_store.clone(),
                protection.clone(),
                credentials,
                source.clone(),
                reconcile.clone(),
                worker_budget.clone(),
            ))
            .await?,
        )
    } else {
        None
    };
    let software_owner = super::software::assemble(
        config,
        runtime.clone(),
        tenant,
        audit_store.clone(),
        protection.clone(),
        software_source,
        software_inventory,
        software_lifecycle,
        software.clone(),
        authority,
        registration_owner.native_materials.clone(),
        channels.clone(),
        signing.loaded_key().is_some(),
        sessions.clone(),
        read_pool.clone(),
        reconcile.clone(),
        worker_budget.clone(),
    )
    .await?;
    let materials = Arc::new(super::policy::EventInputs {
        source: source.clone(),
        protection: protection.clone(),
        instance: config.identity.instance_id.clone(),
    });
    let script_work = Arc::new(
        rss_mdm_script_service::worker::Worker::new(
            scripts.clone(),
            reconcile.clone(),
            worker_budget.clone(),
            config.background.device_concurrency,
        )
        .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?,
    );
    let collection_work = Arc::new(
        rss_mdm_inventory_service::collection::execution::worker::Worker::new(
            collections.clone(),
            reconcile.clone(),
            worker_budget.clone(),
            config.background.device_concurrency,
        )?,
    );
    let self_service = Arc::new(super::self_service::Requests::new(
        runtime.clone(),
        tenant,
        audit_store.clone(),
        config.identity.instance_id.clone(),
        &cursor_key,
    ));
    let service = Arc::new(Service::new(
        rss_mdm_device_service::control::Dependencies {
            retirement: Arc::new(crate::registration_lifecycle::Bridge),
            worker_budget,
            capacity: Arc::new(super::capacity::Capacity),
            task_cleanup: Arc::new(super::task_cleanup::Cleanup(
                software_owner.transactions.clone(),
            )),
            configuration_cleanup,
            worker_concurrency: config.background.device_concurrency,
            lock_pins: recovery_credentials.as_ref().map(|p| {
                Arc::new(super::device_materials::Pins(
                    rss_mdm_recovery_credentials::lock_pin::LockPins::new(p.clone()),
                )) as Arc<dyn rss_mdm_device_service::control::lock_pin::LockPins>
            }),

            source: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            protection: protection.clone(),

            agent_store,
            apple_profiles: apple_store.clone(),
            windows_results: windows_results.clone(),
            apple_results: apple_store.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            audit_store,
            runtime: runtime.clone(),
            outbox,
            store,
            reconcile,
            reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(
                runtime.clone(),
                tenant,
                deadline(),
            )
            .await
            .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?,
            tenant,
            instance: config.identity.instance_id.clone(),
        },
    ));
    service
        .initialize_recovery()
        .await
        .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?;
    Ok((
        service,
        scripts,
        collections,
        script_work,
        collection_work,
        software_owner,
        registration_owner,
        access_execution,
        credential_execution,
        self_service,
        queries,
        materials,
        configuration,
        read_pool,
    ))
}

#[derive(Clone)]
pub(crate) struct Assembly {
    pub(crate) access_execution: super::access_execution::Assembly,
    pub(crate) credential_execution: Option<super::credential_execution::Assembly>,
    pub(crate) credential_receipts:
        Option<Arc<rss_mdm_recovery_credentials::native_receipts::NativeReceipts>>,
    pub(crate) software: super::software::Assembly,
    pub(crate) registration: super::registration::Assembly,
    pub(crate) read_pool: sqlx::PgPool,
    pub(crate) configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub(crate) signing: Arc<rss_mdm_task_trust::Signing>,
    pub(crate) task_trust: Arc<rss_mdm_task_trust::Service>,
    pub(crate) materials: Arc<super::policy::EventInputs>,
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) bootstrap:
        Option<Arc<rss_mdm_registration_service::agent::bootstrap::Configuration>>,
    pub(crate) service: Arc<Service>,
    pub(crate) self_service: Arc<super::self_service::Requests>,
    pub(crate) script_work: Arc<rss_mdm_script_service::worker::Worker>,
    pub(crate) collection_work:
        Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    pub(crate) scripts: Arc<rss_mdm_script_service::ScriptService>,
    pub(crate) collections:
        Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
    pub(crate) task_reads: Arc<super::task_reads::Reads>,
    pub(crate) queries: Arc<rss_mdm_device_service::control::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) runtime: Arc<PgRuntime>,
}
