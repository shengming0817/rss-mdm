//! Host assembly of execution storage, recovery and content adapters.
use crate::{Error, Failure};
use rss_mdm_execution_service::{ExecutionService, deadline, messaging_domain, recovery, storage};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::DeliveryBudget,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
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
        .connect_with(config.flow.storage.database.options()?)
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
        StorageIdentity::new(config.flow.storage.target, config.flow.storage.lineage)
            .map_err(|_| bad())?,
        vec![(
            tenant,
            Epoch::new(config.flow.storage.epoch).map_err(|_| bad())?,
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
        let signer = loaded_signing.map(|loaded| Arc::new(loaded.task));
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
        let (service, inputs, queries) = assemble(
            config,
            protection.clone(),
            task_signing_audit.clone(),
            content.clone(),
            exports,
            runtime.clone(),
            channels.clone(),
            signer,
            bootstrap_urls,
            sessions,
            config
                .recovery_credentials
                .as_ref()
                .map(crate::recovery_credentials::Config::open)
                .transpose()?,
            command_clock,
            cursor_key.clone(),
        )
        .await?;
        let events = crate::policy_assembly::events(
            runtime.clone(),
            tenant,
            task_signing_audit,
            &cursor_key,
            service.clone(),
        )
        .await?;
        Ok(Assembly {
            events,
            channels,
            providers,
            bootstrap,
            service,
            inputs,
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
    signer: Option<Arc<rss_mdm_execution_service::task_signing::Signer>>,
    bootstrap: Option<std::collections::BTreeMap<String, String>>,
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    command_clock: rss_device_command_postgres::CommandClock,
    cursor_key: Vec<u8>,
) -> Result<
    (
        Arc<ExecutionService>,
        Arc<rss_mdm_execution_service::Inputs>,
        Arc<rss_mdm_execution_service::queries::Queries>,
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
    let (outbox, store, reconcile, read_pool) = open_storage(
        runtime.clone(),
        config.execution.database.options()?,
        tenant,
        &protection,
        command_clock,
    )
    .await?;
    let source: Arc<dyn rss_mdm_execution_service::source_authority::SourceAuthority> =
        Arc::new(rss_mdm_execution_service::scope::source::ExecutionSource {
            policies: Arc::new(rss_mdm_policy_service::management::source::PolicySource {
                objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            }),
            objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
            mdm_software_enabled: config.software_distribution.mdm_enabled,
        });
    let agent_store: Arc<dyn rss_mdm_execution_service::channels::Agent> =
        Arc::new(rss_mdm_agent_channel::Bindings);
    let apple_store = Arc::new(rss_mdm_apple_channel::flow_store::Store {
        protection: protection.clone(),
    });
    let software = Arc::new(rss_mdm_software_service::preparation::Preparation::new(
        rss_mdm_software_service::catalog::Reader::new(tenant),
        exports
            .into_iter()
            .map(|(name, service)| (name, Arc::new(service.exports())))
            .collect(),
    ));
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(
        rss_mdm_execution_service::InputDependencies {
            software_distribution: config.software_distribution,
            product_origin: config.product_origin.clone(),
            recovery_enabled: recovery_credentials.is_some(),
            protection: protection.clone(),
            software,
            bootstrap,
            enrollment_entries: config.enrollment_entries.clone(),
            runtime: runtime.clone(),
            tenant,
            content: content.clone(),
            signing_enabled: signer.is_some(),
            agent_installation: channels.clone(),
        },
    ));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        rss_mdm_execution_service::queries::Dependencies {
            read_pool,
            source: source.clone(),
            protection: protection.clone(),
            agent_store: agent_store.clone(),
            apple_results: apple_store.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime: runtime.clone(),
            tenant,
            inputs: inputs.clone(),
            signed: signer.is_some(),
            content_available: content.is_some(),
        },
    ));
    let service = Arc::new(ExecutionService::new(
        rss_mdm_execution_service::Dependencies {
            worker_concurrency: config.background.device_concurrency,
            cursor_key,
            recovery_credentials,
            sessions,
            source,
            protection: protection.clone(),
            inputs: inputs.clone(),
            agent_store,
            apple_profiles: apple_store.clone(),
            apple_push: apple_store.clone(),
            apple_collections: apple_store.clone(),
            apple_results: apple_store.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            audit_store,
            task_signing_audit,
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
            content: content.clone(),
            signer,
        },
    ));
    service.validate_recovery_credentials().await?;
    service
        .initialize_recovery()
        .await
        .map_err(|_| Error::Configuration(crate::ConfigIssue::Execution))?;
    Ok((service, inputs, queries))
}

/// Execution storage admission on the host's runtime, independent of product assembly.
pub(crate) async fn open_storage(
    runtime: Arc<PgRuntime>,
    options: sqlx::postgres::PgConnectOptions,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    command_clock: rss_device_command_postgres::CommandClock,
) -> Result<
    (
        Arc<PgOutboxStore<()>>,
        rss_device_command_postgres::PgStore<()>,
        rss_reconcile_postgres::PgStore,
        sqlx::PgPool,
    ),
    Error,
> {
    let bad = || Error::Configuration(crate::ConfigIssue::Execution);
    storage::bind_native_key(&runtime, tenant, protection.fingerprint_id()).await?;
    let outbox = Arc::new(
        PgOutboxStore::new(
            runtime.clone(),
            messaging_domain(),
            DeliveryBudget::new(
                Duration::from_secs(60),
                Duration::from_secs(6),
                Duration::from_secs(6),
                Duration::from_secs(6),
            )
            .map_err(|_| bad())?,
        )
        .map_err(|_| bad())?,
    );
    let copy = outbox.clone();
    let store = runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        rss_mdm_policy_postgres::verify_authority(c).await?;
                        rss_mdm_scope_postgres::verify_authority(c).await?;
                        rss_mdm_inventory_service::verify_authority(c).await?;
                        rss_mdm_apple_channel::verify_authority(c).await
                    })
                })
                .await?;
                storage::admit(tx).await.map_err(|_| {
                    PgError::from(sqlx::Error::Protocol("command admission".into()))
                })?;
                rss_device_command_postgres::PgStore::new(tx, copy, command_clock)
                    .await
                    .inspect_err(|_| eprintln!("command startup: device-command admission failed"))
            })
        })
        .await
        .fold(
            Ok,
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::CommitUnknown),
            |_| {
                eprintln!("command startup: transaction failed");
                Err(bad())
            },
        )?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(crate::background::SCHEDULER_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .map_err(|_| bad())?;
    let timer = recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let reconcile = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("command startup: reconcile admission failed");
            pool.close().await;
            return Err(bad());
        }
    };
    Ok((outbox, store, reconcile, pool))
}

#[derive(Clone)]
pub(crate) struct Assembly {
    pub(crate) events: Arc<rss_mdm_policy_service::events::Events>,
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) bootstrap:
        Option<Arc<rss_mdm_registration_service::agent::bootstrap::Configuration>>,
    pub(crate) service: Arc<ExecutionService>,
    pub(crate) inputs: Arc<rss_mdm_execution_service::Inputs>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) runtime: Arc<PgRuntime>,
}
