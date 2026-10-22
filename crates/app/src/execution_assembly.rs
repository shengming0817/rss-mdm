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
        .max_connections(4)
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
    );
    let runtime = Arc::new(
        PgRuntime::connect(pg, crate::lifecycle::RuntimeTimer, binding)
            .await
            .map_err(|_| Error::Unavailable(Failure::CommandStorage))?,
    );
    let result = async {
        crate::database::admit_audit_runtime(&runtime, &audit_store, tenant).await?;
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
                    storage::admit(tx).await.map_err(|_| {
                        PgError::from(sqlx::Error::Protocol("command admission".into()))
                    })?;
                    rss_device_command_postgres::PgStore::new(tx, copy, command_clock)
                        .await
                        .inspect_err(|_| {
                            eprintln!("command startup: device-command admission failed")
                        })
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
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(database.options()?)
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
        config.enrollment_entries.validate()?;
        let source: Arc<dyn rss_mdm_execution_service::source_authority::SourceAuthority> =
            Arc::new(
                rss_mdm_flow_service::planning::execution_source::ExecutionSource {
                    objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
                        audit_store.clone(),
                    )),
                    mdm_software_enabled: config.software_distribution.mdm_enabled,
                },
            );
        let agent_store: Arc<dyn rss_mdm_execution_service::channels::Agent> =
            Arc::new(rss_mdm_agent_channel::Bindings);
        let apple_store = Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: protection.clone(),
        });
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
        let (signer, configuration_signer) = match loaded_signing {
            Some(loaded) => (
                Some(Arc::new(loaded.task)),
                Some(Arc::new(loaded.configuration)),
            ),
            None => (None, None),
        };
        let bootstrap = channels
            .material(
                rss_mdm_management_http::runtime_diagnostics::ChannelName::AgentBootstrap,
                config.agent_pki.bootstrap_materials(
                    &providers,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                ),
            )?
            .flatten();
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
                recovery_enabled: config.recovery_credentials.is_some(),
                protection: protection.clone(),
                software,
                agent_origin: match &config.agent_pki {
                    crate::agent_pki::Config::StepCa { endpoint, .. } => endpoint.origin.clone(),
                    _ => String::new(),
                },
                bootstrap: bootstrap.as_ref().map(|_| {
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
                }),
                enrollment_entries: config.enrollment_entries.clone(),
                runtime: runtime.clone(),
                tenant,
                content: content.clone(),
                signing_enabled: signer.is_some(),
            },
        ));
        let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(
            rss_mdm_execution_service::queries::Dependencies {
                source: source.clone(),
                protection: protection.clone(),
                agent_store: agent_store.clone(),
                apple_results: apple_store.clone(),
                policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
                audit_store: audit_store.clone(),
                runtime: runtime.clone(),
                tenant,
                inputs: inputs.clone(),
                signed: signer.is_some(),
                content_available: content.is_some(),
            },
        ));
        let service = Arc::new(ExecutionService::new(
            rss_mdm_execution_service::Dependencies {
                recovery_credentials: config
                    .recovery_credentials
                    .as_ref()
                    .map(crate::recovery_credentials::Config::open)
                    .transpose()?,
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
                runtime: runtime.clone(),
                outbox,
                store,
                reconcile,
                tenant,
                instance: config.identity.instance_id.clone(),
                content: content.clone(),
                signer,
            },
        ));
        service.validate_recovery_credentials().await?;
        Ok(Assembly {
            channels,
            providers,
            bootstrap,
            configuration_signer,
            #[cfg(test)]
            webhooks: Arc::default(),
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

#[derive(Clone)]
pub(crate) struct Assembly {
    pub(crate) channels: Arc<crate::channel_status::Channels>,
    pub(crate) providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub(crate) bootstrap:
        Option<Arc<rss_mdm_registration_service::agent::bootstrap::Configuration>>,
    pub(crate) configuration_signer:
        Option<Arc<rss_mdm_registration_service::agent::configurations::Signer>>,
    #[cfg(test)]
    pub(crate) webhooks: Arc<std::sync::OnceLock<Arc<crate::webhooks::Backend>>>,
    pub(crate) service: Arc<ExecutionService>,
    pub(crate) inputs: Arc<rss_mdm_execution_service::Inputs>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) runtime: Arc<PgRuntime>,
}
