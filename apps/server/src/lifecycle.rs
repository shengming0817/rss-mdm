//! Product process lifetime, driven by the existing RSS managed listener.
use crate::{ConfigIssue, Failure};
use crate::{Error, ProcessError, config::Config};
use rss_runtime::{
    DynManagedResource, LifecycleScope, ManagedResource, ScopeExit, ShutdownError, TotalDrainBudget,
};
use std::{sync::Arc, time::Duration};
// Product composition chooses the Tokio timer for the RSS lifecycle's time domain.
pub(crate) struct RuntimeTimer;
impl rss_request_context::Clock for RuntimeTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete product runtime clock owns the Tokio time domain"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for RuntimeTimer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
pub(crate) struct AccessResource(pub(crate) std::sync::Arc<crate::Database>);
impl ManagedResource for AccessResource {
    fn name(&self) -> &str {
        "access-store"
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
#[cfg(test)]
tokio::task_local! {
    pub(crate) static INSTALLED_ADMISSION: Arc<std::sync::OnceLock<rss_runtime::AdmissionGate>>;
}
pub async fn serve(
    config: Config,
    stop: impl std::future::Future<Output = Result<(), std::io::Error>>,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> Result<(), ProcessError> {
    let readiness = Arc::new(crate::inventory_runtime::Readiness::default());
    let stop_readiness = readiness.clone();
    let startup_cancel = tokio_util::sync::CancellationToken::new();
    let stop_cancel = startup_cancel.clone();
    let stop = async move {
        let result = stop.await;
        stop_cancel.cancel();
        stop_readiness.stop();
        result
    };
    let compiled = config
        .compile()
        .map_err(|e| ProcessError::at("startup.configuration", e))?;
    let background = compiled.background;
    let http = compiled.http;
    let admission = Arc::new(std::sync::OnceLock::new());
    let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
        TotalDrainBudget::new(http.total_drain).map_err(|_| {
            ProcessError::at("startup.budget", Error::Configuration(ConfigIssue::Budget))
        })?,
        Arc::new(RuntimeTimer),
    )
    .map_err(|_| ProcessError::at("startup.scope", Error::Unavailable(Failure::Runtime)))?;
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let (
                        listener,
                        app,
                        native_listeners,
                        _,
                        _,
                        runtime,
                        protocol_runtime, windows_business, _, (task_registrations, command_relay),
                        automation,
                        group_work,
                        scope_work,
                        query_work,
                        compliance_work,
                        scope_delivery,
                        asset_delivery,
                        publications,
                        archive,
                        device_work,
                        notifications,
                        gateway,
                    ) = tokio::time::timeout(crate::assembly::publication::startup_budget(&compiled.config.publication), async {
                        let access = Arc::new(
                            crate::Database::connect(
                                compiled.config.access_options().map_err(|e| {
                                    ProcessError::at("startup.access_configuration", e)
                                })?,
                                &compiled.config.audit,
                            )
                            .await
                            .map_err(|e| ProcessError::at("startup.access_store", e))?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(AccessResource(
                            access.clone(),
                        )));
                        access
                            .authorization_store()
                            .require_management_initializer()
                            .await
                            .map_err(|error| {
                                ProcessError::at("startup.identity_management", error.into())
                            })?;
                        let notifications = crate::worker_wake::Listener::new(
                            compiled
                                .config
                                .access_database
                                .options()
                                .map_err(|e| ProcessError::at("startup.notifications", e))?,

                        );
                        startup.stage_resource(DynManagedResource::new_box(notifications.clone()));
                        use crate::inventory_runtime::{
                            Clock, InventoryRuntime, ObservationResource, ProjectionResource,
                        };
                        let clock = Clock::new(monotonic.clone(), compiled.inventory_runtime);
                        let runtime_options =
                            compiled.config.runtime_options().map_err(|e| {
                                ProcessError::at("startup.runtime_database_configuration", e)
                            })?;
                        let observation =
                            ObservationResource::open(runtime_options.clone(), clock.clone())
                                .await
                                .map_err(|e| ProcessError::at("startup.observation", e.into()))?;
                        let observation_store = observation.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(observation));
                        let startup_control =
                            rss_projection::Control::new(&clock, clock.startup_cutoff(), &startup_cancel);
                        let projection = ProjectionResource::open(
                            runtime_options,
                            clock.clone(),
                            &startup_control,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.projection", e.into()))?;
                        let projection_store = projection.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(projection));
                        let probe=compiled.config.management_binding().map_err(assembly_error)?;
                        crate::identity::management_tenant(
                            &compiled.config.identity.database,
                            rss_identity_core::InstanceId::parse(
                                &compiled.config.identity.instance_id,
                            )
                            .map_err(|_| {
                                assembly_error(Error::Configuration(
                                    ConfigIssue::IdentityConfiguration,
                                ))
                            })?,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.access_transaction", e))?;
                        let source_runtime = crate::identity::open_runtime(
                            &compiled.config.access_database,
                            &compiled.config.storage_binding.target,
                            &compiled.config.storage_binding.lineage,
            compiled.background.access_connections,
        )
                        .await
                        .map_err(|e| ProcessError::at("startup.access_transaction", e))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            AccessTransactionResource(source_runtime.clone()),
                        ));
                        let audit_store = access
                            .audit_store(&compiled.config.audit, source_runtime.clone(), probe)
                            .await
                            .map_err(|e| ProcessError::at("startup.audit", e))?;
                        let runtime = Arc::new(InventoryRuntime::new(
                            observation_store,
                            projection_store,
                            access.inventory(),
            access.long_operations.clone(),
                            audit_store.clone(),
                            probe.storage(),
                            rss_transactional_messaging::fence::Epoch::new(compiled.config.storage_binding.epoch)
                                .map_err(|_|assembly_error(Error::Configuration(ConfigIssue::IdentityConfiguration)))?,
                            clock,
                            readiness,
                        ));
                        let protection = compiled
                            .config
                            .native_protector()
                            .map_err(|e| ProcessError::at("startup.native_protection", e))?;
                        let content = crate::assembly::content::open(
                            &compiled.config,
                            protection.clone(),
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.content", e))?;
                        if let Some(content) = &content {
                            startup.stage_resource(DynManagedResource::new_box(
                                crate::assembly::content::Resource(content.clone()),
                            ));
                        }
let application_clock:Arc<dyn crate::clock::Clock>=Arc::new(crate::clock::SystemClock);
let cursor_key=crate::cursor_keys::load(&source_runtime,probe).await.map_err(assembly_error)?;
let inventory_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.inventory),probe,compiled.background.inventory_connections,audit_store.clone(),"inventory-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let scope_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.scope),probe,compiled.background.scope_connections,audit_store.clone(),"scope-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let policy_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Runtime(&compiled.config.business_databases.policy),probe,compiled.background.policy_connections,audit_store.clone(),"policy-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.resource),probe,2,audit_store.clone(),"resource-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let software_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.software),probe,2,audit_store.clone(),"software-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let inventory_services=crate::assembly::inventory::Services::new(runtime.clone(),access.archive_pool(),inventory_owner.runtime.clone(),inventory_owner.audit.clone(),probe,&cursor_key,application_clock.clone()).await.map_err(assembly_error)?;
let policy_application=crate::assembly::policy::application(&compiled.background,&policy_owner,probe,&cursor_key,application_clock.clone(),protection.clone(),content.clone()).await.map_err(assembly_error)?;
let publications=crate::assembly::publication::open(access.archive_pool(),&compiled.config.publication,&compiled.config.storage_binding,&software_owner,probe,&cursor_key,application_clock.clone(),content.clone(),|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_catalog=crate::assembly::resource::catalog(resource_owner.audit.clone(),resource_owner.runtime.clone(),probe,application_clock.clone(),cursor_key.clone()).await.map_err(assembly_error)?;
let software_catalog=crate::assembly::software::catalog(rss_transactional_messaging::fence::Epoch::new(compiled.config.storage_binding.epoch).map_err(|_|assembly_error(Error::Malformed))?,&software_owner,probe,&cursor_key,application_clock.clone(),content.clone()).await.map_err(assembly_error)?;
let scope_group_health=Arc::new(crate::local_delivery::Health::default());
let asset_input_health=Arc::new(crate::local_delivery::Health::default());
                        let identity = crate::identity::Identity::connect(
                            &compiled.config,
                            &compiled.identity,
                            compiled.identity_management.clone(),
                            if compiled.config.device_access.is_some() {Some(crate::assembly::device_access::identity_platform(&compiled.config).await.map_err(assembly_error)?)} else {None},
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(|error| ProcessError::at("startup.identity", error))?;
                        let da=if compiled.config.device_access.is_some() {Some(Arc::new(crate::assembly::device_access::open(&compiled.config,&identity,&access.authorization_store(),protection.clone(),&cursor_key,|resource|startup.stage_resource(resource)).await.map_err(assembly_error)?))} else {None};
                        if let Some(da)=&da {
                        if let Some(pki)=&da.pki {startup.stage_task_with_token(crate::device_pki::registration("da-device-pki-maintenance",pki.clone()));}
                        if let Some(listener)=crate::assembly::device_access::listener(&compiled.config,compiled.http,&identity,da).await.map_err(assembly_error)? {startup.stage_task_with_token(listener.critical());}
                        }
                        let audit_budget =
                            rss_mdm_audit_integration::budget::AuditBudget::with_cancellation(
                                Duration::from_secs(5),
                                startup_cancel.clone(),
                            );
                        let audit_control = audit_budget.control();
                        audit_store.validate_tenant(probe.tenant(), &audit_control).await.map_err(|error|ProcessError::at("startup.audit",error.into()))?;

let content_access=if let Some(content)=&content {
let content_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.content),probe,2,audit_store.clone(),"content-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
Some(crate::assembly::content::access(&content_owner,&identity,access.authorization_store(),content.clone(),application_clock.clone()).await.map_err(assembly_error)?)
}else{None};
                        let config = &compiled.config;
                        let commands = crate::assembly::host_storage::Storage::open(
                            config,
                            access.archive_pool(),
                            &compiled.background,
                            audit_store.clone(),
                            &protection,
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let channels = Arc::new(crate::channel_status::Channels::new(config,protection.clone()));
                        let providers =
                            crate::device_pki::prepare(&config.device_pki, &channels).map_err(assembly_error)?;
                        let (signing, task_trust) = crate::assembly::task_trust::signing(
                            protection.clone(),
                            audit_store.clone(),
                        )
                        .map_err(assembly_error)?;
                        channels.set(crate::channel_status::ChannelName::Signing,crate::channel_status::ChannelState::Ready,None).map_err(assembly_error)?;
                        let recovery_materials = config
                            .recovery_credentials
                            .as_ref()
                            .map(crate::recovery_credentials::open)
                            .transpose()
                            .map_err(assembly_error)?;
                        let credential_receipts = recovery_materials.as_ref().map(|p| {
                            Arc::new(rss_mdm_recovery_credentials::native_receipts::NativeReceipts::new(p.clone()))
                        });
                        let bootstrap = channels
                            .material(
                                crate::channel_status::ChannelName::AgentBootstrap,
                                config.agent_pki.bootstrap_materials(
                                    &config.identity.instance_id,
                                    &providers,
                                    time::OffsetDateTime::now_utc().unix_timestamp(),
                                ),
                            )
                            .map_err(assembly_error)?
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
                        let source = Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(rss_mdm_install_support::StorageProfile::Mdm, Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects))));
                        let sessions = Arc::new(
                            rss_mdm_authorization_service::session::SessionAuthority::new(
                                identity.authority.clone(),
                            ),
                        );
                        let (scripts, script_work) =
                            crate::assembly::script::assemble(config, &commands, source.clone(), sessions.clone())
                                .await
                                .map_err(assembly_error)?;
                        let (collections, collection_work) = crate::assembly::collection::assemble(
                            probe,
                            &commands,
                            source.clone(),
                            protection.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let configuration = crate::assembly::policy::configuration(
                            &compiled.background,
                            commands.runtime.clone(),
                            commands.audit.clone(),
                            probe,
                            protection.clone(),
                            content.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let software = Arc::new(rss_mdm_software_service::preparation::Preparation::new(
                            rss_mdm_software_service::catalog::Reader::new(),
                            publications
                                .services
                                .clone(),
                        ));
                        let software_source = Arc::new(crate::assembly::software_sources::Source(source.clone()));
                        let software_inventory = Arc::new(crate::assembly::software_sources::Inventory);
                        let software_lifecycle = Arc::new(crate::assembly::software_sources::Lifecycle);
                        let authority = Arc::new(
                            rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
                                instance: config.identity.instance_id.clone(),
                                source: software_source.clone(),
                                inventory: software_inventory.clone(),
                                lifecycle: software_lifecycle.clone(),
                                protection: protection.clone(),
                                software_distribution: config.software_distribution,
                            },
                        );
                        let registration_owner = crate::assembly::registration::assemble(commands.discovery_pool.clone(),
                            config,
                            &compiled.background,
                            commands.runtime.clone(),
                            probe,
                            commands.audit.clone(),
                            protection.clone(),
                            source.clone(),
                            authority.clone(),
                            bootstrap_urls,
                            sessions.clone(),
                            commands.reconcile.clone(),
                            commands.worker_budget.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        // Keep independent owner startup futures off the enclosing host startup stack.
                        let access_execution = Box::pin(crate::assembly::access_execution::assemble(commands.discovery_pool.clone(),
                            commands.runtime.clone(),
                            probe,
                            commands.audit.clone(),
                            recovery_materials.clone(),
                            commands.reconcile.clone(),
                            commands.worker_budget.clone(),
                            config.device_access.is_some(),
                        ))
                        .await
                        .map_err(assembly_error)?;
                        let credential_execution = if let Some(credentials) = recovery_materials.clone() {
                            Some(
                                Box::pin(crate::assembly::credential_execution::assemble(commands.discovery_pool.clone(),
                                    config,
                            &compiled.background,
                                    commands.runtime.clone(),
                                    probe,
                                    commands.audit.clone(),
                                    protection.clone(),
                                    credentials,
                                    source.clone(),
                                    commands.reconcile.clone(),
                                    commands.worker_budget.clone(),
                                ))
                                .await
                                .map_err(assembly_error)?,
                            )
                        } else {
                            None
                        };
                        let software_owner = crate::assembly::software::assemble(commands.discovery_pool.clone(),
                            config,
                            &compiled.background,
                            commands.runtime.clone(),
                            probe,
                            commands.audit.clone(),
                            protection.clone(),
                            software_source,
                            software_inventory,
                            software_lifecycle,
                            software.clone(),
                            authority,
                            registration_owner.native_materials.clone(),
                            channels.clone(),
                            sessions.clone(),
                            commands.read_pool.clone(),
                            commands.reconcile.clone(),
                            commands.worker_budget.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let (control, queries) = crate::assembly::device_control::assemble(
                            config,
                            &commands,
                            protection.clone(),
                            recovery_materials,
                            software_owner.transactions.clone(),
                            configuration.clone(),
                            rss_device_command_postgres::CommandClock::Postgres,
                        )
                        .await
                        .map_err(assembly_error)?;
                        let materials = Arc::new(crate::assembly::policy::EventInputs {
                            source: source.clone(),
                            protection: protection.clone(),
                            instance: config.identity.instance_id.clone(),
                        });
                        let self_service = Arc::new(crate::assembly::self_service::Requests::new(
                            commands.runtime.clone(),
                            commands.audit.clone(),
                            config.identity.instance_id.clone(),
                            &cursor_key,
                        ));
                        let task_reads = crate::assembly::task_reads::assemble(
                            config,
                            &commands,
                            protection.clone(),
                            content.clone(),
                            credential_execution.is_some(),
                            source,
                            configuration.clone(),
                            software_owner.queries.clone(),
                            registration_owner.materials.clone(),
                            queries.clone(),
                        );
                        let scope_editor = Box::pin(crate::scopes::editor(policy_owner.runtime.clone(), probe, application_clock.clone(), policy_owner.audit.clone(), cursor_key.clone(), access.archive_pool())).await.map_err(assembly_error)?;
                        let policies = crate::assembly::policy::management(
            probe,                            scope_editor,
                            &policy_application,
                            Arc::new(rss_mdm_software_service::deployment::Inputs::bind(
                                policy_owner.runtime.clone(),
                                software_owner.materials.inputs.clone(),
                            )),
                            compiled.config.enrollment_entries.clone(),
                            &cursor_key,
                            content.clone(),
                            protection.clone(),
                            compiled.config.software_distribution.mdm_enabled,
                            credential_execution.is_some(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let events = Box::pin(crate::assembly::policy::events(
                            probe,
                            policy_application.clone(),
                            materials.clone(),
                            software_owner.materials.clone(),
                            registration_owner.materials.clone(),
                            credential_execution.as_ref().map(|v| v.materials.clone()).unwrap_or_default(),
                        ))
                        .await
                        .map_err(assembly_error)?;
                        let telemetry = if !compiled.config.telemetry.is_empty() {
let telemetry_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.telemetry),probe,compiled.background.telemetry_control_connections,audit_store.clone(),"telemetry-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let dependencies=rss_mdm_telemetry_service::PolicyDependencies {
 protection: protection.clone(),
 agent_facts: Arc::new(crate::assembly::agent_facts::AgentFacts),
                    read_pool: access.archive_pool(),
clock: Arc::new(crate::lifecycle::RuntimeTimer),
 audit_store:telemetry_owner.audit.clone(),policies:Arc::new(rss_mdm_policy_service::telemetry::Reader::new(rss_mdm_install_support::StorageProfile::Mdm, telemetry_owner.runtime.clone(),Arc::new(rss_mdm_device_service::planning::PlanningObjects))),objects:Arc::new(rss_mdm_device_service::planning::PlanningObjects),
};

                                let service = crate::telemetry::open(&compiled.config.telemetry,probe,telemetry_owner.runtime,dependencies,signing.clone(),|resource|startup.stage_resource(DynManagedResource::new_box(resource)))
                                    .await.map_err(|e| ProcessError::at("startup.telemetry", e))?;
                                Some(service)
                            } else { None };
                        let scheduler = crate::scheduler::SchedulerStorage::open(
                            compiled.config.business_databases.scheduler
                                .options()
                                .map_err(|e| ProcessError::at("startup.scheduler", e))?,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.scheduler", e))?;
                        startup.stage_resource(DynManagedResource::new_box(scheduler.clone()));
                        let automation =
                            crate::automation::Automation::new(crate::automation::PolicyWork::new(
                                access.archive_pool(),
                                probe.storage(),
                                policy_application.clone(),
                                events.clone(),
                                scheduler.store.clone(),
                            ));
                        let scopes = crate::scopes::open(
                            scope_owner.runtime.clone(),
                            probe,
                            Arc::new(crate::clock::SystemClock),
                            scope_owner.audit.clone(),
                            cursor_key.clone(),
            access.archive_pool(),
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.scope", e))?;
                        let scope_work = Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
                            scopes.clone(),
                            scheduler.store.clone(),
                        ));
                        let group_work =
                            Arc::new(rss_mdm_group_service::runtime::GroupWork::new(
                                inventory_services.groups.clone(),
                                scheduler.store.clone(),
                            ));
                        let query_work =
                            Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
                                inventory_services.assets.clone(),
                                scheduler.store.clone(),
                            ));
                        let compliance_work = Arc::new(
                            rss_mdm_compliance_service::runtime::ComplianceWork::new(
                                inventory_services.compliance.clone(),
                                scheduler.store.clone(),
                            ),
                        );
                        let scope_delivery = crate::local_delivery::Delivery::open(
                            &compiled.config, commands.discovery_pool.clone(),protection.clone(), scope_group_health.clone(),
                            crate::local_delivery::Lane { database: &compiled.config.scope_group_database,
                                role: "mdm_scope_group_consumer", domain: rss_mdm_scope_service::group_changes::DOMAIN,
                                consumer: rss_mdm_scope_service::group_changes::CONSUMER, name: "scope-group-delivery",scopes:"SELECT * FROM mdm_group.delivery_scopes($1,$2)" },
                            |runtime, binding, messaging| (rss_mdm_scope_service::group_changes::Receiver::new(
                                rss_mdm_install_support::StorageProfile::Mdm, runtime, messaging),
                                rss_mdm_scope_service::group_changes::Validator { storage:binding.storage() }),
                        ).await.map_err(|e| ProcessError::at("startup.scope_group_delivery", e))?;
                        startup.stage_resource(DynManagedResource::new_box(crate::local_delivery::Resource(scope_delivery.clone())));
                        let asset_delivery = crate::local_delivery::Delivery::open(
                            &compiled.config, commands.discovery_pool.clone(),protection.clone(), asset_input_health.clone(),
                            crate::local_delivery::Lane { database: &compiled.config.asset_input_database,
                                role: "mdm_asset_ingress_consumer", domain: crate::asset_inputs::DOMAIN,
                                consumer: crate::asset_inputs::CONSUMER, name: "asset-input-delivery",scopes:"SELECT * FROM mdm_devices.asset_delivery_scopes($1,$2)" },
                            |_, binding, messaging| (crate::asset_inputs::Receiver { messaging }, crate::asset_inputs::Validator { storage:binding.storage() }),
                        ).await.map_err(|e| ProcessError::at("startup.asset_input_delivery", e))?;
                        startup.stage_resource(DynManagedResource::new_box(crate::local_delivery::Resource(asset_delivery.clone())));
                        let listen = compiled.config.listen;
                        let gateway = compiled.config.trusted_gateway;
                        let associations = Arc::new(
                            rss_mdm_device_service::Associations::new(
                                audit_store.clone(),

                                &cursor_key,
                            )
                            .map_err(|_| {
                                ProcessError::at(
                                    "startup.associations",
                                    Error::Unavailable(Failure::Database),
                                )
                            })?,
                        );
                        let device_work=Arc::new(rss_mdm_device_service::worker::DeviceWork::new(
                            commands.discovery_pool.clone(),probe,associations.clone(),source_runtime.clone(),scheduler.store.clone(),
                            rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(8)),
                        ).await.map_err(|_|ProcessError::at("startup.device_worker",Error::Unavailable(Failure::Database)))?);
                        let timeline = access
                            .timeline(audit_store.clone(), &cursor_key, compiled.audit_query)
                            .map_err(|e| ProcessError::at("startup.timeline", e))?;
                        let archive = crate::certificate_archive::assemble(
                            &access,
                            audit_store.clone(),
                            Arc::new(crate::clock::SystemClock),
                        );
                        // Resource declarations are corrected before any execution runner is exposed.









                        let task_registrations = {
                            use crate::worker_wake::Work;
                            let signals = &notifications.signals;
                            let mut tasks = vec![
                                access_execution
                                    .worker
                                    .clone()
                                    .registration(background.tasks, background.tasks_drain, signals.handle(Work::AccessRecovery))
                                    .critical(),
                            ];
                            if let Some(credentials) = &credential_execution {
                                for maintenance in &credentials.maintenance {tasks.push(maintenance.clone().registration().critical());}
                                for worker in &credentials.worker {tasks.push(worker.clone().registration(background.tasks, background.tasks_drain, signals.handle(Work::CredentialRecovery)).critical());}
                                tasks.push(
                                    credentials
                                        .native
                                        .clone()
                                        .registration(background.tasks, background.tasks_drain, Arc::new(
                                            rss_mdm_recovery_credentials::native::worker_wake::Signals::from_handles([
                                                signals.handle(Work::CommandRelay),
                                                signals.handle(Work::CredentialNativeRecovery),
                                            ]),
                                        ))
                                        .critical(),
                                );
                            }
                            tasks.extend([
                                control.clone().registration(background.commands, background.commands_drain, signals.execution()).critical(),
                                script_work
                                    .clone()
                                    .registration(background.tasks, background.tasks_drain, signals.handle(Work::ScriptRecovery))
                                    .critical(),
                                collection_work
                                    .clone()
                                    .registration(background.tasks, background.tasks_drain, signals.handle(Work::CollectionRecovery))
                                    .critical(),
                                software_owner
                                    .service
                                    .clone()
                                    .registration(background.commands, background.commands_drain, signals.software())
                                    .critical(),
                                registration_owner
                                    .native
                                    .clone()
                                    .registration(background.tasks, background.tasks_drain, signals.installation())
                                    .critical(),
                                registration_owner
                                    .worker
                                    .clone()
                                    .registration(background.tasks, background.tasks_drain, signals.handle(Work::EnrollmentRecovery))
                                    .critical(),
                            ]);
                            let relay = crate::assembly::task_relay::registration(
                                automation.work.clone(),
                                control.clone(),
                                script_work.clone(),
                                collection_work.clone(),
                                software_owner.service.clone(),
                                registration_owner.native.clone(),
                                registration_owner.worker.clone(),
                                access_execution.worker.clone(),
                                credential_execution.as_ref().map(|v| v.worker.clone()).unwrap_or_default(),
                                credential_execution.as_ref().map(|v| v.native.clone()),
                                background.commands.concurrency(),
                                probe.storage(),
                                signals.handle(Work::CommandRelay),
                            ).critical();
                            (tasks, relay)
                        };
                        let windows_business = Arc::new(crate::assembly::windows_business::WindowsBusiness(
                            control.clone(),
                            configuration.clone(),
                            collections.clone(),
                            software_owner.service.clone(),
                            registration_owner.native.clone(),
                        ));
                        let protocol_runtime = commands.runtime.clone();
                        let product_origin = compiled.config.product_origin.clone();
                        let mut app = crate::assembly::from_compiled(
                            compiled,
                            crate::assembly::AssemblyDependencies {
                                baseline_wake: notifications.signals.handle(crate::worker_wake::Work::Baseline),
                                da:da.clone(),
                                script_work,
                                collection_work,
                                telemetry: telemetry.clone(),
                                certificate_archive: archive.clone(),
                                timeline: timeline.clone(),
                                associations: associations.clone(),
                                audit_store: audit_store.clone(),
                                clock: Arc::new(crate::clock::SystemClock),
                                monotonic,
                                access: access.clone(),
                                runtime: runtime.clone(),
groups: inventory_services.groups.clone(), policy_application: policy_application.clone(), policies: policies.clone(),
publications: publications.clone(), software_catalog: software_catalog.clone(), content_access: content_access.clone(),
cursor_key: cursor_key.clone(), scope_group_health: scope_group_health.clone(), asset_input_health: asset_input_health.clone(), resources: resource_catalog.clone(), events: events.clone(),
                                scopes: scopes.clone(),
                                assets: inventory_services.assets,
                                compliance: inventory_services.compliance,
                                access_execution: access_execution.clone(),
                                credential_execution: credential_execution.clone(),
                                credential_receipts: credential_receipts.clone(),
                                software: software_owner.clone(),
                                registration: registration_owner.clone(),
                                read_pool: commands.read_pool.clone(),
                                configuration: configuration.clone(),
                                signing: signing.clone(),
                                task_trust: task_trust.clone(),
                                channels: channels.clone(),
                                providers: providers.clone(),
                                bootstrap: bootstrap.clone(),
                                control: control.clone(),
                                self_service: self_service.clone(),
                                scripts: scripts.clone(),
                                collections: collections.clone(),
                                task_reads: task_reads.clone(),
                                queries: queries.clone(),
                                protection: protection.clone(),
                                content: content.clone(),
                                protocol_runtime: commands.runtime.clone(),
                                identity,
                            },
                        )
                        .await
                        .map_err(assembly_error)?;
                        startup.stage_resource(DynManagedResource::new_box(
                            crate::assembly::webhooks::Resource(app.webhooks.clone()),
                        ));
                        let native_listeners = app
                            .listeners
                            .iter()
                            .any(|(kind, _)| kind.windows_retention());
                        app.browser = crate::native::gateway::router(
                            app.browser,
                            std::mem::take(&mut app.listeners),
                            product_origin,
                        );
                        let listener =
                            tokio::net::TcpListener::bind(listen).await.map_err(|e| {
                                ProcessError::Io {
                                    stage: "startup.listener_bind",
                                    kind: e.kind(),
                                }
                            })?;
                        listener_receipt(&listener, &mut std::io::stdout().lock()).map_err(
                            |e| ProcessError::Io {
                                stage: "startup.listener_receipt",
                                kind: e.kind(),
                            },
                        )?;
                        Ok::<_, ProcessError>((
                            listener,
                            app,
                            native_listeners,
                            audit_store,
                            access,
                            runtime,
                            protocol_runtime,
                            windows_business,
                            protection,
                            task_registrations,
                            automation,
                                group_work,
                            scope_work,
                            query_work,
                            compliance_work,
                            scope_delivery,
                        asset_delivery,
                            publications.clone(),
                            archive,
                            device_work,
                            notifications,
                            gateway,
                        ))
                    })
                    .await
                    .map_err(|_| ProcessError::Stage {
                        stage: "startup",
                        kind: "total deadline exceeded",
                    })??;
                    let signals = notifications.signals.clone();
                    let mut launch = startup.commit();
                    launch.stage_deferred_task_with_token(app.baseline);
                    launch.stage_deferred_task_with_token(
                        crate::assembly::webhooks::registration(app.webhooks.clone()).critical(),
                    );
                    launch.stage_task_with_token(
                        crate::device_pki::registration("device-pki-maintenance",app.pki.clone()).critical(),
                    );

                    launch.stage_task_with_token(notifications.registration().critical());
                    if app.apple.is_some() {
                        launch.stage_task_with_token(
                            rss_mdm_apple_channel::ade::registration(
                                app.apple_control.clone(),
                                signals.handle(crate::worker_wake::Work::Apple),
                            )
                            .critical(),
                        );
                    }
                    if app.apple.is_some(){launch.stage_task_with_token(rss_mdm_apple_channel::push::registration(app.apple_control.clone(),signals.handle(crate::worker_wake::Work::Apple)).critical());}
                    launch.stage_deferred_task_with_token(publications.registration().critical());
                    launch.stage_deferred_task_with_token(
                        device_work.registration(background.device, background.device_drain, signals.handle(crate::worker_wake::Work::Devices)),
                    );
                    launch.stage_deferred_task_with_token(archive.registration().critical());
                    for task in task_registrations { launch.stage_deferred_task_with_token(task); }
                    launch.stage_task_with_token(command_relay);
                    launch.stage_task_with_token(scope_delivery.registration(signals.handle(crate::worker_wake::Work::GroupEvents)).critical());
                    launch.stage_task_with_token(asset_delivery.registration(signals.handle(crate::worker_wake::Work::AssetInputs)).critical());
                    launch.stage_deferred_task_with_token(
                        query_work
                            .registration(background.inventory, background.planning_drain, signals.handle(crate::worker_wake::Work::AssetQueries))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        compliance_work
                            .registration(background.compliance, background.planning_drain, signals.handle(crate::worker_wake::Work::Compliance))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        group_work
                            .registration(background.group, background.planning_drain, signals.handle(crate::worker_wake::Work::Groups))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        scope_work
                            .registration(background.scope, background.planning_drain, signals.handle(crate::worker_wake::Work::Scopes))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        automation.registration(background.policy_events, background.policy, background.policy_drain, signals.policy()).critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        runtime
                            .registration(signals.handle(crate::worker_wake::Work::Inventory))
                            .critical(),
                    );
                    if app.windows.is_some(){launch.stage_task_with_token(rss_mdm_windows_channel::push::registration(app.windows_control.clone(),windows_business.clone(),signals.handle(crate::worker_wake::Work::WindowsPush)).critical());}
                    if native_listeners {
                        launch.stage_task_with_token(
                            rss_mdm_windows_channel::retention::registration(
                                app.windows_control.clone(),
                                signals.handle(crate::worker_wake::Work::Windows),
                            )
                            .critical(),
                        );
                    }
                    launch.stage_task_with_token(
                        rss_axum::serve_http1_registration(
                            listener,
                            app.browser.layer(axum::middleware::from_fn_with_state(
                                admission.clone(),
                                crate::native::admission::lifecycle,
                            )),
                            crate::native::gateway::Transport { gateway },
                            "mdm-http",
                            http.listener,
                        )
                        .critical(),
                    );
                    // Root cancellation stops telemetry admission alongside HTTP. Its task
                    // drains concurrently while the final request gate waits for admitted work.
                    if let Some(service) = app.telemetry.clone() {
                        launch.stage_task_with_token(
                            crate::telemetry::registration(service, protocol_runtime.clone())
                                .critical(),
                        );
                    }
                    let (control, gate) = launch
                        .finish_with_admission("native-accepted-requests", http.admission_drain);
                    #[cfg(test)]
                    let _ = INSTALLED_ADMISSION.try_with(|slot| slot.set(gate.clone()));
                    admission.set(gate).map_err(|_| ProcessError::Stage {
                        stage: "startup.admission",
                        kind: "admission already bound",
                    })?;
                    control.open().map_err(|_| ProcessError::Stage {
                        stage: "startup.admission",
                        kind: "admission could not open",
                    })?;
                    std::future::pending().await
                })
            },
            stop,
        )
        .await
        .map_err(|_| ProcessError::at("lifecycle.drive", Error::Unavailable(Failure::Runtime)))?;
    let clean = outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean());
    if let Ok(receipt) = outcome.shutdown() {
        for failure in receipt.failures() {
            use rss_runtime::ShutdownFailureKind as K;
            let kind = match failure.kind {
                K::Failed(_) => "failed",
                K::TimedOut(_) => "timed_out",
                K::Panicked => "panicked",
                K::Cancelled => "cancelled",
                K::TaskUnknown => "task_unknown",
                K::DeadlineExceeded => "deadline_exceeded",
                K::BudgetExhausted => "budget_exhausted",
            };
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_shutdown_failure","resource":failure.name,"kind":kind})
            );
        }
    }
    finish(outcome.exit(), clean)
}
fn assembly_error(error: Error) -> ProcessError {
    let stage = match error {
        Error::Configuration(ConfigIssue::EnrollmentCa) => "startup.windows_ca",
        Error::Configuration(ConfigIssue::ProtocolKey) => "startup.protocol_key",
        Error::Configuration(ConfigIssue::NativeTls) => "startup.native_tls",
        Error::Configuration(ConfigIssue::WindowsListeners) => "startup.windows_listeners",
        _ => "startup.identity",
    };
    ProcessError::at(stage, error)
}
fn finish(
    exit: &ScopeExit<(), ProcessError, std::io::Error>,
    clean: bool,
) -> Result<(), ProcessError> {
    match exit {
        ScopeExit::CriticalTaskExited(exit) => Err(ProcessError::CriticalTask {
            task: exit.name().into(),
            reason: exit.reason(),
            cleanup_failed: !clean,
        }),
        ScopeExit::Completed(Err(error)) => Err(error.clone()),
        _ if !clean => Err(ProcessError::Stage {
            stage: "shutdown",
            kind: "resource drain failed",
        }),
        ScopeExit::StopRequested(Ok(())) => Ok(()),
        ScopeExit::StopRequested(Err(e)) => Err(ProcessError::Io {
            stage: "shutdown.signal",
            kind: e.kind(),
        }),
        _ => Err(ProcessError::Stage {
            stage: "lifecycle",
            kind: "scope terminated",
        }),
    }
}
// Report the address of the listener we still own, including OS-assigned ports.
// ref: tokio net/tcp/listener.rs (bind port 0 + local_addr).
fn listener_receipt(
    listener: &tokio::net::TcpListener,
    output: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(
        output,
        "{}",
        serde_json::json!({"event":"listener-bound", "address":listener.local_addr()?.to_string()})
    )?;
    output.flush()
}
pub async fn signal() -> Result<(), std::io::Error> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {r=tokio::signal::ctrl_c()=>r,_=term.recv()=>Ok(())}
}

#[cfg(test)]
#[path = "../tests/lifecycle/unit.rs"]
mod tests;

struct AccessTransactionResource(Arc<rss_transactional_messaging_postgres::PgRuntime>);
impl ManagedResource for AccessTransactionResource {
    fn name(&self) -> &str {
        "audit-source-runtime"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}

/// Initialization retries share RSS task ownership and the original durable receipts.
pub(crate) fn baseline_registration(
    state: Arc<crate::administration::baseline::Service>,
    tenants: Option<Arc<crate::administration::tenants::service::Service>>,
    wake: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("tenant-baseline", Duration::from_secs(20));
    task.into_registration(move |cancel| async move {
        let Some(tenants) = tenants else {
            cancel.cancelled().await;
            return Ok(());
        };
        let idle = crate::worker_wake::RECOVERY;
        rss_mdm_work_page::run(
            std::num::NonZeroUsize::new(2).unwrap(),
            idle,
            &cancel,
            &wake,
            |after| {
                let tenants = tenants.clone();
                async move {
                    tenants
                        .pending_initializations(after)
                        .await
                        .map_err(|error| eprintln!("baseline discovery failed: {error}"))
                }
            },
            |id| {
                let state = state.clone();
                let tenants = tenants.clone();
                let stop = cancel.clone();
                async move {
                    let tenant =
                        rss_request_context::TenantId::parse(&id.to_string()).map_err(|_| ())?;
                    let cutoff = rss_request_context::Deadline::from_timeout(
                        &RuntimeTimer,
                        Duration::from_secs(120),
                    )
                    .expect("fixed initialization budget");
                    let (binding, steps) =
                        crate::administration::baseline::resume(&state, tenant, &stop, cutoff)
                            .await
                            .map_err(|error| {
                                eprintln!("baseline initialization for {tenant} blocked: {error}")
                            })?;
                    if let Some(binding) = binding {
                        tenants
                            .complete_initialization(binding, cutoff)
                            .await
                            .map_err(|error| {
                                eprintln!("baseline receipt for {tenant} unconfirmed: {error}")
                            })?;
                    }
                    Ok(if steps > 0 { Duration::ZERO } else { idle })
                }
            },
            |_| {},
        )
        .await;
        Ok(())
    })
}

pub(crate) struct TenantResource(pub Arc<crate::administration::tenants::service::Service>);
impl rss_runtime::ManagedResource for TenantResource {
    fn name(&self) -> &str {
        "tenant-administration"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
