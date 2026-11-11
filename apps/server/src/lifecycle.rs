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
// Preparation includes five seconds of TLS and two seconds of failure audit.
// All three listeners use the same RSS owner and finite protocol budgets.
pub(crate) fn http_policy() -> rss_axum::Http1ServePolicy {
    rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            128,
            Duration::from_secs(8),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("constant listener budgets are valid"),
        Duration::from_secs(10),
        64,
        32768,
    )
    .expect("constant HTTP/1 limits are valid")
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
    let admission = Arc::new(std::sync::OnceLock::new());
    let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(60)).map_err(|_| {
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
                        audit_store,
                        access,
                        tenant,
                        runtime,
                        protocol_runtime, windows_business, protection, task_registrations,
                        automation,
                        group_work,
                        scope_work,
                        query_work,
                        compliance_work,
                        scope_delivery,
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
                            .claim_tenant_use(&compiled.config)
                            .await
                            .map_err(|error| ProcessError::at("startup.tenant_binding", error))?;
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
                            rss_request_context::TenantId::parse(
                                &compiled.config.identity.tenant_id,
                            )
                            .map_err(|_| {
                                ProcessError::at(
                                    "startup.notification_tenant",
                                    crate::Error::Malformed,
                                )
                            })?,
                        );
                        startup.stage_resource(DynManagedResource::new_box(notifications.clone()));
                        use crate::inventory_runtime::{
                            Clock, InventoryRuntime, ObservationResource, ProjectionResource,
                        };
                        let clock = Clock::new(monotonic.clone());
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
                            rss_projection::Control::new(&clock, clock.cutoff(), &startup_cancel);
                        let projection = ProjectionResource::open(
                            runtime_options,
                            clock.clone(),
                            &startup_control,
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.projection", e.into()))?;
                        let projection_store = projection.store.clone();
                        startup.stage_resource(DynManagedResource::new_box(projection));
                        let audit_tenant = rss_request_context::TenantId::parse(
                            &compiled.config.identity.tenant_id,
                        )
                        .map_err(|_| assembly_error(Error::Configuration(ConfigIssue::Tenant)))?;
                        let management_tenant = crate::identity::management_tenant(
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
                        let mut audit_tenants =
                            vec![(audit_tenant, compiled.config.storage_binding.epoch)];
                        if management_tenant != audit_tenant {
                            audit_tenants.push((
                                management_tenant,
                                rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH,
                            ));
                        }
                        let source_runtime = crate::identity::open_runtime(
                            &compiled.config.access_database,
                            &compiled.config.storage_binding.target,
                            &compiled.config.storage_binding.lineage,
                            &audit_tenants,
            compiled.config.background.access_connections(),
        )
                        .await
                        .map_err(|e| ProcessError::at("startup.access_transaction", e))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            AccessTransactionResource(source_runtime.clone()),
                        ));
                        let audit_store = access
                            .audit_store(&compiled.config.audit, source_runtime.clone(), audit_tenant)
                            .await
                            .map_err(|e| ProcessError::at("startup.audit", e))?;
                        let runtime = Arc::new(InventoryRuntime::new(
                            observation_store,
                            projection_store,
                            access.inventory(),
                            audit_store.clone(),
                            rss_request_context::TenantId::parse(
                                &compiled.config.identity.tenant_id,
                            )
                            .map_err(|_| {
                                assembly_error(Error::Configuration(ConfigIssue::Tenant))
                            })?,
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
                        let inventory_tenant = rss_request_context::TenantId::parse(
                            &compiled.config.identity.tenant_id,
                        )
                        .map_err(|_| assembly_error(Error::Malformed))?;
let application_clock:Arc<dyn crate::clock::Clock>=Arc::new(crate::clock::SystemClock);
let cursor_key=crate::cursor_keys::load(&source_runtime,inventory_tenant).await.map_err(assembly_error)?;
let inventory_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.inventory),&compiled.config.storage_binding,inventory_tenant,compiled.config.background.inventory_connections(),audit_store.clone(),"inventory-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let scope_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.scope),&compiled.config.storage_binding,inventory_tenant,compiled.config.background.scope_connections(),audit_store.clone(),"scope-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let policy_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Runtime(&compiled.config.business_databases.policy),&compiled.config.storage_binding,inventory_tenant,compiled.config.background.policy_connections(),audit_store.clone(),"policy-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.resource),&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"resource-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let software_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.software),&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"software-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let inventory_services=crate::assembly::inventory::Services::new(runtime.clone(),access.archive_pool(),inventory_owner.runtime.clone(),inventory_owner.audit.clone(),inventory_tenant,&cursor_key,application_clock.clone()).await.map_err(assembly_error)?;
let policy_application=crate::assembly::policy::application(&policy_owner,inventory_tenant,&cursor_key,application_clock.clone(),protection.clone(),content.clone()).await.map_err(assembly_error)?;
let publications=crate::assembly::publication::open(&compiled.config.publication,&compiled.config.storage_binding,&software_owner,inventory_tenant,&cursor_key,application_clock.clone(),content.clone(),|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_catalog=crate::assembly::resource::catalog(resource_owner.audit.clone(),resource_owner.runtime.clone(),inventory_tenant,application_clock.clone(),cursor_key.clone()).await.map_err(assembly_error)?;
let software_catalog=crate::assembly::software::catalog(&software_owner,inventory_tenant,&cursor_key,application_clock.clone(),content.clone()).await.map_err(assembly_error)?;
let scope_group_health=Arc::new(crate::scope_group_changes::Health::default());
                        let identity = crate::identity::Identity::connect(
                            &compiled.config,
                            compiled.identity_management.clone(),
                            if compiled.config.device_access.is_some() {Some(crate::assembly::device_access::identity_platform(&compiled.config).await.map_err(assembly_error)?)} else {None},
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(|error| ProcessError::at("startup.identity", error))?;
                        let da=if compiled.config.device_access.is_some() {Some(Arc::new(crate::assembly::device_access::open(&compiled.config,&identity,&access.authorization_store(),protection.clone(),&cursor_key,|resource|startup.stage_resource(resource)).await.map_err(assembly_error)?))} else {None};
                        if let Some(da)=&da {
                        if let Some(pki)=&da.pki {startup.stage_task_with_token(crate::device_pki::registration("da-device-pki-maintenance",pki.clone()));}
                        if let Some(listener)=crate::assembly::device_access::listener(&compiled.config,&identity,da).await.map_err(assembly_error)? {startup.stage_task_with_token(listener.critical());}
                        }
                        let audit_budget =
                            rss_mdm_audit_integration::budget::AuditBudget::with_cancellation(
                                Duration::from_secs(5),
                                startup_cancel.clone(),
                            );
                        let audit_control = audit_budget.control();
                        for admitted_tenant in [identity.tenant, identity.management_tenant] {
                            audit_store
                                .validate_tenant(admitted_tenant, &audit_control)
                                .await
                                .map_err(|error| ProcessError::at("startup.audit", error.into()))?;
                        }
let content_access=if let Some(content)=&content {
let content_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.content),&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"content-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
Some(crate::assembly::content::access(&content_owner,&identity,access.authorization_store(),content.clone(),application_clock.clone()).await.map_err(assembly_error)?)
}else{None};
                        let config = &compiled.config;
                        let commands = crate::assembly::host_storage::Storage::open(
                            config,
                            audit_store.clone(),
                            &protection,
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let channels = Arc::new(crate::channel_status::Channels::new(config));
                        let providers =
                            crate::device_pki::prepare(&config.device_pki, &channels).map_err(assembly_error)?;
                        let (signing, task_trust) = crate::assembly::task_trust::signing(
                            config,
                            commands.tenant,
                            protection.clone(),
                            audit_store.clone(),
                            &channels,
                        )
                        .await
                        .map_err(assembly_error)?;
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
                                identity.tenant,
                            ),
                        );
                        let (scripts, script_work) =
                            crate::assembly::script::assemble(config, &commands, source.clone(), sessions.clone())
                                .await
                                .map_err(assembly_error)?;
                        let (collections, collection_work) = crate::assembly::collection::assemble(
                            config,
                            &commands,
                            source.clone(),
                            protection.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let configuration = crate::assembly::policy::configuration(
                            commands.runtime.clone(),
                            commands.audit.clone(),
                            commands.tenant,
                            protection.clone(),
                            content.clone(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let software = Arc::new(rss_mdm_software_service::preparation::Preparation::new(
                            rss_mdm_software_service::catalog::Reader::new(commands.tenant),
                            publications
                                .services
                                .clone()
                                .into_iter()
                                .map(|(name, service)| (name, Arc::new(service.exports())))
                                .collect(),
                        ));
                        let software_source = Arc::new(crate::assembly::software_sources::Source(source.clone()));
                        let software_inventory = Arc::new(crate::assembly::software_sources::Inventory);
                        let software_lifecycle = Arc::new(crate::assembly::software_sources::Lifecycle);
                        let authority = Arc::new(
                            rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
                                tenant: commands.tenant,
                                instance: config.identity.instance_id.clone(),
                                source: software_source.clone(),
                                inventory: software_inventory.clone(),
                                lifecycle: software_lifecycle.clone(),
                                protection: protection.clone(),
                                software_distribution: config.software_distribution,
                            },
                        );
                        let registration_owner = crate::assembly::registration::assemble(
                            config,
                            commands.runtime.clone(),
                            commands.tenant,
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
                        let access_execution = Box::pin(crate::assembly::access_execution::assemble(
                            commands.runtime.clone(),
                            commands.tenant,
                            commands.audit.clone(),
                            recovery_materials.clone(),
                            commands.reconcile.clone(),
                            commands.worker_budget.clone(),
                            config.background.device_concurrency,
                            config.device_access.is_some(),
                        ))
                        .await
                        .map_err(assembly_error)?;
                        let credential_execution = if let Some(credentials) = recovery_materials.clone() {
                            Some(
                                Box::pin(crate::assembly::credential_execution::assemble(
                                    config,
                                    commands.runtime.clone(),
                                    commands.tenant,
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
                        let software_owner = crate::assembly::software::assemble(
                            config,
                            commands.runtime.clone(),
                            commands.tenant,
                            commands.audit.clone(),
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
                            commands.tenant,
                            commands.audit.clone(),
                            config.identity.instance_id.clone(),
                            &cursor_key,
                        ));
                        let task_reads = crate::assembly::task_reads::assemble(
                            config,
                            &commands,
                            protection.clone(),
                            content.clone(),
                            signing.loaded_key().is_some(),
                            credential_execution.is_some(),
                            source,
                            configuration.clone(),
                            software_owner.queries.clone(),
                            registration_owner.materials.clone(),
                            queries.clone(),
                        );
                        let scope_editor = Box::pin(crate::scopes::editor(policy_owner.runtime.clone(), inventory_tenant, application_clock.clone(), policy_owner.audit.clone(), cursor_key.clone(), access.archive_pool())).await.map_err(assembly_error)?;
                        let policies = crate::assembly::policy::management(
                            scope_editor,
                            &policy_application,
                            Arc::new(rss_mdm_software_service::deployment::Inputs::bind(
                                policy_owner.runtime.clone(),
                                policy_application.tenant,
                                software_owner.materials.inputs.clone(),
                            )),
                            compiled.config.enrollment_entries.clone(),
                            &cursor_key,
                            content.clone(),
                            protection.clone(),
                            compiled.config.software_distribution.mdm_enabled,
                            signing.loaded_key().is_some(),
                            credential_execution.is_some(),
                        )
                        .await
                        .map_err(assembly_error)?;
                        let events = Box::pin(crate::assembly::policy::events(
                            policy_application.clone(),
                            materials.clone(),
                            software_owner.materials.clone(),
                            registration_owner.materials.clone(),
                            credential_execution.as_ref().map(|v| v.materials.clone()).unwrap_or_default(),
                        ))
                        .await
                        .map_err(assembly_error)?;
                        let telemetry = match &compiled.config.telemetry {
                            Some(config) => {
let telemetry_owner=crate::owner_storage::OwnerRuntime::open(crate::owner_storage::Messaging::Producer(&compiled.config.business_databases.telemetry),&compiled.config.storage_binding,inventory_tenant,compiled.config.background.telemetry_control_connections(),audit_store.clone(),"telemetry-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let dependencies=rss_mdm_telemetry_service::PolicyDependencies {
 agent_facts: Arc::new(crate::assembly::agent_facts::AgentFacts),
                    read_pool: commands.read_pool.clone(),
clock: Arc::new(crate::lifecycle::RuntimeTimer),
 audit_store:telemetry_owner.audit.clone(),policies:Arc::new(rss_mdm_policy_service::telemetry::Reader::new(rss_mdm_install_support::StorageProfile::Mdm, telemetry_owner.runtime.clone(),inventory_tenant,Arc::new(rss_mdm_device_service::planning::PlanningObjects))),objects:Arc::new(rss_mdm_device_service::planning::PlanningObjects),
};
                                let service = config
                                    .open(inventory_tenant, telemetry_owner.runtime, dependencies, signing.clone())
                                    .await
                                    .map_err(|e| ProcessError::at("startup.telemetry", e))?;
                                startup.stage_resource(DynManagedResource::new_box(
                                    crate::telemetry::Resource(service.clone()),
                                ));
                                Some(service)
                            }
                            None => None,
                        };
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
                                policy_application.clone(),
                                events.clone(),
                                scheduler.store.clone(),
                            ),compiled.config.background.device_concurrency);
                        let scopes = crate::scopes::open(
                            scope_owner.runtime.clone(),
                            identity.tenant,
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
                        let scope_delivery = crate::scope_group_changes::Delivery::open(
                            &compiled.config,
                            protection.clone(),
                            scope_group_health.clone(),
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.scope_group_delivery", e))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            crate::scope_group_changes::Resource(scope_delivery.clone()),
                        ));
                        let listen = compiled.config.listen;
                        let tenant = compiled.config.identity.tenant_id.clone();
                        let gateway = compiled.config.trusted_gateway;
                        let associations = Arc::new(
                            rss_mdm_device_service::Associations::new(
                                audit_store.clone(),
                                identity.tenant,
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
                            associations.clone(),source_runtime.clone(),scheduler.store.clone(),
                            compiled.config.background.device_concurrency,
                            rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(8)),
                        ).await.map_err(|_|ProcessError::at("startup.device_worker",Error::Unavailable(Failure::Database)))?);
                        let timeline = access
                            .timeline(audit_store.clone(), identity.tenant, &cursor_key)
                            .map_err(|e| ProcessError::at("startup.timeline", e))?;
                        let archive = crate::certificate_archive::assemble(
                            &access,
                            audit_store.clone(),
                            Arc::new(crate::clock::SystemClock),
                        );
                        let task_registrations = {
                            use crate::worker_wake::Work;
                            let signals = &notifications.signals;
                            let mut tasks = vec![
                                access_execution
                                    .worker
                                    .clone()
                                    .registration(signals.handle(Work::AccessRecovery))
                                    .critical(),
                            ];
                            if let Some(credentials) = &credential_execution {
                                for maintenance in &credentials.maintenance {tasks.push(maintenance.clone().registration().critical());}
                                for worker in &credentials.worker {tasks.push(worker.clone().registration(signals.handle(Work::CredentialRecovery)).critical());}
                                tasks.push(
                                    credentials
                                        .native
                                        .clone()
                                        .registration(Arc::new(
                                            rss_mdm_recovery_credentials::native::worker_wake::Signals::from_handles([
                                                signals.handle(Work::CommandRelay),
                                                signals.handle(Work::CredentialNativeRecovery),
                                            ]),
                                        ))
                                        .critical(),
                                );
                            }
                            tasks.extend([
                                control.clone().registration(signals.execution()).critical(),
                                script_work
                                    .clone()
                                    .registration(signals.handle(Work::ScriptRecovery))
                                    .critical(),
                                collection_work
                                    .clone()
                                    .registration(signals.handle(Work::CollectionRecovery))
                                    .critical(),
                                software_owner
                                    .service
                                    .clone()
                                    .registration(signals.software())
                                    .critical(),
                                registration_owner
                                    .native
                                    .clone()
                                    .registration(signals.installation())
                                    .critical(),
                                registration_owner
                                    .worker
                                    .clone()
                                    .registration(signals.handle(Work::EnrollmentRecovery))
                                    .critical(),
                                crate::assembly::task_relay::registration(
                                    control.clone(),
                                    script_work.clone(),
                                    collection_work.clone(),
                                    software_owner.service.clone(),
                                    registration_owner.native.clone(),
                                    registration_owner.worker.clone(),
                                    access_execution.worker.clone(),
                                    credential_execution.as_ref().map(|v| v.worker.clone()).unwrap_or_default(),
                                    credential_execution.as_ref().map(|v| v.native.clone()),
                                    signals.handle(Work::CommandRelay),
                                )
                                .critical(),
                            ]);
                            tasks
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
cursor_key: cursor_key.clone(), scope_group_health: scope_group_health.clone(), resources: resource_catalog.clone(), events: events.clone(),
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
                        let agent_enrollment = app.agent_enrollment.clone();
                        app.browser = crate::native::gateway::router(
                            app.browser,
                            std::mem::take(&mut app.listeners),
                            product_origin,
                            agent_enrollment,
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
                            tenant,
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
                    if let Some(service) = app.telemetry.clone() {
                        launch.stage_deferred_task_with_token(
                            crate::telemetry::registration(service, protocol_runtime.clone())
                                .critical(),
                        );
                    }
                    launch.stage_deferred_task_with_token(
                        crate::assembly::webhooks::registration(app.webhooks.clone()).critical(),
                    );
                    launch.stage_task_with_token(
                        crate::device_pki::registration("device-pki-maintenance",app.pki.clone()).critical(),
                    );
                    if let Some(agent_pki) = app.agent_pki.clone() {
                        launch.stage_task_with_token(agent_pki.registration().critical());
                    }
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
                    if let Some(apple) = app.apple {
                        launch.stage_task_with_token(
                            rss_mdm_apple_channel::push::registration(
                                apple.channel.clone(),
                                app.apple_control.delivery.clone(),
                                access.apple_store(),
                                audit_store.clone(),
                                tenant.clone(),
                                signals.handle(crate::worker_wake::Work::Apple),
                            )
                            .critical(),
                        );
                    }
                    launch.stage_deferred_task_with_token(publications.registration().critical());
                    launch.stage_deferred_task_with_token(
                        device_work.registration(signals.handle(crate::worker_wake::Work::Devices)),
                    );
                    launch.stage_deferred_task_with_token(archive.registration().critical());
                    for task in task_registrations { launch.stage_deferred_task_with_token(task); }
                    launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
                    launch.stage_deferred_task_with_token(
                        query_work
                            .registration(signals.handle(crate::worker_wake::Work::AssetQueries))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        compliance_work
                            .registration(signals.handle(crate::worker_wake::Work::Compliance))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        group_work
                            .registration(signals.handle(crate::worker_wake::Work::Groups))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        scope_work
                            .registration(signals.handle(crate::worker_wake::Work::Scopes))
                            .critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        automation.registration(signals.policy()).critical(),
                    );
                    launch.stage_deferred_task_with_token(
                        runtime
                            .registration(signals.handle(crate::worker_wake::Work::Inventory))
                            .critical(),
                    );
                    if let Some(windows) = app.windows.as_ref().filter(|w| w.channel.push.is_some())
                    {
                        launch.stage_task_with_token(
                            rss_mdm_windows_channel::push::registration(
                                windows.channel.clone(),
                                windows_business.clone(),
                                protection.clone(),
                                access.windows_store(),
                                audit_store.clone(),
                                tenant.clone(),
                                signals.handle(crate::worker_wake::Work::WindowsPush),
                            )
                            .critical(),
                        );
                    }
                    if native_listeners {
                        launch.stage_task_with_token(
                            rss_mdm_windows_channel::retention::registration(
                                access.windows_store(),
                                audit_store.clone(),
                                tenant.clone(),
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
                            http_policy(),
                        )
                        .critical(),
                    );
                    let (control, gate) = launch
                        .finish_with_admission("native-accepted-requests", Duration::from_secs(35));
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
    state: crate::administration::baseline::Service,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) =
        rss_runtime::ManagedTask::prepare("tenant-baseline", std::time::Duration::from_secs(10));
    task.into_registration(move|cancel|async move {
        let mut previous=None;
        loop {
            let result=tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                result=tokio::time::timeout(std::time::Duration::from_secs(120),crate::administration::baseline::resume(&state))=>result,
            };
            let failure=match result {Ok(Ok(()))=>None,Ok(Err(error))=>Some(error.to_string()),Err(_)=>Some("initialization outcome unknown".into())};
            if failure!=previous {
                if let Some(reason)=&failure {eprintln!("baseline initialization blocked: {reason}");}
                previous=failure;
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        }
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
