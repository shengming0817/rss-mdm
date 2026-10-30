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
        512 * 1024,
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
                        execution,
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
                            compiled.config.runtime_database.options().map_err(|e| {
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
                        let content = crate::assembly::execution::open_content(
                            &compiled.config,
                            protection.clone(),
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.content", e))?;
                        if let Some(content) = &content {
                            startup.stage_resource(DynManagedResource::new_box(
                                crate::assembly::execution::ContentResource(content.clone()),
                            ));
                        }
                        let inventory_tenant = rss_request_context::TenantId::parse(
                            &compiled.config.identity.tenant_id,
                        )
                        .map_err(|_| assembly_error(Error::Malformed))?;
let application_clock:Arc<dyn crate::clock::Clock>=Arc::new(crate::clock::SystemClock);
let cursor_key=crate::cursor_keys::load(&source_runtime,inventory_tenant).await.map_err(assembly_error)?;
let inventory_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.inventory,&compiled.config.storage_binding,inventory_tenant,compiled.config.background.inventory_connections(),audit_store.clone(),"inventory-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let scope_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.scope,&compiled.config.storage_binding,inventory_tenant,compiled.config.background.scope_connections(),audit_store.clone(),"scope-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let policy_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.policy,&compiled.config.storage_binding,inventory_tenant,compiled.config.background.policy_connections(),audit_store.clone(),"policy-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.resource,&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"resource-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let software_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.software,&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"software-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let inventory_services=crate::assembly::inventory::Services::new(runtime.clone(),access.archive_pool(),inventory_owner.runtime.clone(),inventory_owner.audit.clone(),inventory_tenant,&cursor_key,application_clock.clone()).await.map_err(assembly_error)?;
let policy_application=crate::assembly::policy::application(&policy_owner,inventory_tenant,&cursor_key,application_clock.clone()).await.map_err(assembly_error)?;
let publications=crate::assembly::publication::open(&compiled.config.publication,&compiled.config.storage_binding,&software_owner,inventory_tenant,&cursor_key,application_clock.clone(),content.clone(),|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let resource_catalog=crate::assembly::resource::catalog(resource_owner.audit.clone(),resource_owner.runtime.clone(),inventory_tenant,application_clock.clone(),cursor_key.clone()).await.map_err(assembly_error)?;
let software_catalog=crate::assembly::software::catalog(&software_owner,inventory_tenant,&cursor_key,application_clock.clone(),content.clone()).await.map_err(assembly_error)?;
let scope_group_health=Arc::new(crate::scope_group_changes::Health::default());
                        let identity = crate::identity::Identity::connect(
                            &compiled.config,
                            compiled.identity_management.clone(),
                            Some(
                                crate::apple::identity_platform(&compiled.config)
                                    .await
                                    .map_err(assembly_error)?,
                            ),
                            |resource| startup.stage_resource(resource),
                        )
                        .await
                        .map_err(|error| ProcessError::at("startup.identity", error))?;
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
let content_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.content,&compiled.config.storage_binding,inventory_tenant,2,audit_store.clone(),"content-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
Some(crate::assembly::content::access(&content_owner,&identity,access.authorization_store(),content.clone(),application_clock.clone()).await.map_err(assembly_error)?)
}else{None};
                        let execution = crate::assembly::execution::open(
                            &compiled.config,
                            protection.clone(),
                            audit_store.clone(),
                            content.clone(),
                            publications.services.clone(),
                            rss_device_command_postgres::CommandClock::Postgres,
                            Arc::new(
                                rss_mdm_authorization_service::session::SessionAuthority::new(
                                    identity.authority.clone(),
                                    identity.tenant,
                                ),
                            ),
                            cursor_key.clone(),
                        )
                        .await
                        .map_err(|e| ProcessError::at("startup.execution", e))?;
                        startup.stage_resource(DynManagedResource::new_box(
                            rss_mdm_execution_service::Resource(execution.service.clone()),
                        ));
let policy_inputs=Arc::new(rss_mdm_execution_service::Inputs::bind(policy_owner.runtime.clone(),policy_application.tenant,execution.materials.inputs.clone()));
let policies=crate::assembly::policy::management(&policy_application,policy_inputs,&cursor_key).await.map_err(assembly_error)?;
let events=crate::assembly::policy::events(policy_application.clone(),execution.materials.clone()).await.map_err(assembly_error)?;
                        let telemetry = match &compiled.config.telemetry {
                            Some(config) => {
let telemetry_owner=crate::owner_storage::OwnerRuntime::open(&compiled.config.business_databases.telemetry,&compiled.config.storage_binding,inventory_tenant,compiled.config.background.telemetry_control_connections(),audit_store.clone(),"telemetry-runtime-postgres",|resource|{startup.stage_resource(DynManagedResource::new_box(resource));}).await.map_err(assembly_error)?;
let dependencies=rss_mdm_telemetry_service::PolicyDependencies {
                    query_reads: execution.queries.clone(),
 audit_store:telemetry_owner.audit.clone(),policies:Arc::new(rss_mdm_policy_service::telemetry::Reader::new(telemetry_owner.runtime.clone(),inventory_tenant,Arc::new(rss_mdm_device_service::planning::PlanningObjects))),objects:Arc::new(rss_mdm_device_service::planning::PlanningObjects),
};
                                let service = config
                                    .open(inventory_tenant, telemetry_owner.runtime, dependencies, execution.service.clone())
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
                            Arc::new(rss_mdm_inventory_service::groups::runtime::GroupWork::new(
                                inventory_services.groups.clone(),
                                scheduler.store.clone(),
                            ));
                        let query_work =
                            Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
                                inventory_services.assets.clone(),
                                scheduler.store.clone(),
                            ));
                        let compliance_work = Arc::new(
                            rss_mdm_inventory_service::compliance::runtime::ComplianceWork::new(
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
                            Arc::new(crate::registration_lifecycle::Bridge),compiled.config.background.device_concurrency,
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
                        let product_origin = compiled.config.product_origin.clone();
                        let mut app = crate::assembly::from_compiled(
                            compiled,
                            crate::assembly::AssemblyDependencies {
                                #[cfg(test)]
                                mount_channels: true,
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
                                execution: execution.clone(),
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
                            execution,
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
                            crate::telemetry::registration(service, execution.runtime.clone())
                                .critical(),
                        );
                    }
                    launch.stage_deferred_task_with_token(
                        crate::assembly::webhooks::registration(app.webhooks.clone()).critical(),
                    );
                    launch.stage_task_with_token(
                        crate::device_pki::registration(app.pki.clone()).critical(),
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
                                execution.service.clone(),
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
                    if let Some(maintenance) = execution.service.clone().credential_maintenance() {
                        launch.stage_deferred_task_with_token(maintenance);
                    }
                    launch.stage_deferred_task_with_token(
                        execution
                            .service
                            .clone()
                            .registration(signals.execution())
                            .critical(),
                    );
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
                                execution.service.clone(),
                                execution.protection.clone(),
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
