//! Product route and service assembly.
use crate::clock::Clock;
use crate::{ConfigIssue, Database};
use crate::{
    Error, authorization::identity_management::IdentityManagementPolicy,
    enrollment::credentials::Credentials, identity::Identity,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware::{self},
    response::{IntoResponse, Response},
    routing::get,
};
use rss_mdm_inventory_service::collection_service::CollectionService;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
pub(crate) struct Assembly {
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) content_writer: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub(crate) queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub(crate) inputs: Arc<rss_mdm_execution_service::Inputs>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    #[cfg(test)]
    pub(crate) execution_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Arc<Identity>,
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) collection: Arc<CollectionService>,
    pub(crate) inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: Option<Arc<crate::apple::Apple>>,
    pub(crate) windows: Option<Arc<crate::windows::Windows>>,
    pub(crate) access: Arc<Database>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
impl Assembly {
    pub(crate) fn apple(&self) -> Result<&Arc<crate::apple::Apple>, Error> {
        self.apple.as_ref().ok_or(Error::Unsupported)
    }
    pub(crate) fn windows(&self) -> Result<&Arc<crate::windows::Windows>, Error> {
        self.windows.as_ref().ok_or(Error::Unsupported)
    }
}

#[cfg(test)]
pub(crate) async fn application_fixture(
    config: crate::config::Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    access: Arc<Database>,
    identity: Option<Identity>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
) -> Result<
    (
        Router,
        crate::execution_assembly::Assembly,
        Arc<rss_transactional_messaging_postgres::PgRuntime>,
    ),
    Error,
> {
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.inventory(),
        rss_request_context::TenantId::parse(&config.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?,
        monotonic.clone(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let protection = config.native_protector()?;
    let content = crate::execution_assembly::open_content(&config, protection.clone())?;
    let planning = config
        .flow
        .open(
            audit_store.clone(),
            rss_request_context::TenantId::parse(&config.identity.tenant_id)
                .map_err(|_| Error::Malformed)?,
            clock.clone(),
            content.clone(),
            |_| {},
        )
        .await?;
    let execution = crate::execution_assembly::open(
        &config,
        protection,
        audit_store.clone(),
        content,
        planning.publications.services.clone(),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    let compiled = config.compile()?;
    let identity = match identity {
        Some(identity) => identity,
        None => {
            Identity::connect(
                &compiled.config,
                compiled.identity_management.clone(),
                |_| {},
            )
            .await?
        }
    };
    let timeline = access.timeline(audit_store.clone(), identity.tenant, &planning.cursor_key)?;
    timeline
        .initialize()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let plan_runtime = planning.runtime.clone();
    let execution_service = execution.clone();
    Ok((
        from_compiled(
            compiled,
            AssemblyDependencies {
                certificate_archive: crate::certificate_archive::assemble(
                    &access,
                    audit_store.clone(),
                    clock.clone(),
                ),
                timeline,
                audit_store,
                execution,
                clock,
                monotonic,
                access,
                runtime,
                flow: planning,
                identity,
            },
        )?
        .browser,
        execution_service,
        plan_runtime,
    ))
}
pub(crate) struct AssemblyDependencies {
    pub(crate) certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub(crate) timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) execution: crate::execution_assembly::Assembly,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<Database>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) flow: Arc<crate::flow::Flow>,
    pub(crate) identity: Identity,
}
pub(crate) fn from_compiled(
    compiled: crate::config::Compiled,
    dependencies: AssemblyDependencies,
) -> Result<crate::native::Routers, Error> {
    let crate::config::Compiled {
        config,
        identity_management,
    } = compiled;
    let AssemblyDependencies {
        certificate_archive,
        timeline,
        audit_store,
        execution,
        clock,
        monotonic,
        access,
        runtime,
        flow: planning,
        identity,
    } = dependencies;
    let crate::execution_assembly::Assembly {
        service: execution,
        inputs,
        queries,
        protection,
        content: content_writer,
        runtime: _execution_runtime,
    } = execution;
    let devices = Arc::new(crate::device::DeviceService::new(
        access.registration(),
        config.identity.tenant_id.clone(),
        audit_store.clone(),
    ));
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    let native_agent = config.agent_installation.clone();
    let windows = config
        .native_protocols
        .windows
        .map(|config| {
            crate::windows::Windows::load(
                config,
                clock.unix_seconds()?,
                native_agent
                    .identity(rss_mdm_policy::Platform::Windows)
                    .cloned(),
            )
            .map(Arc::new)
        })
        .transpose()?;
    let apple = config
        .native_protocols
        .apple
        .map(|config| {
            crate::apple::Apple::load(
                protection.clone(),
                config,
                clock.unix_seconds()?,
                native_agent
                    .identity(rss_mdm_policy::Platform::Macos)
                    .cloned(),
            )
            .map(Arc::new)
        })
        .transpose()?;
    let state = Arc::new(Assembly {
        certificate_archive,
        timeline,
        content_writer,
        inputs,
        queries,
        protection,
        #[cfg(test)]
        execution_runtime: _execution_runtime,
        audit_store,
        apple,
        execution,
        flow: planning,
        windows,
        access: access.clone(),
        identity: Arc::new(identity),
        credentials: Arc::new(Credentials::new(monotonic.clone(), 10000)),
        clock,
        identity_management,
        collection: Arc::new(CollectionService::new(
            devices.clone(),
            access.inventory(),
            runtime.clone(),
        )),
        inventory: runtime.clone(),
        devices,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    Ok(from_state(state, host, monotonic))
}

pub(crate) fn from_state(
    state: Arc<Assembly>,
    host: String,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> crate::native::Routers {
    let agent = Arc::new(crate::agent::HttpState {
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::AgentBuiltin,
        ),
        audit_store: state.audit_store.clone(),
        access: Arc::new(state.access.agent_store()),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                state.identity.authority.clone(),
                state.identity.tenant,
            ),
        ),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        collection: state.collection.clone(),
    });
    let apple_state = Arc::new(rss_mdm_apple_channel::HttpState {
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmApple,
        ),
        audit_store: state.audit_store.clone(),
        access: state.access.apple_store(),
        apple: state.apple.as_ref().map(|a| a.channel.clone()),
        clock: Arc::new(crate::clock::InventoryClock(state.clock.clone())),
        execution: state.execution.clone(),
        protection: state.protection.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                state.identity.authority.clone(),
                state.identity.tenant,
            ),
        ),
        requests: state.requests.clone(),
    });
    let windows_state = Arc::new(rss_mdm_windows_channel::HttpState {
        protection: state.protection.clone(),
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmWindows,
        ),
        audit_store: state.audit_store.clone(),
        access: state.access.windows_store(),
        clock: Arc::new(crate::clock::InventoryClock(state.clock.clone())),
        execution: state.execution.clone(),
        credentials: state.credentials.clone(),
        devices: state.devices.clone(),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                state.identity.authority.clone(),
                state.identity.tenant,
            ),
        ),
        requests: state.requests.clone(),
        windows: state.windows.as_ref().map(|w| w.channel.clone()),
    });
    let diagnostics = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
        execution: state.execution.clone(),
        inventory: state.inventory.clone(),
        identity_audit: state.identity.audit_readiness.clone(),
        apple: state.apple.clone(),
        clock: state.clock.clone(),
        planning: state.flow.planning.clone(),
        tenant: state.identity.tenant,
        instance: state.identity.instance.to_string(),
    });
    let authentication = state.identity.routes();
    let admission = Arc::new(tokio::sync::Semaphore::new(32));
    let management_boundary = rss_mdm_management_http::boundary::Envelope {
        admission: admission.clone(),
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let apple_boundary = rss_mdm_apple_channel::boundary::Envelope {
        admission: admission.clone(),
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let agent_boundary = rss_mdm_agent_channel::boundary::Envelope {
        admission,
        host: host.clone(),
        clock: monotonic.clone(),
        audit_store: state.audit_store.clone(),
        requests: state.requests.clone(),
        tenant: state.identity.tenant.to_string(),
    };
    let authentication =
        rss_mdm_management_http::authentication_routes(authentication, management_boundary.clone());
    let management = rss_mdm_management_http::router(
        rss_mdm_management_http::Services {
            certificate_archive: state.certificate_archive.clone(),
            timeline: state.timeline.clone(),
            diagnostics: diagnostics.clone(),
            identity: state.identity.browser(),
            authorization: state.access.authorization_store(),
            identity_management: state.identity_management.clone(),
            requests: state.requests.clone(),
            audit_store: state.audit_store.clone(),
            planning: state.flow.planning.clone(),
            groups: state.flow.groups.clone(),
            compliance: state.flow.compliance.clone(),
            execution: state.execution.clone(),
            queries: state.queries.clone(),
            policies: Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(
                state.flow.runtime.clone(),
                state.audit_store.clone(),
                state.identity.tenant,
                state.flow.planning.policy_store.clone(),
                rss_mdm_flow_service::resource_catalog::VersionReader::new(state.identity.tenant),
                state.inputs.clone(),
            )),
            assets: state.flow.assets.clone(),
            catalog: state.flow.catalog.clone(),
            publications: state.flow.publications.clone(),
            software_catalog: Arc::new(rss_mdm_software_service::management::catalog::Access {
                resources: state.flow.software_resources.clone(),
                clock: Arc::new(crate::clock::ContentClock(state.clock.clone())),
                runtime: state.flow.runtime.clone(),
                audit: state.audit_store.clone(),
                tenant: state.identity.tenant,
                catalog: rss_mdm_software_service::catalog::Catalog::new(
                    state.flow.runtime.clone(),
                    state.identity.tenant,
                    state.audit_store.clone(),
                ),
                content: state.content_writer.as_ref().map(|store| {
                    Arc::new(rss_mdm_content_service::software::SoftwareContent::new(
                        store.clone(),
                        Arc::new(crate::clock::ContentClock(state.clock.clone())),
                    ))
                }),
                imports: rss_mdm_software_service::management::catalog::ImportConfig {
                    sources: state
                        .content_writer
                        .as_ref()
                        .map(|s| s.config.imports.clone())
                        .unwrap_or_default(),
                    transfer_seconds: state
                        .content_writer
                        .as_ref()
                        .map_or(0, |s| s.config.transfer_seconds),
                },
            }),
            content: Arc::new(rss_mdm_content_service::service::Access {
                catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(
                    state.identity.tenant,
                )),
                runtime: state.flow.runtime.clone(),
                audit_store: state.audit_store.clone(),
                tenant: state.identity.tenant,
                content: state.content_writer.clone(),
                clock: Arc::new(crate::clock::ContentClock(state.clock.clone())),
            }),
            enrollment: Arc::new(
                rss_mdm_registration_service::enrollment::EnrollmentService::new(
                    state.access.registration(),
                    state.credentials.clone(),
                    state.audit_store.clone(),
                ),
            ),
            devices: state.devices.clone(),
            collection: state.collection.clone(),
            collection_intake: rss_mdm_inventory_service::apple_collection::Service {
                audit_store: state.audit_store.clone(),
                tenant: state.identity.tenant,
                participant: state.apple.as_ref().map(|_| {
                    Arc::new(rss_mdm_apple_channel::collection::Participant {
                        protection: state.protection.clone(),
                    })
                        as Arc<dyn rss_mdm_inventory_service::apple_collection::Participant>
                }),
            },
            windows: state.windows.is_some(),
            apple: state.apple.is_some(),
        },
        management_boundary,
    );
    let mut listeners = Vec::new();
    if let Some((enrollment, planning)) =
        crate::windows::routers(state.windows.as_deref(), windows_state, monotonic.clone())
    {
        listeners.push((
            crate::native::NativeListenerKind::WindowsEnrollment,
            enrollment,
        ));
        listeners.extend(
            planning
                .into_iter()
                .map(|router| (crate::native::NativeListenerKind::WindowsManagement, router)),
        );
    }
    if let Some(apple) = crate::apple::router(
        state.apple.as_deref(),
        apple_state.clone(),
        monotonic.clone(),
    ) {
        listeners.push((crate::native::NativeListenerKind::AppleManagement, apple));
    }
    let apple = state.apple.clone();
    let host_routes = Router::new()
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
        .route(
            "/readyz",
            get(ready).with_state((diagnostics, monotonic.clone())),
        )
        .fallback(|| async { axum::http::StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            host,
            crate::http_host::guard,
        ));
    let browser = Router::new()
        .merge(management)
        .merge(rss_mdm_apple_channel::browser_routes(
            apple_state,
            apple_boundary,
        ))
        .nest(
            "/api/agent/v6",
            rss_mdm_agent_channel::router(agent, agent_boundary.clone()).merge(
                rss_mdm_agent_channel::task_router(
                    Arc::new(rss_mdm_agent_channel::TaskState {
                        access: Arc::new(state.access.agent_store()),
                        mount: crate::device::ChannelMount::new(
                            state.identity.tenant,
                            rss_mdm_inventory::ReportSource::AgentBuiltin,
                        ),
                        devices: state.devices.clone(),
                        execution: state.execution.clone(),
                    }),
                    agent_boundary,
                ),
            ),
        )
        .merge(authentication)
        .merge(host_routes)
        .merge(
            rss_mdm_management_http::software_native::routes().with_state(Arc::new(
                rss_mdm_management_http::software_native::StateData {
                    directory: state.flow.publications.clone(),
                    content: state.content_writer.clone(),
                    requests: state.requests.clone(),
                },
            )),
        )
        .layer(DefaultBodyLimit::max(16384));
    crate::native::Routers {
        windows: state.windows.clone(),
        apple,
        browser,
        listeners,
    }
}

async fn ready(
    State((diagnostics, clock)): State<(
        Arc<crate::runtime_diagnostics::RuntimeDiagnostics>,
        Arc<dyn rss_observation::Clock>,
    )>,
) -> Response {
    let result = diagnostics
        .collect(clock.now() + std::time::Duration::from_secs(8), false)
        .await;
    let status = if result.ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(json!({"ready":result.ready}))).into_response()
}

#[cfg(test)]
#[path = "../tests/api/diagnostics.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/api/mod.rs"]
pub(crate) mod t2;
