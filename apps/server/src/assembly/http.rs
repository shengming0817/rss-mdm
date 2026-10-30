//! HTTP composition over already constructed application services.
use super::Assembly;
use axum::{
    Json,
    extract::{DefaultBodyLimit, State},
    middleware::{self},
    response::{IntoResponse, Response},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
#[cfg(test)]
use serde_json::Value;
use std::sync::Arc;
pub(crate) fn from_state(
    state: Arc<Assembly>,
    host: String,
    monotonic: Arc<dyn rss_observation::Clock>,
) -> crate::native::Routers {
    let apple_state = Arc::new(rss_mdm_apple_channel::HttpState {
        query_cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &state.cursor_key,
        )),
        platform_sso: state.apple.as_ref().and_then(|a| a.platform_sso.clone()),
        platform_objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
        material_roots: state.apple_material_roots.clone(),
        account_authority: rss_mdm_apple_channel::account_enrollment::authority(),
        authentication: rss_mdm_apple_channel::account_enrollment::Authentication {
            authority: state.identity.authority.clone(),
            http: state.identity.browser().http.clone(),
            origin: format!("https://{host}"),
        },
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmApple,
            rss_mdm_registration_service::Purpose::Primary,
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
    state
        .identity
        .enterprise_platform
        .bind(state.execution.clone())
        .expect("single enterprise platform composition");
    if let Some(platform) = &state.identity.platform {
        platform
            .bind(&apple_state)
            .expect("single platform composition");
    }
    let windows_state = Arc::new(rss_mdm_windows_channel::HttpState {
        query_cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &state.cursor_key,
        )),
        protection: state.protection.clone(),
        mount: crate::device::ChannelMount::new(
            state.identity.tenant,
            rss_mdm_inventory::ReportSource::MdmWindows,
            rss_mdm_registration_service::Purpose::Primary,
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
    let channels = Arc::new(crate::registration_channels::Channels {
        preparation: state.channels.clone(),
        windows: state.windows.clone(),
        agent: state.agent_pki.clone(),
        apple: state.apple.clone(),
        pki: state.pki.clone(),
        clock: state.clock.clone(),
    });
    let diagnostics = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
        channels: state.channels.clone(),
        registration: channels.clone(),
        pki: state.pki.clone(),
        apple_store: state.access.apple_store(),
        access: state.access.archive_pool(),
        telemetry: state.telemetry.clone(),
        execution: state.execution.clone(),
        inventory: state.inventory.clone(),
        apple: state.apple.clone(),
        clock: state.clock.clone(),
        planning: state.policy_application.clone(),
        devices: state.associations.clone(),
        scopes: state.scopes.clone(),
        groups: state.groups.clone(),
        assets: state.assets.clone(),
        compliance: state.compliance.clone(),
        scope_group_health: state.scope_group_health.clone(),
        tenant: state.identity.tenant,
        instance: state.identity.instance.to_string(),
    });
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
    let windows_browser_boundary = rss_mdm_windows_channel::boundary::Envelope {
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
    let authentication = state.identity.http_routes(
        Arc::new(rss_mdm_management_http::api_access::BearerAdmission {
            access: state.access.authorization_store(),
            tenant: state.identity.tenant.to_string(),
        }),
        management_boundary.clone(),
    );
    let directory = crate::administration::settings::Directory {
        tenant: state.identity.tenant,
        management_tenant: state.identity.management_tenant,
        identity: state.identity.authority.clone(),
        federation: state.identity.federation.clone(),
        tenant_administration: state.identity.tenant_administration.clone(),
        user_profiles: Arc::new(crate::administration::user_profiles::Backend {
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &state.cursor_key,
            )),
            identity: state.identity.authority.clone(),
            tenant: state.identity.tenant,
            instance: state.identity.instance,
            audit: state.audit_store.clone(),
        }),
        audit: state.audit_store.clone(),
        clock: state.clock.clone(),
        protection: state.protection.clone(),
        pki: state.pki.clone(),
        software_runtime: state.software_catalog.runtime.clone(),
        registration: state.agent_enrollment.clone(),
        webhooks: state.webhooks.clone(),
        windows: state.access.windows_store(),
        windows_loaded: state.windows.is_some(),
        windows_push_revision: state
            .windows
            .as_ref()
            .filter(|w| w.channel.push.is_some())
            .and_then(|w| w.config.push.as_ref().map(|p| p.revision)),
        apple_materials: state
            .apple
            .as_ref()
            .map(|apple| apple.config.materials.clone()),
        content: state.content_writer.clone(),
        signing_key: state.execution.loaded_task_signing_key().map(str::to_owned),
        recovery: state.execution.recovery_credentials(),
        apple_store: apple_state.access.clone(),
        apple: apple_state.apple.clone(),
    };
    let settings: Arc<crate::administration::settings::Directory> = Arc::new(directory.clone());
    let first_use = Arc::new(crate::administration::first_use::FirstUse {
        directory: settings.clone(),
        tenant: state.identity.tenant,
        instance: state.identity.instance,
        audit: state.audit_store.clone(),
        admission: rss_mdm_registration_service::admission::Admission::new(
            state.access.registration(),
            state.audit_store.clone(),
        ),
        channels: channels.clone(),
    });
    let tenant_administration = rss_mdm_management_http::tenant_administration::router(
        Arc::new(
            rss_mdm_management_http::authorization::http::AuthenticationState {
                identity: state.identity.management_browser(),
                access: state.access.authorization_store(),
                requests: state.requests.clone(),
            },
        ),
        crate::administration::tenants::http::routes(state.identity.tenant_administration.clone()),
        crate::administration::settings::http::platform_routes(Some(&settings)),
        state.identity_management.clone(),
        rss_mdm_management_http::boundary::Envelope {
            tenant: state.identity.management_tenant.to_string(),
            ..management_boundary.clone()
        },
        rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &state.cursor_key,
        )),
    );
    let management_authentication = Arc::new(
        rss_mdm_management_http::authorization::http::AuthenticationState {
            identity: state.identity.browser(),
            access: state.access.authorization_store(),
            requests: state.requests.clone(),
        },
    );
    let apple_management = rss_mdm_management_http::boundary::wrap(
        rss_mdm_management_http::authorization::http::mount_protection(
            rss_mdm_apple_channel::management_routes(apple_state.clone())
                .route_layer(middleware::from_fn(apple_management_settlement)),
            Some(management_authentication.clone()),
            false,
        ),
        management_boundary.clone(),
    );
    let wns_management = rss_mdm_management_http::boundary::wrap(
        rss_mdm_management_http::authorization::http::mount_protection(
            windows_management_routes(Some(windows_state.clone())),
            Some(management_authentication),
            false,
        ),
        management_boundary.clone(),
    );
    let management = rss_mdm_management_http::router(
        rss_mdm_management_http::Services {
            query_cursor: rss_mdm_query::cursor::CursorCodec::new(&state.cursor_key)
                .expect("validated query key"),
            mail: Arc::new(rss_mdm_mail_service::authority::Authority {
                tenant: state.identity.tenant,
                protection: state.protection.clone(),
                audit: state.audit_store.clone(),
            }),
            webhooks: state.webhooks.clone(),
            telemetry: state.telemetry.clone(),
            registration_channels: channels,
            windows_entra: state
                .windows
                .as_ref()
                .and_then(|w| w.channel.entra.as_ref())
                .map(|_| {
                    Arc::new(
                        rss_mdm_registration_service::windows_entra::Management::new(
                            state.access.registration(),
                            state.audit_store.clone(),
                            state.identity.tenant,
                        ),
                    )
                }),
            agent_enrollment: state.agent_enrollment.clone(),
            pki: state.pki.clone(),
            pki_clock: Arc::new(crate::agent_pki::PkiClock(state.clock.clone())),
            filevault: state.execution.recovery_credentials().map(|p| {
                Arc::new(rss_mdm_recovery_credentials::FilevaultService::new(
                    state.access.archive_pool(),
                    state.audit_store.clone(),
                    p.clone(),
                ))
            }),
            recovery_credentials: state.execution.recovery_credentials().map(|p| {
                Arc::new(rss_mdm_recovery_credentials::Credentials::new(
                    state.access.archive_pool(),
                    state.audit_store.clone(),
                    p.keys.clone(),
                    state.access_audit.clone(),
                    state.execution.clone(),
                ))
            }),
            certificate_archive: state.certificate_archive.clone(),
            timeline: state.timeline.clone(),
            associations: state.associations.clone(),
            platform_configuration: state.platform_configuration.clone(),
            diagnostics: diagnostics.clone(),
            identity: state.identity.browser(),
            authorization: state.access.authorization_store(),
            identity_management: state.identity_management.clone(),
            requests: state.requests.clone(),
            audit_store: state.audit_store.clone(),
            events: state.events.clone(),
            scopes: state.scopes.clone(),
            groups: state.groups.clone(),
            compliance: state.compliance.clone(),
            execution: state.execution.clone(),
            queries: state.queries.clone(),
            policies: state.policies.clone(),
            assets: state.assets.clone(),
            catalog: state.resources.clone(),
            publications: state.publications.clone(),
            software_catalog: state.software_catalog.clone(),
            storage_connections: Arc::new(
                rss_mdm_content_service::connections::authority::Authority {
                    tenant: state.identity.tenant,
                    protection: state.protection.clone(),
                    audit: state.audit_store.clone(),
                    content: state.content_writer.clone(),
                },
            ),
            content: state.content_access.clone(),
            enrollment_progress: Arc::new(crate::enrollment_progress::EnrollmentProgress {
                sessions: apple_state.identity.clone(),
                windows: state.windows.as_ref().map(|w| w.channel.clone()),
                apple: state.apple.as_ref().map(|a| a.channel.clone()),
            }),
            enrollment: Arc::new(
                rss_mdm_registration_service::enrollment::EnrollmentService::new(
                    state.access.registration(),
                    state.credentials.clone(),
                    state.audit_store.clone(),
                ),
            ),
            devices: state.devices.clone(),
            windows: state.windows.is_some(),
            apple: state.apple.is_some(),
        },
        management_boundary,
        crate::administration::http::mount(Some(crate::administration::http::Services {
            profiles: &directory.user_profiles,
            first_use: &first_use,
            settings: &settings,
        })),
    );
    let mut listeners = Vec::new();
    if let Some((enrollment, planning)) = crate::windows::routers(
        state.windows.as_deref(),
        windows_state.clone(),
        monotonic.clone(),
    ) {
        listeners.push((crate::native::ChannelKind::WindowsEnrollment, enrollment));
        listeners.extend(
            planning
                .into_iter()
                .map(|router| (crate::native::ChannelKind::WindowsManagement, router)),
        );
    }
    if let Some(apple) = crate::apple::router(
        state.apple.as_deref(),
        apple_state.clone(),
        monotonic.clone(),
    ) {
        listeners.push((crate::native::ChannelKind::AppleManagement, apple));
    }
    if let (Some(pki), Some(service)) = (&state.agent_pki, &state.agent_enrollment) {
        let mut envelope = agent_boundary;
        // This outer gateway dispatcher validates the actual published Agent origin.
        envelope.host.clear();
        let task_state = Arc::new(crate::agent::TaskState {
            identity: Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    state.identity.authority.clone(),
                    state.identity.tenant,
                ),
            ),
            authorization: state.access.authorization_store(),
            enrollment: service.clone(),
            access: Arc::new(state.access.agent_store()),
            execution: state.execution.clone(),
        });
        let agent_services = rss_mdm_agent_channel::RuntimeServices {
            http: Arc::new(crate::agent::HttpState {
                content: state.content_writer.clone(),
                enrollment: service.clone(),
                audit_store: state.audit_store.clone(),
                access: Arc::new(state.access.agent_store()),
                inventory: state.inventory.clone(),
                telemetry: state.telemetry.clone(),
            }),
            tasks: task_state,
            timeline: state.timeline.clone(),
            events: state.events.clone(),
            filevault: state.execution.recovery_credentials().map(|p| {
                Arc::new(rss_mdm_recovery_credentials::FilevaultService::new(
                    state.access.archive_pool(),
                    state.audit_store.clone(),
                    p.clone(),
                ))
            }),
            envelope,
        };
        let router = mount_agent(
            Some(&agent_services),
            rss_mdm_apple_channel::platform_sso::agent_routes(apple_state.clone(), service.clone()),
            rss_mdm_management_http::software_catalog::agent_packages_public(
                state.software_catalog.clone(),
            ),
            agent_services.filevault.is_some(),
        );
        listeners.push((
            crate::native::ChannelKind::Agent,
            crate::native::ChannelRouter {
                origins: pki.origins.clone(),
                router: router.into_checked_axum(rss_mdm_http_contract::module::Listener::Agent),
                admission: crate::native::admission::Admission::new(
                    monotonic.clone(),
                    state.requests.clone(),
                    "agent-tls",
                ),
            },
        ));
    }
    let apple = state.apple.clone();
    let browser = BrowserRoutes {
        tenants: tenant_administration,
        management,
        windows_management: wns_management,
        apple_management,
        apple_browser: rss_mdm_apple_channel::browser_routes(apple_state.clone(), apple_boundary),
        windows_browser: rss_mdm_windows_channel::entra::browser_routes(
            windows_state,
            windows_browser_boundary,
        ),
        host: host_routes(Some(HostRuntime {
            diagnostics,
            clock: monotonic.clone(),
            observation: state.runtime_observation.clone(),
            host,
        })),
        software_native: rss_mdm_management_http::software_native::routes().with_state(Arc::new(
            rss_mdm_management_http::software_native::StateData {
                directory: state.publications.clone(),
                content: state.content_writer.clone(),
                requests: state.requests.clone(),
            },
        )),
    }
    .assemble();
    let browser = authentication
        .merge(browser.into_checked_axum(rss_mdm_http_contract::module::Listener::Browser));
    let browser = browser.layer(DefaultBodyLimit::max(16384));
    crate::native::Routers {
        baseline: crate::lifecycle::baseline_registration(
            crate::administration::baseline::Service {
                tenant: state.identity.tenant,
                instance: state.identity.instance,
                pool: state.access.archive_pool(),
                authorization: state.access.authorization_store(),
                groups: state.groups.clone(),
                scopes: state.scopes.clone(),
                resources: state.resources.clone(),
                content_access: state.content_access.clone(),
                assets: state.assets.clone(),
                policies: state.policies.clone(),
                telemetry_loaded: state.telemetry.is_some(),
            },
        ),
        telemetry: state.telemetry.clone(),
        webhooks: state.webhooks.clone(),
        apple_control: apple_state,
        pki: state.pki.clone(),
        agent_pki: state.agent_pki.clone(),
        windows: state.windows.clone(),
        apple,
        browser,
        agent_enrollment: state.agent_enrollment.clone(),
        listeners,
    }
}

async fn ready(
    State((diagnostics, clock, observation)): State<(
        Arc<crate::runtime_diagnostics::RuntimeDiagnostics>,
        Arc<dyn rss_observation::Clock>,
        crate::installation::host::Observation,
    )>,
) -> Readiness {
    let result = diagnostics
        .collect(clock.now() + std::time::Duration::from_secs(8), false)
        .await;
    Readiness {
        ready: result.ready,
        observation,
    }
}

#[cfg(test)]
#[path = "../../tests/api/mod.rs"]
pub(crate) mod t2;

/// Compose the Apple business owner's settlement class with the common HTTP boundary.
pub(crate) async fn apple_management_settlement(
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    use rss_mdm_apple_channel::{Error as AppleError, Failure as AppleFailure};
    use rss_mdm_audit_integration::completion::ResponseFailure;
    let mut response = next.run(request).await;
    let failure = match response.extensions().get::<AppleError>() {
        Some(AppleError::CommitUnknown) => Some(ResponseFailure::CommitUnknown),
        Some(AppleError::RollbackFailed) => Some(ResponseFailure::RollbackFailed),
        Some(AppleError::Unauthorized | AppleError::Forbidden) => Some(ResponseFailure::Denied),
        Some(AppleError::Unavailable(AppleFailure::RequestDeadline)) => {
            Some(ResponseFailure::Deadline)
        }
        Some(AppleError::Unavailable(AppleFailure::AuditIntegrity)) => {
            Some(ResponseFailure::AuditIntegrity)
        }
        Some(AppleError::Unavailable(
            AppleFailure::AuditContract
            | AppleFailure::AuditIsolation
            | AppleFailure::AuditAdmission,
        )) => Some(ResponseFailure::AuditContract),

        Some(AppleError::Unavailable(AppleFailure::Audit)) => {
            Some(ResponseFailure::AuditUnavailable)
        }
        _ => None,
    };
    if let Some(failure) = failure {
        response.extensions_mut().insert(failure);
    }
    response
}

#[cfg(test)]
#[path = "../../tests/api/diagnostics.rs"]
mod tests;

/// Final prefixes are shared by the serving listener and offline contract projection.
fn mount_agent<
    D0: rss_mdm_http_contract::module::Declaration,
    D1: rss_mdm_http_contract::module::Declaration,
>(
    runtime: Option<&rss_mdm_agent_channel::RuntimeServices>,
    platform_sso: Router<(), D0>,
    packages: Router<(), D1>,
    filevault: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0, D1>> {
    let (platform_sso, packages) = match runtime {
        Some(runtime) => (
            rss_mdm_agent_channel::boundary::wrap(platform_sso, runtime.envelope.clone()),
            rss_mdm_agent_channel::boundary::wrap_enroll(packages, runtime.envelope.clone()),
        ),
        None => (platform_sso, packages),
    };
    {
 rss_mdm_http_contract::route_module! { struct MountAgentModule1 for [Agent] { api_v1_agent_runtime at "/api/v1/agent/runtime", api_v1_agent_enroll at "/api/v1/agent/enroll" } }
 MountAgentModule1 { api_v1_agent_runtime: {
 rss_mdm_http_contract::route_module! { struct MountAgentModule101 for [Agent] { base, platform_sso } }
 MountAgentModule101 { base: rss_mdm_agent_channel::runtime_routes(runtime, filevault),
platform_sso }.assemble()
},
api_v1_agent_enroll: {
 rss_mdm_http_contract::route_module! { struct MountAgentModule102 for [Agent] { base, packages } }
 MountAgentModule102 { base: rss_mdm_agent_channel::enrollment_routes(runtime),
packages }.assemble()
} }.assemble()
}
        .when("agent_listener", true)
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct Liveness {
    alive: bool,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Readiness {
    ready: bool,
    observation: crate::installation::host::Observation,
}
impl Readiness {
    fn status(&self) -> u16 {
        if self.ready { 200 } else { 503 }
    }
}
impl IntoResponse for Readiness {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::from_u16(self.status()).expect("readiness status"),
            Json(self),
        )
            .into_response()
    }
}
impl rss_mdm_http_contract::signature::Output for Readiness {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        [(200, true), (503, false)]
            .into_iter()
            .map(|(status, ready)| {
                let mut response = rss_mdm_http_contract::signature::Response::json::<Self>(status);
                response.body.as_mut().unwrap().schema.value["properties"]["ready"] =
                    serde_json::json!({"type":"boolean","const":ready});
                response
            })
            .collect()
    }
}

struct HostRuntime {
    diagnostics: Arc<crate::runtime_diagnostics::RuntimeDiagnostics>,
    clock: Arc<dyn rss_observation::Clock>,
    observation: crate::installation::host::Observation,
    host: String,
}
fn host_routes(
    runtime: Option<HostRuntime>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let mut routes = {
 rss_mdm_http_contract::route_module! { struct HostRoutesModule1 for [Browser] { get_livez, get_ready } }
 HostRoutesModule1 { get_livez: rss_mdm_http_contract::module::Route::new("/livez", get(|| async { Json(Liveness { alive: true }) }, &contracts::HEALTH, &[RouteOperation::Action])),
get_ready: rss_mdm_http_contract::module::Route::new("/readyz", get(ready, &contracts::HEALTH, &[RouteOperation::Action])) }.assemble()
}
        .bind_with(runtime.as_ref(), |r| {
            (
                r.diagnostics.clone(),
                r.clock.clone(),
                r.observation.clone(),
            )
        })
        .fallback(|| async { axum::http::StatusCode::NOT_FOUND });
    if let Some(runtime) = runtime {
        routes = routes.layer(middleware::from_fn_with_state(
            runtime.host,
            crate::http_host::guard,
        ));
    }
    routes
}
fn windows_management_routes(
    app: Option<Arc<rss_mdm_windows_channel::HttpState>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! { struct WindowsManagementRoutes for [Browser] { wns, certificates } }
    WindowsManagementRoutes {
        wns: rss_mdm_windows_channel::wns_materials::mount(app.clone()),
        certificates: rss_mdm_windows_channel::certificate_queries::mount(app),
    }
    .assemble()
}

// One final browser combination; each field is produced by its actual ingress owner.
rss_mdm_http_contract::route_module! {
    struct BrowserRoutes for [Browser] {
        tenants, management, windows_management, apple_management,
        apple_browser, windows_browser, host, software_native
    }
}
/// Complete self-owned HTTP surface, including conditional mounts, with no runtime state.
/// Third-party Identity routers retain their external owner; product adapters remain included.
pub fn http_contract_document() -> std::result::Result<serde_json::Value, Vec<String>> {
    let browser = BrowserRoutes {
        tenants: rss_mdm_management_http::tenant_administration::contract_routes(
            crate::administration::tenants::http::mount_registry(None, true),
            crate::administration::settings::http::platform_routes(None),
        ),
        management: rss_mdm_management_http::contract_routes(
            rss_mdm_management_http::Mounts {
                agent_enrollment: true,
                filevault: true,
                recovery_credentials: true,
            },
            crate::administration::http::mount(None),
        ),
        windows_management: rss_mdm_management_http::authorization::http::mount_protection(
            windows_management_routes(None),
            None,
            false,
        ),
        apple_management: rss_mdm_management_http::authorization::http::mount_protection(
            rss_mdm_apple_channel::mount_management(None),
            None,
            false,
        ),
        apple_browser: rss_mdm_apple_channel::mount_browser(None),
        windows_browser: rss_mdm_windows_channel::entra::mount_browser(None),
        host: host_routes(None),
        software_native: rss_mdm_management_http::software_native::routes().bind_with(
            None::<&Arc<rss_mdm_management_http::software_native::StateData>>,
            Clone::clone,
        ),
    }
    .assemble();
    let agent = mount_agent(
        None,
        rss_mdm_apple_channel::platform_sso::mount_agent(None),
        rss_mdm_management_http::software_catalog::mount_agent_packages(None),
        true,
    );
    let (windows_enrollment, windows_management) =
        rss_mdm_windows_channel::mount_native(None, None);
    let apple = rss_mdm_apple_channel::mount_native(None);
    let mut violations = browser
        .validate(rss_mdm_http_contract::module::Listener::Browser)
        .into_iter()
        .map(|v| format!("browser mount coverage: {v:?}"))
        .collect::<Vec<_>>();
    violations.extend(
        agent
            .validate(rss_mdm_http_contract::module::Listener::Agent)
            .into_iter()
            .map(|v| format!("agent mount coverage: {v:?}")),
    );
    violations.extend(
        windows_enrollment.validate(rss_mdm_http_contract::module::Listener::WindowsEnrollment),
    );
    violations.extend(
        windows_management.validate(rss_mdm_http_contract::module::Listener::WindowsManagement),
    );
    violations.extend(apple.validate(rss_mdm_http_contract::module::Listener::Apple));
    if !violations.is_empty() {
        return Err(violations);
    }
    let mut document = rss_mdm_http_contract::artifact::document([
        ("browser", browser.into_endpoints()),
        ("agent", agent.into_endpoints()),
        ("windows-enrollment", windows_enrollment.into_endpoints()),
        ("windows-management", windows_management.into_endpoints()),
        ("apple", apple.into_endpoints()),
    ])?;
    document["externalOwners"] = serde_json::json!([{"owner":"rss-identity-http-axum","entry":"Identity::http_routes","scope":"Identity SDK routers; RSS product adapters are included in endpoints"}]);
    Ok(document)
}
