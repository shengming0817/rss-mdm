use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
pub struct Services {
    pub query_cursor: rss_mdm_query::cursor::CursorCodec,
    pub user_profiles: Arc<dyn crate::user_profiles::Source>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub first_use: Arc<dyn crate::first_use::Source>,
    pub mail: Arc<rss_mdm_mail_service::authority::Authority>,
    pub settings: Arc<dyn crate::settings::Source>,
    pub storage_connections: Arc<rss_mdm_content_service::connections::authority::Authority>,
    pub webhooks: Arc<dyn crate::webhooks::Source>,
    pub registration_channels: Arc<dyn crate::enrollment::channels::Source>,
    pub associations: Arc<rss_mdm_device_service::Associations>,
    pub platform_configuration: Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    pub windows_entra: Option<Arc<rss_mdm_registration_service::windows_entra::Management>>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub pki_clock: Arc<dyn rss_mdm_registration_service::agent_pki::Clock>,
    pub agent_enrollment: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    pub filevault: Option<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
    pub recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
    pub certificate_archive: Arc<rss_mdm_certificate_archive_service::Archive>,
    pub timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub diagnostics: Arc<dyn crate::runtime_diagnostics::Source>,
    pub identity: Arc<crate::identity::Identity>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub identity_management:
        Arc<rss_mdm_authorization_service::identity_management::IdentityManagementPolicy>,
    pub requests: Arc<tokio::sync::Semaphore>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub planning: Arc<rss_mdm_flow_service::planning::Planning>,
    pub groups: Arc<rss_mdm_inventory_service::groups::Groups>,
    pub compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub policies: Arc<rss_mdm_flow_service::planning::policies::Policies>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub catalog: Arc<rss_mdm_flow_service::resource_catalog::ResourceCatalog>,
    pub publications:
        Arc<rss_mdm_software_service::management::publication::service::PublicationDirectory>,
    pub software_catalog: Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
    pub content: Arc<rss_mdm_content_service::service::Access>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::EnrollmentService>,
    pub enrollment_progress:
        Arc<dyn rss_mdm_registration_service::enrollment::read::NativeProgress>,
    pub devices: Arc<rss_mdm_registration_service::device::DeviceService>,
    pub windows: bool,
    pub apple: bool,
}
pub fn device_action_routes() -> Router {
    Router::new().route(
        "/devices/{id}/actions",
        post(action).owned(
            &contracts::DEVICES,
            &[RouteOperation::Action, RouteOperation::Create],
        ),
    )
}
/// Conditions that affect route presence. Disabled services whose endpoints report
/// unavailable are deliberately not represented here.
#[derive(Clone, Copy)]
pub struct Mounts {
    pub agent_enrollment: bool,
    pub filevault: bool,
    pub recovery_credentials: bool,
}
impl Mounts {
    fn from_services(state: &Services) -> Self {
        Self {
            agent_enrollment: state.agent_enrollment.is_some(),
            filevault: state.filevault.is_some(),
            recovery_credentials: state.recovery_credentials.is_some(),
        }
    }
}
pub fn router(state: Services, envelope: crate::boundary::Envelope) -> Router {
    let mounts = Mounts::from_services(&state);
    let routes = assemble(Some((&state, &envelope)), mounts);
    crate::boundary::wrap(routes, envelope)
}
/// Offline construction traverses the same registrations and final path composition.
pub fn contract_routes(mounts: Mounts) -> Router {
    assemble(None, mounts)
}
fn assemble(runtime: Option<(&Services, &crate::boundary::Envelope)>, mounts: Mounts) -> Router {
    let context = runtime.as_ref();
    let cursor = || runtime.map(|(s, _)| s.query_cursor.clone());
    let core = Router::new()
        .merge(
            crate::user_profiles::register().bind_with(context, |(s, _)| s.user_profiles.clone()),
        )
        .merge(crate::first_use::register().bind_with(context, |(s, _)| s.first_use.clone()))
        .merge(crate::mail::register(cursor()).bind_with(context, |(s, _)| s.mail.clone()))
        .merge(
            crate::content::connections::register(cursor())
                .bind_with(context, |(s, _)| s.storage_connections.clone()),
        )
        .merge(crate::settings::register().bind_with(context, |(s, _)| s.settings.clone()))
        .merge(crate::webhooks::register().bind_with(context, |(s, _)| s.webhooks.clone()))
        .merge(
            crate::telemetry::register().bind_with(context, |(s, _)| Arc::new(s.telemetry.clone())),
        )
        .merge(
            crate::api_access::register_keys().bind_with(context, |(s, _)| {
                Arc::new(crate::api_access::Management {
                    cursor: s.query_cursor.clone(),
                    access: s.authorization.clone(),
                    audit: s.audit_store.clone(),
                })
            }),
        )
        .merge(crate::pki::routes().bind_with(context, |(s, _)| {
            Arc::new(crate::pki::HttpState {
                registry: s.pki.clone(),
                clock: s.pki_clock.clone(),
            })
        }))
        .merge(
            crate::certificate_archive::register(cursor())
                .bind_with(context, |(s, _)| s.certificate_archive.clone()),
        )
        .merge(crate::recovery_credentials::mount_filevault(
            runtime.and_then(|(s, _)| s.filevault.clone()),
            mounts.filevault,
        ))
        .merge(crate::recovery_credentials::mount(
            runtime.and_then(|(s, _)| {
                s.recovery_credentials.as_ref().map(|credentials| {
                    Arc::new(crate::recovery_credentials::Services {
                        credentials: credentials.clone(),
                        cursor: s.query_cursor.clone(),
                    })
                })
            }),
            mounts.recovery_credentials,
        ))
        .merge(
            crate::software_publication::http::routes().bind_with(context, |(s, _)| {
                Arc::new(crate::software_publication::http::HttpState {
                    publications: s.publications.clone(),
                    access: s.authorization.clone(),
                })
            }),
        )
        .merge(crate::authorization::routes().bind_with(context, |(s, _)| {
            Arc::new(crate::authorization::http::HttpState {
                cursor: s.query_cursor.clone(),
                audit_store: s.audit_store.clone(),
            })
        }))
        .merge(device_action_routes());
    let planning = Router::new()
        .merge(
            crate::runtime_diagnostics::routes().bind_with(context, |(s, _)| s.diagnostics.clone()),
        )
        .merge(crate::planning::routes().bind_with(context, |(s, _)| {
            Arc::new(crate::planning::http::HttpState {
                planning: s.planning.clone(),
                groups: s.groups.clone(),
            })
        }))
        .merge(
            crate::execution::actions::http::register(cursor())
                .bind_with(context, |(s, _)| s.queries.clone()),
        )
        .merge(crate::assets::routes().bind_with(context, |(s, _)| {
            Arc::new(crate::assets::http::HttpState {
                assets: s.assets.clone(),
            })
        }))
        .merge(crate::compliance::http::routes().bind_with(context, |(s, _)| s.compliance.clone()));
    let resources = crate::resource_catalog::http::routes().bind_with(context, |(s, _)| {
        Arc::new(crate::resource_catalog::http::HttpState {
            catalog: s.catalog.clone(),
            content: s.content.clone(),
        })
    });
    let public_packages = crate::software_catalog::register_agent_packages()
        .bind_with(context, |(s, _)| s.software_catalog.clone());
    let operations = Router::new()
        .merge(crate::device_access::mount(
            runtime.and_then(|(s, _)| {
                s.agent_enrollment.as_ref().map(|registration| {
                    Arc::new(crate::device_access::Services {
                        cursor: s.query_cursor.clone(),
                        recovery: s.recovery_credentials.clone(),
                        registration: registration.clone(),
                        execution: s.execution.clone(),
                        identity: s.identity.clone(),
                    })
                })
            }),
            mounts.agent_enrollment,
        ))
        .merge(
            crate::agent_enrollment::register()
                .bind_with(context, |(s, _)| Arc::new(s.agent_enrollment.clone())),
        )
        .merge(
            crate::windows_entra::register()
                .bind_with(context, |(s, _)| Arc::new(s.windows_entra.clone())),
        )
        .merge(
            crate::execution::http::register(runtime.map(|(s, _)| s.queries.clone()), cursor())
                .bind_with(context, |(s, _)| {
                    Arc::new(crate::execution::http::HttpState {
                        execution: s.execution.clone(),
                        windows: s.windows,
                        apple: s.apple,
                    })
                }),
        )
        .merge(
            crate::planning::policies::http::register(
                runtime.map(|(s, _)| s.queries.clone()),
                cursor(),
            )
            .bind_with(context, |(s, _)| s.policies.clone()),
        )
        .merge(
            crate::planning::policies::http::register_previews(cursor()).bind_with(
                context,
                |(s, _)| {
                    Arc::new(crate::planning::policies::http_preview::StateServices {
                        queries: s.queries.clone(),
                        telemetry: s.telemetry.clone(),
                    })
                },
            ),
        )
        .merge(
            crate::software_catalog::routes()
                .bind_with(context, |(s, _)| s.software_catalog.clone()),
        )
        .merge(crate::content::http::routes().bind_with(context, |(s, _)| s.content.clone()))
        .merge(
            crate::enrollment::http::register(cursor()).bind_with(context, |(s, _)| {
                Arc::new(crate::enrollment::http::HttpState {
                    channels: s.registration_channels.clone(),
                    service: s.enrollment.clone(),
                    native: s.enrollment_progress.clone(),
                    devices: s.devices.clone(),
                    apple: s.apple,
                    windows: s.windows,
                })
            }),
        )
        .merge(
            crate::enrollment::directory::routes().bind_with(context, |(s, _)| {
                Arc::new(crate::enrollment::directory::HttpState {
                    cursor: s.query_cursor.clone(),
                    devices: s.devices.clone(),
                    assets: s.assets.clone(),
                    queries: s.queries.clone(),
                    windows: s.windows,
                    apple: s.apple,
                })
            }),
        )
        .merge(crate::timeline::routes().bind_with(context, |(s, _)| s.timeline.clone()))
        .merge(
            crate::device_views::register(runtime.map(|(s, _)| {
                (
                    Arc::new(
                        rss_mdm_authorization_service::session::SessionAuthority::new(
                            s.identity.authority.clone(),
                            s.identity.tenant,
                        ),
                    ),
                    s.identity.authority.clone(),
                    s.platform_configuration.clone(),
                )
            }))
            .bind_with(context, |(s, _)| s.associations.clone()),
        );
    let policy_events = crate::policy_events::register().bind_with(context, |(s, _)| {
        Arc::new(rss_mdm_flow_service::planning::events::Events {
            planning: s.planning.clone(),
            execution: s.execution.clone(),
        })
    });
    let host_context = register_identity_context().bind_with(context, |(s, _)| {
        Arc::new(IdentityContextState {
            identity_management: s.identity_management.clone(),
        })
    });
    let protected = core
        .merge(planning)
        .merge(policy_events)
        .merge(operations)
        .merge(resources)
        .merge(workspace_routes());
    let authentication = runtime.map(|(s, _)| {
        Arc::new(crate::authorization::http::AuthenticationState {
            identity: s.identity.clone(),
            access: s.authorization.clone(),
            requests: s.requests.clone(),
        })
    });
    let host_context =
        crate::authorization::http::mount_protection(host_context, authentication.clone(), false);
    let protected = crate::authorization::http::mount_protection(protected, authentication, false);
    let broker = crate::enterprise_broker::mount(
        runtime.and_then(|(s, envelope)| {
            s.agent_enrollment.as_ref().map(|registration| {
                Arc::new(crate::enterprise_broker::Services {
                    registration: registration.clone(),
                    execution: s.execution.clone(),
                    identity: s.identity.clone(),
                    origin: format!("https://{}", envelope.host),
                    platform_configuration: serde_json::to_value(&s.platform_configuration)
                        .expect("closed platform configuration"),
                })
            })
        }),
        mounts.agent_enrollment,
    );
    let software_content =
        crate::software_content::register().bind_with(context, |(s, _)| s.execution.clone());
    Router::new()
        .merge(broker)
        .merge(software_content)
        .merge(host_context)
        .nest("/api/v1/agent/enroll", public_packages)
        .nest("/api/v1", protected)
}
pub fn workspace_routes() -> Router {
    Router::new().route(
        "/mdm-candidate/workspace",
        get(workspace).owned(&contracts::WORKSPACE, &[RouteOperation::Get]),
    )
}

async fn workspace(Extension(auth): Extension<RequestAuth>) -> Result<Json<Workspace>, Error> {
    use rss_mdm_authorization_service::Permission as P;
    let p = &auth.proof;
    let device = |permission| {
        p.authorization()
            .and_then(|a| a.devices_for(p, permission).map_err(Into::into))
            .is_ok()
    };
    let manage = |permission| p.manage(permission).is_ok();
    let modules = [
        (WorkspaceId::Devices, device(P::InventoryRead)),
        (
            WorkspaceId::Policies,
            manage(P::PolicyRead)
                || manage(P::GroupRead)
                || manage(P::ScopeRead)
                || manage(P::ResourceRead),
        ),
        (
            WorkspaceId::Software,
            manage(P::SoftwareRead) || manage(P::ResourceRead) || manage(P::ReleaseRead),
        ),
        (
            WorkspaceId::Security,
            device(P::ComplianceRead) || manage(P::ComplianceRuleRead),
        ),
        (
            WorkspaceId::Operations,
            manage(P::AuthorizationRead) || manage(P::RuntimeDiagnosticsRead),
        ),
    ];
    p.check_live()?;
    Ok(Json(Workspace {
        modules: modules
            .into_iter()
            .map(|(id, available)| WorkspaceModule {
                id,
                source: WorkspaceSource::Real,
                available,
            })
            .collect(),
    }))
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityHostContext {
    tenant_id: String,
    principal_id: String,
    session_id: String,
    navigation: crate::authorization::identity_management::IdentityNavigation,
}
/// Product identity navigation over the existing authenticated request proof.
pub fn identity_context_routes(
    policy: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
) -> Router {
    register_identity_context().with_state(Arc::new(IdentityContextState {
        identity_management: policy,
    }))
}
fn register_identity_context() -> Router<Arc<IdentityContextState>> {
    Router::new().route(
        "/api/v1/identity-host/tenants/{tenant}/context",
        get(identity_context).owned(&contracts::IDENTITY_CONTEXT, &[RouteOperation::Get]),
    )
}

async fn identity_context(
    State(app): State<Arc<IdentityContextState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> Result<Json<IdentityHostContext>, Error> {
    let proof = &auth.proof;
    if tenant != proof.tenant_id() {
        return Err(Error::Unauthorized);
    }
    identity_context_response(&app, proof)
}
fn identity_context_response(
    app: &IdentityContextState,
    proof: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<Json<IdentityHostContext>, Error> {
    Ok(Json(IdentityHostContext {
        tenant_id: proof.tenant_id().to_owned(),
        principal_id: proof.principal_id().to_owned(),
        session_id: proof.session_id()?,
        navigation: app.identity_management.identity_navigation(proof)?,
    }))
}
/// The installation management coordinate is an exact route, sharing the existing projection.
pub(crate) fn mount_management_identity_context(
    runtime: Option<(
        Arc<crate::authorization::http::AuthenticationState>,
        Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
        &str,
    )>,
) -> Router {
    let router = Router::new()
        .configured_route(
            "/api/v1/identity-host/tenants/{management_tenant}/context",
            rss_mdm_http_contract::ConfiguredSegment {
                name: "management_tenant",
                source: "installation.management_tenant",
            },
            runtime.as_ref().map(|(_, _, tenant)| *tenant),
            get(management_context).owned(&contracts::IDENTITY_CONTEXT, &[RouteOperation::Get]),
        )
        .bind_with(runtime.as_ref(), |(_, policy, _)| {
            Arc::new(IdentityContextState {
                identity_management: policy.clone(),
            })
        });
    crate::authorization::http::mount_protection(
        router,
        runtime.map(|(authentication, _, _)| authentication),
        true,
    )
}

async fn management_context(
    State(app): State<Arc<IdentityContextState>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<IdentityHostContext>, Error> {
    identity_context_response(&app, &auth.proof)
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action: String,
}
async fn action(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<std::convert::Infallible, Error> {
    if rss_observation::Id::new(&id).is_ok() {
        audit.target_device(&id);
    }
    audit.set_action(
        "device_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let _grant = auth.proof.dangerous(&id)?;
    if input.map_err(Error::from)?.0.action != "wipe" {
        return Err(Error::Malformed);
    }
    Err(Error::Unsupported)
}

struct IdentityContextState {
    identity_management: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct Workspace {
    modules: Vec<WorkspaceModule>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct WorkspaceModule {
    id: WorkspaceId,
    source: WorkspaceSource,
    available: bool,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum WorkspaceId {
    Devices,
    Policies,
    Software,
    Security,
    Operations,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum WorkspaceSource {
    Real,
}
