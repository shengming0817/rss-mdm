use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    middleware,
    response::Response,
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
        post(action).owned(&contracts::DEVICES, &[RouteOperation::Action]),
    )
}
pub fn router(state: Services, envelope: crate::boundary::Envelope) -> Router {
    let broker = crate::enterprise_broker::routes(
        state.agent_enrollment.clone(),
        state.execution.clone(),
        state.identity.clone(),
        &envelope.host,
        serde_json::to_value(&state.platform_configuration).expect("closed platform configuration"),
    );
    let directory_identity = state.identity.authority.clone();
    let sessions = Arc::new(
        rss_mdm_authorization_service::session::SessionAuthority::new(
            state.identity.authority.clone(),
            state.identity.tenant,
        ),
    );
    let software_content = crate::software_content::routes(state.execution.clone());
    let directory = Arc::new(crate::enrollment::directory::HttpState {
        cursor: state.query_cursor.clone(),
        devices: state.devices.clone(),
        assets: state.assets.clone(),
        queries: state.queries.clone(),
        windows: state.windows,
        apple: state.apple,
    });
    let execution = Arc::new(crate::execution::http::HttpState {
        execution: state.execution.clone(),
        windows: state.windows,
        apple: state.apple,
    });
    let planning = Arc::new(crate::planning::http::HttpState {
        planning: state.planning.clone(),
        groups: state.groups.clone(),
    });
    let policies = state.policies;
    let assets = Arc::new(crate::assets::http::HttpState {
        assets: state.assets,
    });
    let authorization = Arc::new(crate::authorization::http::HttpState {
        cursor: state.query_cursor.clone(),
        audit_store: state.audit_store.clone(),
    });
    let authentication_state = Arc::new(crate::authorization::http::AuthenticationState {
        identity: state.identity.clone(),
        access: state.authorization.clone(),
        requests: state.requests,
    });
    let enrollment = Arc::new(crate::enrollment::http::HttpState {
        channels: state.registration_channels,
        service: state.enrollment,
        native: state.enrollment_progress,
        devices: state.devices,
        apple: state.apple,
        windows: state.windows,
    });
    let core = Router::new()
        .merge(crate::user_profiles::routes(state.user_profiles))
        .merge(crate::first_use::routes(state.first_use))
        .merge(crate::mail::routes(state.mail, state.query_cursor.clone()))
        .merge(
            crate::content::connections::routes(state.query_cursor.clone())
                .with_state(state.storage_connections),
        )
        .merge(crate::settings::routes(state.settings))
        .merge(crate::webhooks::routes(state.webhooks))
        .merge(crate::telemetry::routes(state.telemetry.clone()))
        .merge(crate::api_access::key_routes(Arc::new(
            crate::api_access::Management {
                cursor: state.query_cursor.clone(),
                access: state.authorization.clone(),
                audit: state.audit_store.clone(),
            },
        )))
        .merge(
            crate::pki::routes().with_state(Arc::new(crate::pki::HttpState {
                registry: state.pki,
                clock: state.pki_clock,
            })),
        )
        .merge(
            crate::certificate_archive::routes(state.query_cursor.clone())
                .with_state(state.certificate_archive),
        )
        .merge(crate::recovery_credentials::filevault_routes(
            state.filevault.clone(),
        ))
        .merge(crate::recovery_credentials::routes(
            state.recovery_credentials.clone(),
            state.query_cursor.clone(),
        ))
        .merge(
            crate::software_publication::http::routes().with_state(Arc::new(
                crate::software_publication::http::HttpState {
                    publications: state.publications,
                    access: state.authorization.clone(),
                },
            )),
        )
        .merge(crate::authorization::routes().with_state(authorization))
        .merge(device_action_routes());
    let planning_routes = Router::new()
        .merge(crate::runtime_diagnostics::routes().with_state(state.diagnostics))
        .merge(crate::planning::routes().with_state(planning.clone()))
        .merge(crate::execution::actions::http::routes().with_state(state.queries.clone()))
        .merge(crate::assets::routes().with_state(assets))
        .merge(crate::compliance::http::routes().with_state(state.compliance));
    let resources = crate::resource_catalog::http::routes().with_state(Arc::new(
        crate::resource_catalog::http::HttpState {
            catalog: state.catalog,
            content: state.content.clone(),
        },
    ));
    let public_packages =
        crate::software_catalog::agent_packages_public(state.software_catalog.clone());
    let operations = Router::new()
        .merge(crate::device_access::routes(
            state.query_cursor.clone(),
            state.authorization.clone(),
            state.recovery_credentials,
            state.agent_enrollment.clone(),
            state.execution.clone(),
            state.identity.clone(),
        ))
        .merge(crate::agent_enrollment::routes(state.agent_enrollment))
        .merge(crate::windows_entra::routes(state.windows_entra))
        .merge(
            crate::execution::routes(state.queries.clone(), state.query_cursor.clone())
                .with_state(execution),
        )
        .merge(
            crate::planning::policies::http::routes(state.queries.clone())
                .with_state(policies.clone()),
        )
        .merge(crate::planning::policies::http::previews(
            state.queries.clone(),
            state.telemetry.clone(),
        ))
        .merge(crate::software_catalog::routes().with_state(state.software_catalog))
        .merge(crate::content::http::routes().with_state(state.content))
        .merge(crate::enrollment::http::routes().with_state(enrollment))
        .merge(crate::enrollment::directory::routes().with_state(directory))
        .merge(crate::timeline::routes().with_state(state.timeline))
        .merge(
            crate::device_views::routes(sessions, directory_identity, state.platform_configuration)
                .with_state(state.associations),
        );
    let host_context = identity_context_routes(state.identity_management).route_layer(
        middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ),
    );
    let protected = core
        .merge(planning_routes)
        .merge(operations)
        .merge(resources)
        .merge(workspace_routes())
        .route_layer(middleware::from_fn_with_state(
            authentication_state,
            crate::authorization::http::protect,
        ));
    crate::boundary::wrap(
        Router::new()
            .merge(broker)
            .merge(software_content)
            .merge(host_context)
            .nest("/api/v1/agent/enroll", public_packages)
            .nest("/api/v1", protected),
        envelope,
    )
}
pub fn workspace_routes() -> Router {
    Router::new().route(
        "/mdm-candidate/workspace",
        get(workspace).owned(&contracts::WORKSPACE, &[RouteOperation::Get]),
    )
}

async fn workspace(
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<serde_json::Value>, Error> {
    use rss_mdm_authorization_service::Permission as P;
    let p = &auth.proof;
    let device = |permission| {
        p.authorization()
            .and_then(|a| a.devices_for(p, permission).map_err(Into::into))
            .is_ok()
    };
    let manage = |permission| p.manage(permission).is_ok();
    let modules = [
        ("devices", device(P::InventoryRead)),
        (
            "policies",
            manage(P::PolicyRead)
                || manage(P::GroupRead)
                || manage(P::ScopeRead)
                || manage(P::ResourceRead),
        ),
        (
            "software",
            manage(P::SoftwareRead) || manage(P::ResourceRead) || manage(P::ReleaseRead),
        ),
        (
            "security",
            device(P::ComplianceRead) || manage(P::ComplianceRuleRead),
        ),
        (
            "operations",
            manage(P::AuthorizationRead) || manage(P::RuntimeDiagnosticsRead),
        ),
    ];
    p.check_live()?;
    Ok(Json(
        serde_json::json!({"modules":modules.into_iter().map(|(id,available)|serde_json::json!({"id":id,"source":"real","available":available})).collect::<Vec<_>>()}),
    ))
}
#[derive(serde::Serialize)]
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
    Router::new().route(
        "/api/v1/identity-host/tenants/{tenant}/context",
        get(identity_context)
            .owned(&contracts::IDENTITY_CONTEXT, &[RouteOperation::Get])
            .with_state(Arc::new(IdentityContextState {
                identity_management: policy,
            })),
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
pub(crate) fn management_identity_context(
    authentication: Arc<crate::authorization::http::AuthenticationState>,
    policy: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
    tenant: &str,
) -> Router {
    Router::new()
        .route(
            &format!("/api/v1/identity-host/tenants/{tenant}/context"),
            get(management_context)
                .owned(&contracts::IDENTITY_CONTEXT, &[RouteOperation::Get])
                .with_state(Arc::new(IdentityContextState {
                    identity_management: policy,
                })),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication,
            crate::authorization::http::protect_management,
        ))
}
async fn management_context(
    State(app): State<Arc<IdentityContextState>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<IdentityHostContext>, Error> {
    identity_context_response(&app, &auth.proof)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action: String,
}
async fn action(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
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
