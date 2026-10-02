use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    middleware,
    response::Response,
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::device::coordinates::Coordinates;
use serde::Deserialize;
use std::sync::Arc;
pub struct Services {
    pub timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub diagnostics: Arc<dyn crate::runtime_diagnostics::Source>,
    pub identity: Arc<crate::identity::Identity>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub identity_management:
        Arc<rss_mdm_authorization_service::identity_management::IdentityManagementPolicy>,
    pub requests: Arc<tokio::sync::Semaphore>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub planning: Arc<rss_mdm_flow_service::planning::Planning>,
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
    pub devices: Arc<rss_mdm_registration_service::device::DeviceService>,
    pub collection: Arc<rss_mdm_inventory_service::collection_service::CollectionService>,
    pub collection_intake: rss_mdm_inventory_service::apple_collection::Service,
    pub windows: bool,
    pub apple: bool,
}
pub fn router(state: Services, envelope: crate::boundary::Envelope) -> Router {
    let directory = Arc::new(crate::enrollment::directory::HttpState {
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
    });
    let policies = state.policies;
    let assets = Arc::new(crate::assets::http::HttpState {
        assets: state.assets,
    });
    let authorization = Arc::new(crate::authorization::http::HttpState {
        audit_store: state.audit_store.clone(),
    });
    let collection = Arc::new(crate::collection::apple::HttpState {
        service: state.collection_intake,
    });
    let collection_read = Arc::new(CollectionState {
        collection: state.collection,
    });
    let authentication_state = Arc::new(crate::authorization::http::AuthenticationState {
        identity: state.identity,
        access: state.authorization.clone(),
        requests: state.requests,
    });
    let identity_context_state = Arc::new(IdentityContextState {
        identity_management: state.identity_management,
    });
    let enrollment = Arc::new(crate::enrollment::http::HttpState {
        service: state.enrollment,
        devices: state.devices,
        apple: state.apple,
        windows: state.windows,
    });
    let protected_v1 = Router::new()
        .merge(
            crate::software_publication::http::routes().with_state(Arc::new(
                crate::software_publication::http::HttpState {
                    publications: state.publications,
                    access: state.authorization,
                },
            )),
        )
        .merge(crate::authorization::routes().with_state(authorization))
        .route(
            "/devices/{id}/collection-runs",
            post(crate::collection::apple::create).with_state(collection),
        )
        .route(
            "/devices/{id}/collection-runs/{run}",
            get(collection_run).with_state(collection_read),
        )
        .route("/devices/{id}/actions", post(action))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let protected_v2 = Router::new()
        .merge(crate::runtime_diagnostics::routes().with_state(state.diagnostics))
        .merge(crate::planning::routes_v2().with_state(planning.clone()))
        .merge(crate::execution::actions::http::routes().with_state(state.queries.clone()))
        .merge(crate::assets::routes().with_state(assets))
        .merge(crate::compliance::http::routes().with_state(Arc::new(state.planning.compliance())))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let protected_v4 = crate::resource_catalog::http::routes()
        .with_state(Arc::new(crate::resource_catalog::http::HttpState {
            catalog: state.catalog,
        }))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let protected_v3 = Router::new()
        .merge(crate::execution::routes(state.queries.clone()).with_state(execution))
        .merge(
            crate::planning::policies::http::routes(state.queries.clone())
                .with_state(policies.clone()),
        )
        .merge(
            crate::remote_operations::routes(state.queries.clone())
                .with_state(state.execution.clone()),
        )
        .merge(crate::software_catalog::routes().with_state(state.software_catalog))
        .merge(crate::content::http::routes().with_state(state.content))
        .merge(crate::enrollment::http::routes().with_state(enrollment))
        .merge(crate::enrollment::directory::routes().with_state(directory))
        .merge(crate::timeline::routes().with_state(state.timeline))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    let host_context = Router::new()
        .route(
            "/api/identity-host/v1/tenants/{tenant}/context",
            get(identity_context).with_state(identity_context_state),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::identity_only,
        ));
    let workspace = Router::new()
        .route("/api/mdm-candidate/v1/workspace", get(workspace))
        .route_layer(middleware::from_fn_with_state(
            authentication_state.clone(),
            crate::authorization::http::protect,
        ));
    crate::boundary::wrap(
        Router::new()
            .merge(host_context)
            .merge(workspace)
            .nest("/api/v1", protected_v1)
            .nest("/api/v2", protected_v2)
            .nest("/api/v3", protected_v3)
            .nest("/api/v4", protected_v4)
            .layer(axum::extract::DefaultBodyLimit::max(16384)),
        envelope,
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
async fn identity_context(
    State(app): State<Arc<IdentityContextState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> Result<Json<IdentityHostContext>, Error> {
    let proof = &auth.proof;
    if tenant != proof.tenant_id() {
        return Err(Error(rss_mdm_flow_service::Error::Unauthorized));
    }
    Ok(Json(IdentityHostContext {
        tenant_id: proof.tenant_id().to_owned(),
        principal_id: proof.principal_id().to_owned(),
        session_id: proof.session_id(),
        navigation: app.identity_management.identity_navigation(proof)?,
    }))
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
        audit.target(&id);
    }
    audit.set_action("device_action");
    let _grant = auth.proof.dangerous(&id)?;
    if input
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
        .0
        .action
        != "wipe"
    {
        return Err(Error(rss_mdm_flow_service::Error::Malformed));
    }
    Err(Error(rss_mdm_flow_service::Error::Unsupported))
}

async fn collection_run(
    State(app): State<Arc<CollectionState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<(String, uuid::Uuid)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<Coordinates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::assets::collection::CollectionResponse>, Error> {
    let Path((device, run)) = path.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    let Query(coordinates) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    audit.target(&device);
    audit.set_action("collection_read");
    let grant = crate::assets::collection::InventoryRead::new(&auth.proof, &device, coordinates)?;
    Ok(Json(app.collection.run(grant, run).await?))
}

struct IdentityContextState {
    identity_management: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
}

struct CollectionState {
    collection: Arc<crate::assets::collection::CollectionService>,
}
