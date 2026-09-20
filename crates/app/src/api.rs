//! One protected path: current SDK proof -> MDM capability -> private data access.
use crate::{
    AccessStore, ConfigIssue, Failure,
    audit::{Audit, FailureReason, WriteOutcome},
    enrollment::{Create, Resume},
};
use crate::{
    Error,
    access::{Coordinates, IdentityManagementPolicy, InventoryResponse, InventoryService},
    enrollment_credentials::Credentials,
    identity::Identity,
};
use crate::{clock::Clock, identity::Principal};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_identity_core::session::SessionSecret;
use rss_mdm_inventory_postgres::InventoryReader;
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::{sync::Arc, time::Duration};
pub(crate) struct App {
    pub(crate) management: Arc<crate::management::Management>,
    pub(crate) identity: Identity,
    pub(crate) credentials: Credentials,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) identity_management: Arc<IdentityManagementPolicy>,
    pub(crate) inventory: InventoryService,
    pub(crate) readiness: Arc<crate::inventory_runtime::Readiness>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) windows: crate::windows::Windows,
    pub(crate) access: Arc<AccessStore>,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
pub(crate) struct RequestAuth {
    pub(crate) proof: Arc<Principal>,
    credential: Arc<SessionSecret>,
}
async fn protect(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    authenticate_and_run(app, request, next, true).await
}
async fn identity_only(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    authenticate_and_run(app, request, next, false).await
}
async fn authenticate_and_run(
    app: Arc<App>,
    request: Request,
    next: Next,
    authorization: bool,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let activity =
        if parts.method == axum::http::Method::GET || parts.method == axum::http::Method::HEAD {
            rss_identity_http_axum::SessionActivity::Passive
        } else {
            rss_identity_http_axum::SessionActivity::Active
        };
    let _global = match app.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Error::Unavailable(Failure::Capacity).into_response(),
    };
    match app
        .identity
        .authenticate_request(&parts.headers, activity)
        .await
    {
        Ok((proof, credential)) => {
            if let Some(audit) = parts.extensions.get::<Audit>() {
                audit.identify(&proof);
            }
            // Authentication has settled. Authorization I/O and the handler share the host budget.
            tokio::time::timeout(Duration::from_secs(8), async {
                let proof = if authorization {
                    match proof.load_authorization(&app.access).await {
                        Ok(proof) => proof,
                        Err(error) => return error.into_response(),
                    }
                } else {
                    proof
                };
                parts.extensions.insert(RequestAuth {
                    proof: Arc::new(proof),
                    credential: Arc::new(credential),
                });
                next.run(Request::from_parts(parts, body)).await
            })
            .await
            .unwrap_or_else(|_| Error::Unavailable(Failure::RequestDeadline).into_response())
        }
        Err(response) => response,
    }
}

#[cfg(test)]
pub(crate) async fn application(
    config: crate::config::Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    reader: Arc<InventoryReader>,
    access: Arc<AccessStore>,
    identity: Option<Identity>,
) -> Result<Router, Error> {
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.clone(),
        rss_request_context::TenantId::parse(&config.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?,
        monotonic.clone(),
    )
    .await?;
    let management = config
        .management
        .open(
            rss_request_context::TenantId::parse(&config.identity.tenant_id)
                .map_err(|_| Error::Malformed)?,
            clock.clone(),
            |_| {},
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
    Ok(from_compiled(
        compiled,
        AssemblyDependencies {
            clock,
            monotonic,
            reader,
            access,
            runtime,
            management,
            identity,
        },
    )?
    .browser)
}
pub(crate) struct AssemblyDependencies {
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) monotonic: Arc<dyn rss_observation::Clock>,
    pub(crate) reader: Arc<InventoryReader>,
    pub(crate) access: Arc<AccessStore>,
    pub(crate) runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub(crate) management: Arc<crate::management::Management>,
    pub(crate) identity: Identity,
}
pub(crate) fn from_compiled(
    compiled: crate::config::Compiled,
    dependencies: AssemblyDependencies,
) -> Result<crate::windows::Routers, Error> {
    let crate::config::Compiled {
        config,
        identity_management,
    } = compiled;
    let AssemblyDependencies {
        clock,
        monotonic,
        reader,
        access,
        runtime,
        management,
        identity,
    } = dependencies;
    let devices = Arc::new(crate::device::DeviceService::new(
        access.clone(),
        config.identity.tenant_id.clone(),
    ));
    let authentication = identity.routes();
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    let audit_tenant = config.identity.tenant_id.clone();
    let windows = crate::windows::Windows::load(
        config.windows,
        clock
            .unix_seconds()
            .map_err(|_| Error::Unavailable(Failure::Clock))?,
    )?;
    let state = Arc::new(App {
        management,
        windows,
        access: access.clone(),
        identity,
        credentials: Credentials::new(monotonic.clone(), 10000),
        clock,
        identity_management,
        inventory: InventoryService::new(reader, devices.clone(), access.clone(), runtime.clone()),
        readiness: runtime.readiness.clone(),
        devices,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let protected = Router::new()
        .merge(crate::management::routes())
        .merge(crate::authorization::routes())
        .route("/enrollments", post(create_enrollment))
        .route("/enrollments/{id}", get(enrollment_status))
        .route("/devices/{device}/registrations", get(registrations))
        .route("/enrollments/{id}/resume", post(resume_enrollment))
        .route("/enrollments/{id}/cancel", post(cancel_enrollment))
        .route(
            "/devices/{device}/registrations/{registration}/revoke",
            post(revoke_registration),
        )
        .route("/devices/{id}/inventory", get(inventory))
        .route("/devices/{id}/collection-runs/{run}", get(collection_run))
        .route("/devices/{id}/actions", post(action))
        .route_layer(middleware::from_fn_with_state(state.clone(), protect));
    let (enrollment, management) = crate::windows::routers(state.clone(), monotonic.clone());
    let host_context = Router::new()
        .route(
            "/api/identity-host/v1/tenants/{tenant}/context",
            get(identity_context),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), identity_only));
    let browser = Router::new()
        .merge(host_context)
        .nest("/api/v1", protected)
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
        .route("/readyz", get(ready))
        .with_state(state)
        .merge(authentication)
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(
            Envelope {
                host,
                clock: monotonic,
                access,
                tenant: audit_tenant,
            },
            envelope,
        ));
    Ok(crate::windows::Routers {
        browser,
        enrollment,
        management,
    })
}

#[derive(Clone)]
pub(crate) struct Envelope {
    pub(crate) host: String,
    pub(crate) clock: Arc<dyn rss_observation::Clock>,
    pub(crate) access: Arc<AccessStore>,
    pub(crate) tenant: String,
}
pub(crate) async fn envelope(
    State(envelope): State<Envelope>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let host = &envelope.host;
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let action = match route {
        "/api/v1/authorization" => "authorization_effective_read",
        "/api/v1/authorization/rules" => "authorization_rules_read",
        "/api/v1/authorization/user-groups" => "authorization_groups_read",
        "/api/v1/authorization/user-groups/{id}/members" => "authorization_members_read",
        "/api/v1/authorization/departments" => "authorization_departments_read",
        "/api/v1/authorization/rules/{id}" | "/api/v1/authorization/user-groups/{id}" => {
            "authorization_write"
        }
        "/api/v1/enrollments" => "enrollment_create",
        "/api/v1/enrollments/{id}" => "enrollment_read",
        "/api/v1/devices/{device}/registrations" => "registration_read",
        "/api/v1/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v1/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v1/devices/{device}/registrations/{registration}/revoke" => "credential_revoke",
        "/api/v1/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/collection-runs/{run}" => "collection_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        path if path.starts_with("/api/v2/") => "authentication",
        "/EnrollmentServer/Discovery.svc" => "windows_discovery",
        "/EnrollmentServer/Policy.svc" => "windows_policy",
        "/EnrollmentServer/Enrollment.svc" => "enrollment_issue",
        "/ManagementServer/MDM.svc" => "windows_management",
        _ => "protected_request",
    };
    let soap = route.starts_with("/EnrollmentServer/");
    let audit = Audit::new(envelope.tenant.clone(), action);
    let request_id = audit.request_id();
    // Native authentication commits its own atomic security event. A second product
    // audit must not replace that settled response (including rotated credentials).
    let audited =
        !matches!(request.uri().path(), "/livez" | "/readyz") && !route.starts_with("/api/v2/");
    request.extensions_mut().insert(audit.clone());
    let mut response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(host.as_str())
    {
        Error::Malformed.into_response()
    } else {
        bounded_body(request, next).await
    };
    let snapshot = audit.snapshot();
    if matches!(
        response.extensions().get::<Error>(),
        Some(Error::Unavailable(Failure::RequestDeadline))
    ) {
        response = snapshot.write_outcome.deadline_error().into_response();
    }
    let mut audit_failure = matches!(
        response.extensions().get::<Error>(),
        Some(Error::Unavailable(Failure::Audit))
    )
    .then_some(FailureReason::Transaction);
    if audited && snapshot.write_outcome != WriteOutcome::Committed {
        let status = response.status().as_u16();
        let result = audit_result(&response, &snapshot);
        {
            let store = &envelope.access;
            if !matches!(
                tokio::time::timeout(Duration::from_secs(2), store.record(&audit, status, result))
                    .await,
                Ok(Ok(()))
            ) {
                audit_failure = Some(FailureReason::Persistent);
                response = Error::Unavailable(Failure::Audit).into_response();
            }
        }
    }
    if soap
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"application/soap+xml"))
        && let Some(error) = response.extensions().get::<Error>().copied()
    {
        response = crate::windows::fault(None, error);
    }
    if let Some(key) = snapshot.operation_id {
        response.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_str(&key.to_string()).expect("UUID"),
        );
    }
    audit.finalize(audit_failure);
    eprintln!(
        "{}",
        json!({"event":"mdm_request","request_id":request_id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis(),"error":response.extensions().get::<Error>()})
    );
    secure_response(response, request_id)
}
pub(crate) fn secure_response(mut response: Response, request_id: uuid::Uuid) -> Response {
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID header"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
async fn bounded_body(request: Request, next: Next) -> Response {
    // Bound ingress before starting any transaction. Component operations then settle
    // within their own budgets; product operations are bounded after authentication.
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(
        Duration::from_secs(8),
        axum::body::to_bytes(body, 2 * 1024 * 1024),
    )
    .await
    {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Ok(Err(_)) => axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => Error::Unavailable(Failure::RequestDeadline).into_response(),
    }
}

fn audit_result(response: &Response, snapshot: &crate::audit::Snapshot) -> &'static str {
    let status = response.status().as_u16();
    if matches!(
        response.extensions().get::<Error>(),
        Some(Error::CommitUnknown)
    ) || snapshot.write_outcome == WriteOutcome::Unknown && status >= 500
    {
        "unknown"
    } else if status == 401
        || status == 403
        || matches!(
            response.extensions().get::<Error>(),
            Some(Error::Unauthorized | Error::Forbidden)
        )
    {
        "denied"
    } else if status >= 400 {
        "failed"
    } else if let Some(result) = snapshot.management_result {
        result.audit_tag()
    } else if snapshot.operation_id.is_some() {
        "replay"
    } else {
        "success"
    }
}
pub(crate) async fn authenticate(app: &App, secret: SessionSecret) -> Result<Principal, Error> {
    app.identity
        .authenticate(secret)
        .await?
        .load_authorization(&app.access)
        .await
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityHostContext {
    tenant_id: String,
    principal_id: String,
    session_id: String,
    navigation: crate::access::IdentityNavigation,
}
async fn identity_context(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> Result<Json<IdentityHostContext>, Error> {
    let proof = &auth.proof;
    if tenant != proof.tenant_id() {
        return Err(Error::Unauthorized);
    }
    Ok(Json(IdentityHostContext {
        tenant_id: proof.tenant_id().to_owned(),
        principal_id: proof.principal_id().to_owned(),
        session_id: proof.session_id(),
        navigation: app.identity_management.identity_navigation(proof)?,
    }))
}
async fn inventory(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<Audit>,
    input: Result<Query<Coordinates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<InventoryResponse>, Error> {
    if rss_observation::Id::new(&id).is_ok() {
        audit.target(&id);
    }
    audit.set_action("inventory_read");
    let grant = auth
        .proof
        .inventory(&id, input.map_err(|_| Error::Malformed)?.0)?;
    app.inventory.read(grant).await.map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action: String,
}
async fn action(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    if rss_observation::Id::new(&id).is_ok() {
        audit.target(&id);
    }
    audit.set_action("device_action");
    let _grant = auth.proof.dangerous(&id)?;
    if input.map_err(|_| Error::Malformed)?.0.action != "wipe" {
        return Err(Error::Malformed);
    }
    Err(Error::Unsupported)
}

fn operation_key(headers: &HeaderMap) -> Result<uuid::Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error::Malformed);
    }
    let id = uuid::Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Malformed)?,
    )
    .map_err(|_| Error::Malformed)?;
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    Ok(id)
}
fn write_key(
    headers: &HeaderMap,
    audit: &Audit,
    action: &'static str,
) -> Result<uuid::Uuid, Error> {
    let key = operation_key(headers)?;
    audit.operation(key, action);
    Ok(key)
}
async fn create_enrollment(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let key = write_key(&headers, &audit, "enrollment_create")?;
    let input = input.map_err(|_| Error::Malformed)?.0;
    let permission = auth.proof.enrollment(&input.device_id)?;
    audit.target(&input.device_id);
    let reference = app.credentials.insert(
        SessionSecret::parse(auth.credential.expose().into()).map_err(|_| Error::Unauthorized)?,
    )?;
    app.access
        .create_enrollment(permission, &input.password, reference, key, &audit)
        .await
        .map(Json)
}
async fn enrollment_status(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<Json<crate::enrollment::read::Status>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let device = app.access.enrollment_target(&auth.proof, id).await?;
    let permission = auth.proof.enrollment(&device)?;
    audit.target(&device);
    app.access.enrollment_status(permission, id).await.map(Json)
}
async fn registrations(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    query: Result<Query<crate::enrollment::read::Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::enrollment::read::Registrations>, Error> {
    let Path(device) = path.map_err(|_| Error::Malformed)?;
    let Query(page) = query.map_err(|_| Error::Malformed)?;
    audit.target(&device);
    app.access
        .registration_list(&auth.proof, &device, page)
        .await
        .map(Json)
}
async fn resume_enrollment(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "enrollment_resume")?;
    let input = input.map_err(|_| Error::Malformed)?.0;
    let device = app.access.enrollment_target(&auth.proof, id).await?;
    let permission = auth.proof.enrollment(&device)?;
    audit.target(&device);
    let reference = app.credentials.insert(
        SessionSecret::parse(auth.credential.expose().into()).map_err(|_| Error::Unauthorized)?,
    )?;
    app.access
        .change_enrollment(
            permission,
            id,
            Some((&input.password, reference)),
            key,
            &audit,
        )
        .await
        .map(Json)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}
async fn cancel_enrollment(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
    input: Result<Json<EmptyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let Json(EmptyRequest {}) = input.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "enrollment_cancel")?;
    let device = app.access.enrollment_target(&auth.proof, id).await?;
    let permission = auth.proof.enrollment(&device)?;
    audit.target(&device);
    app.access
        .change_enrollment(permission, id, None, key, &audit)
        .await
        .map(Json)
}
async fn revoke_registration(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<(String, uuid::Uuid)>, axum::extract::rejection::PathRejection>,
    input: Result<Json<EmptyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::device::RevocationReceipt>, Error> {
    let Path((device, registration)) = path.map_err(|_| Error::Malformed)?;
    let Json(EmptyRequest {}) = input.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "credential_revoke")?;
    audit.target(&device);
    app.devices
        .revoke_inner(&auth.proof, &device, registration, key, &audit)
        .await
        .map(Json)
}

async fn ready(State(app): State<Arc<App>>) -> Response {
    if app.readiness.ready() {
        Json(json!({"ready":true})).into_response()
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready":false})),
        )
            .into_response()
    }
}
async fn collection_run(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    path: Result<Path<(String, uuid::Uuid)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<Coordinates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::access::CollectionResponse>, Error> {
    let Path((device, run)) = path.map_err(|_| Error::Malformed)?;
    let Query(coordinates) = query.map_err(|_| Error::Malformed)?;
    audit.target(&device);
    audit.set_action("collection_read");
    let grant = auth.proof.inventory(&device, coordinates)?;
    Ok(Json(app.inventory.run(grant, run).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn audit_failure_logs_preserve_action_and_origin() {
        use tower::ServiceExt;
        const CHILD: &str = "MDM_AUDIT_LOG_TEST";
        if let Ok(mode) = std::env::var(CHILD) {
            let access = Arc::new(AccessStore::unconnected());
            access.close().await;
            let router = Router::new()
                .route(
                    "/api/v1/devices/{id}/inventory",
                    get(move || async move {
                        if mode == "transaction" {
                            Error::Unavailable(Failure::Audit).into_response()
                        } else {
                            Json(json!({"sensitive":"inventory-result"})).into_response()
                        }
                    }),
                )
                .layer(middleware::from_fn_with_state(
                    Envelope {
                        host: "mdm.example.test".into(),
                        clock: monotonic(),
                        access,
                        tenant: "11111111-1111-4111-8111-111111111111".into(),
                    },
                    envelope,
                ));
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/devices/sensitive-target/inventory")
                        .header("host", "mdm.example.test")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            return;
        }
        for mode in ["read", "transaction"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "api::tests::audit_failure_logs_preserve_action_and_origin",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let events: Vec<Value> = stderr
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["event"] == "audit_failure")
                .collect();
            assert_eq!(events.len(), 1, "{mode}: {stderr}");
            assert_eq!(events[0]["reason"], "persistent_audit_unavailable");
            assert_eq!(events[0]["action"], "inventory_read");
            assert!(!stderr.contains("sensitive-target"));
            assert!(!stderr.contains("inventory-result"));
        }
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "test fixture selects the monotonic provider outside request handling"
    )]
    fn monotonic() -> Arc<dyn rss_observation::Clock> {
        Arc::new(crate::Monotonic(std::time::Instant::now))
    }
    #[tokio::test]
    async fn request_diagnostics_keep_causes_internal_and_issue_request_ids() {
        use tower::ServiceExt;
        for reason in [
            Failure::RequestDeadline,
            Failure::IdentityStorage,
            Failure::InventoryPool,
            Failure::InventoryQuery,
            Failure::Clock,
            Failure::Capacity,
        ] {
            let router = Router::new()
                .route(
                    "/livez",
                    get(move || async move { Error::Unavailable(reason) }),
                )
                .layer(middleware::from_fn_with_state(
                    Envelope {
                        host: "mdm.example.test".to_owned(),
                        clock: monotonic(),
                        access: Arc::new(AccessStore::unconnected()),
                        tenant: "11111111-1111-4111-8111-111111111111".into(),
                    },
                    envelope,
                ));
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/livez")
                        .header("host", "mdm.example.test")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(
                uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).is_ok()
            );
            assert!(matches!(
                response.extensions().get::<Error>(),
                Some(Error::Unavailable(_))
            ));
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap(),
                json!({"code":"service_unavailable"})
            );
        }
    }
}
