//! One protected path: current SDK proof -> MDM capability -> private data access.
use crate::{
    AccessStore, ConfigIssue, Failure,
    audit::{Audit, FailureReason, WriteOutcome},
    enrollment::{Create, Resume},
};
use crate::{
    Error,
    access::{Coordinates, InventoryResponse, InventoryService, Policy},
    identity::Identity,
    sessions::{self, Lease, Sessions},
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use rss_identity_client::{Clock, VerifiedIdentity};
use rss_mdm_inventory_postgres::InventoryReader;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
const COOKIE: &str = "__Host-mdm-session";
const BROWSER: &str = "__Host-mdm-login";
pub(crate) struct App {
    pub(crate) management: Arc<crate::management::Management>,
    pub(crate) identity: Identity,
    pub(crate) sessions: Sessions,
    pub(crate) policy: Arc<Policy>,
    pub(crate) inventory: InventoryService,
    pub(crate) readiness: Arc<crate::inventory_runtime::Readiness>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) windows: crate::windows::Windows,
    pub(crate) access: Arc<AccessStore>,
    pub(crate) origin: String,
    pub(crate) requests: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
pub(crate) struct RequestAuth {
    pub(crate) proof: Arc<VerifiedIdentity>,
    lease: Arc<Lease>,
}
async fn protect(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let writes =
        parts.method != axum::http::Method::GET && parts.method != axum::http::Method::HEAD;
    if writes && let Err(error) = same_origin(&app, &parts.headers) {
        return error.into_response();
    }
    let lease = match local(&app, &parts.headers) {
        Ok(lease) => lease,
        Err(error) => return error.into_response(),
    };
    let _session = match lease.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Error::Unavailable(Failure::Capacity).into_response(),
    };
    let _global = match app.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Error::Unavailable(Failure::Capacity).into_response(),
    };
    match authenticate(&app, lease).await {
        Ok((proof, lease)) => {
            if let Some(audit) = parts.extensions.get::<Audit>() {
                audit.identify(&proof);
            }
            if writes
                && !csrf(&parts.headers).is_ok_and(|token| sessions::equal(&lease.csrf, token))
            {
                return Error::Forbidden.into_response();
            }
            parts.extensions.insert(RequestAuth {
                proof: Arc::new(proof),
                lease: Arc::new(lease),
            });
            next.run(Request::from_parts(parts, body)).await
        }
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
pub(crate) async fn application(
    config: crate::config::Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    reader: Arc<InventoryReader>,
    access: Arc<AccessStore>,
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
    Ok(from_compiled(
        config.compile()?,
        clock,
        monotonic,
        reader,
        access,
        runtime,
        management,
    )
    .await?
    .browser)
}
pub(crate) async fn from_compiled(
    compiled: crate::config::Compiled,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    reader: Arc<InventoryReader>,
    access: Arc<AccessStore>,
    runtime: Arc<crate::inventory_runtime::InventoryRuntime>,
    management: Arc<crate::management::Management>,
) -> Result<crate::windows::Routers, Error> {
    let crate::config::Compiled { config, policy } = compiled;
    let policy = Arc::new(policy);
    let devices = Arc::new(crate::device::DeviceService::new(
        access.clone(),
        policy.clone(),
    ));
    let identity = Identity::connect(&config, clock.clone()).await?;
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
        sessions: Sessions::new(clock, 1000, 10000),
        policy,
        inventory: InventoryService::new(reader, devices.clone(), access.clone(), runtime.clone()),
        readiness: runtime.readiness.clone(),
        devices,
        origin: config.product_origin,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let protected = Router::new()
        .merge(crate::management::routes())
        .route("/enrollments", post(create_enrollment))
        .route("/enrollments/{id}", get(enrollment_status))
        .route("/devices/{device}/registrations", get(registrations))
        .route("/enrollments/{id}/resume", post(resume_enrollment))
        .route("/enrollments/{id}/cancel", post(cancel_enrollment))
        .route(
            "/devices/{device}/registrations/{registration}/revoke",
            post(revoke_registration),
        )
        .route("/auth/me", get(me))
        .route("/devices/{id}/inventory", get(inventory))
        .route("/devices/{id}/collection-runs/{run}", get(collection_run))
        .route("/devices/{id}/actions", post(action))
        .route_layer(middleware::from_fn_with_state(state.clone(), protect));
    let (enrollment, management) = crate::windows::routers(state.clone(), monotonic.clone());
    let browser = Router::new()
        .nest("/api/v1", protected)
        .route("/auth/login", post(login))
        .route(
            "/auth/callback",
            get(callback).head(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route("/api/v1/auth/logout", post(logout))
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
        .route("/readyz", get(ready))
        .with_state(state)
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
        "/api/v1/enrollments" => "enrollment_create",
        "/api/v1/enrollments/{id}" => "enrollment_read",
        "/api/v1/devices/{device}/registrations" => "registration_read",
        "/api/v1/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v1/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v1/devices/{device}/registrations/{registration}/revoke" => "credential_revoke",
        "/api/v1/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/collection-runs/{run}" => "collection_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        "/auth/login" | "/auth/callback" | "/api/v1/auth/logout" | "/api/v1/auth/me" => {
            "authentication"
        }
        "/EnrollmentServer/Discovery.svc" => "windows_discovery",
        "/EnrollmentServer/Policy.svc" => "windows_policy",
        "/EnrollmentServer/Enrollment.svc" => "enrollment_issue",
        "/ManagementServer/MDM.svc" => "windows_management",
        _ => "protected_request",
    };
    let soap = route.starts_with("/EnrollmentServer/");
    let audit = Audit::new(envelope.tenant.clone(), action);
    let request_id = audit.request_id();
    let audited = !matches!(request.uri().path(), "/livez" | "/readyz");
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
        tokio::time::timeout(Duration::from_secs(8), next.run(request))
            .await
            .unwrap_or_else(|_| Error::Unavailable(Failure::RequestDeadline).into_response())
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
fn cookie_raw(headers: &HeaderMap, name: &str) -> Result<Option<String>, Error> {
    let mut result = None;
    for line in headers.get_all(header::COOKIE) {
        let line = line.to_str().map_err(|_| Error::Unauthorized)?;
        if line.len() > 8192 {
            return Err(Error::Unauthorized);
        }
        for part in line.split(';') {
            if let Some((key, value)) = part.trim().split_once('=')
                && key == name
            {
                if result.is_some() {
                    return Err(Error::Unauthorized);
                }
                result = Some(value.to_owned());
            }
        }
    }
    Ok(result)
}
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, Error> {
    let value = cookie_raw(headers, name)?;
    if value.as_deref().is_some_and(|v| !sessions::valid(v)) {
        return Err(Error::Unauthorized);
    }
    Ok(value)
}

fn same_origin(app: &App, h: &HeaderMap) -> Result<(), Error> {
    if h.get_all("x-mdm-request").iter().count() != 1
        || h.get_all(header::ORIGIN).iter().count() != 1
        || h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&app.origin)
        || h.get("x-mdm-request").and_then(|v| v.to_str().ok()) != Some("1")
    {
        return Err(Error::Forbidden);
    }
    Ok(())
}
fn csrf(h: &HeaderMap) -> Result<&str, Error> {
    if h.get_all("x-csrf-token").iter().count() != 1 {
        return Err(Error::Forbidden);
    }
    h.get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Forbidden)
}
fn local(app: &App, h: &HeaderMap) -> Result<Lease, Error> {
    app.sessions
        .get(&cookie(h, COOKIE)?.ok_or(Error::Unauthorized)?)
}
pub(crate) async fn authenticate(
    app: &App,
    lease: Lease,
) -> Result<(VerifiedIdentity, Lease), Error> {
    let proof = app.identity.validate(&lease).await?;
    app.sessions.get(&lease.id)?; // Reject local logout/replacement during remote verification.
    Ok((proof, lease))
}
fn set_cookie(r: &mut Response, name: &str, value: &str, max_age: i64) -> Result<(), Error> {
    let v = HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    ))
    .map_err(|_| Error::Unavailable(Failure::Runtime))?;
    r.headers_mut().append(header::SET_COOKIE, v);
    Ok(())
}
async fn login(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, Error> {
    same_origin(&app, &headers)?;
    let presented = cookie_raw(&headers, COOKIE)?;
    let old = match presented
        .as_deref()
        .filter(|id| sessions::valid(id))
        .map(|id| app.sessions.get(id))
    {
        Some(Ok(session)) => {
            if !sessions::equal(&session.csrf, csrf(&headers)?) {
                return Err(Error::Forbidden);
            }
            presented.clone()
        }
        Some(Err(Error::Unauthorized)) | None => None,
        Some(Err(error)) => return Err(error),
    };
    let clear_stale = presented.is_some() && old.is_none();
    let browser = cookie_raw(&headers, BROWSER)?
        .filter(|value| sessions::valid(value))
        .unwrap_or_else(sessions::random);
    let (url, state, pending) = app
        .identity
        .begin(browser.clone(), old, app.sessions.now()?);
    app.sessions.begin(state, pending)?;
    let mut response = Json(json!({"authorization_url":url})).into_response();
    set_cookie(&mut response, BROWSER, &browser, 300)?;
    if clear_stale {
        set_cookie(&mut response, COOKIE, "", 0)?;
    }
    Ok(response)
}
#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: String,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    error_uri: Option<String>,
    scope: Option<String>,
}
async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    input: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, Error> {
    let c = input.map_err(|_| Error::Malformed)?.0;
    let _global = app
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable(Failure::Capacity))?;
    let browser = cookie(&headers, BROWSER)?.ok_or(Error::Unauthorized)?;
    let old = cookie(&headers, COOKIE)?;
    let pending = app.sessions.consume(&c.state, &browser, old.as_deref())?;
    // Error descriptions and URIs are never followed, rendered or logged.
    let _ = (c.error_description, c.error_uri, c.scope);
    if c.iss
        .as_deref()
        .is_some_and(|iss| !app.identity.is_issuer(iss))
    {
        return Err(Error::Unauthorized);
    }
    if let Some(error) = c.error {
        return Err(match error.as_str() {
            "access_denied"
            | "invalid_request"
            | "unauthorized_client"
            | "unsupported_response_type"
            | "invalid_scope" => Error::Unauthorized,
            "server_error" | "temporarily_unavailable" => {
                Error::Unavailable(Failure::IdentityServer)
            }
            _ => Error::Unavailable(Failure::IdentityProtocol),
        });
    }
    let code = c
        .code
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or(Error::Malformed)?;
    let session = app.identity.finish(code, pending).await?;
    let age = session.expires - app.sessions.now()?;
    let id = app.sessions.establish(old.as_deref(), session)?;
    let mut response = Redirect::to("/api/v1/auth/me").into_response();
    set_cookie(&mut response, COOKIE, &id, age)?;
    Ok(response)
}
async fn me(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Value>, Error> {
    let proof = &auth.proof;
    Ok(Json(
        json!({"subject":proof.subject(),"tenant_id":proof.tenant_id(),"client_id":proof.client_id(),"roles":app.policy.roles(proof)?,"csrf_token":auth.lease.csrf,"expires_at":proof.expires_at()}),
    ))
}

async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, Error> {
    same_origin(&app, &headers)?;
    let id = cookie(&headers, COOKIE)?.ok_or(Error::Unauthorized)?;
    app.sessions.remove(&id, csrf(&headers)?)?;
    let mut response = axum::http::StatusCode::NO_CONTENT.into_response();
    set_cookie(&mut response, COOKIE, "", 0)?;
    Ok(response)
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
    let grant = app
        .policy
        .inventory(&auth.proof, &id, input.map_err(|_| Error::Malformed)?.0)?;
    app.inventory.read(grant).await.map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action: String,
}
async fn action(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    if rss_observation::Id::new(&id).is_ok() {
        audit.target(&id);
    }
    audit.set_action("device_action");
    let _grant = app.policy.dangerous(&auth.proof, &id)?;
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
    let permission = app.policy.enrollment(&auth.proof, &input.device_id)?;
    audit.target(&input.device_id);
    let reference = app.sessions.reference(&auth.lease)?;
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
    let permission = app.policy.enrollment(&auth.proof, &device)?;
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
        .registration_list(&app.policy, &auth.proof, &device, page)
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
    let permission = app.policy.enrollment(&auth.proof, &device)?;
    audit.target(&device);
    let reference = app.sessions.reference(&auth.lease)?;
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
    let permission = app.policy.enrollment(&auth.proof, &device)?;
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
    let grant = app.policy.inventory(&auth.proof, &device, coordinates)?;
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
            Failure::IdentityTransport,
            Failure::IdentityServer,
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
    #[test]
    fn oauth_extensions_are_ignored_but_known_duplicates_rejected() {
        for query in [
            "state=s&code=c&session_state=extension",
            "state=s&error=access_denied&custom=extension",
        ] {
            assert!(
                Query::<Callback>::try_from_uri(
                    &format!("/auth/callback?{query}").parse().unwrap()
                )
                .is_ok()
            );
        }
        for query in [
            "state=a&state=b&code=c",
            "state=a&code=b&code=c",
            "state=a&iss=a&iss=b",
        ] {
            assert!(
                Query::<Callback>::try_from_uri(
                    &format!("/auth/callback?{query}").parse().unwrap()
                )
                .is_err()
            );
        }
    }
}
