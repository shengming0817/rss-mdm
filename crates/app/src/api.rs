//! One protected path: current SDK proof -> MDM capability -> private data access.
use crate::{
    AccessStore, ConfigIssue, Failure,
    audit::{Audit, FailureReason, WriteOutcome},
    enrollment::Command,
};
use crate::{
    Error,
    access::{Coordinates, InventoryResponse, InventoryService, Policy},
    config::Config,
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
struct App {
    identity: Identity,
    sessions: Sessions,
    policy: Policy,
    inventory: InventoryService,
    access: Arc<AccessStore>,
    origin: String,
    requests: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
struct RequestAuth {
    proof: Arc<VerifiedIdentity>,
    lease: Arc<Lease>,
}
async fn protect(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    if parts.method != axum::http::Method::GET
        && parts.method != axum::http::Method::HEAD
        && let Err(error) = same_origin(&app, &parts.headers)
    {
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
            parts.extensions.insert(RequestAuth {
                proof: Arc::new(proof),
                lease: Arc::new(lease),
            });
            next.run(Request::from_parts(parts, body)).await
        }
        Err(error) => error.into_response(),
    }
}

pub async fn application(
    config: Config,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    reader: Arc<InventoryReader>,
    access: Arc<AccessStore>,
) -> Result<Router, Error> {
    from_compiled(config.compile()?, clock, monotonic, reader, access).await
}
pub(crate) async fn from_compiled(
    compiled: crate::config::Compiled,
    clock: Arc<dyn Clock>,
    monotonic: Arc<dyn rss_observation::Clock>,
    reader: Arc<InventoryReader>,
    access: Arc<AccessStore>,
) -> Result<Router, Error> {
    let crate::config::Compiled { config, policy } = compiled;
    let identity = Identity::connect(&config, clock.clone()).await?;
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration(ConfigIssue::ProductOrigin))?
        .to_owned();
    let audit_tenant = config.identity.tenant_id.clone();
    let state = Arc::new(App {
        access: access.clone(),
        identity,
        sessions: Sessions::new(clock, 1000, 10000),
        policy,
        inventory: InventoryService::new(reader),
        origin: config.product_origin,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let protected = Router::new()
        .route("/enrollment-grants", post(issue_grant))
        .route("/enrollment-grants/{id}/revoke", post(revoke_grant))
        .route("/registration-requests", post(register))
        .route("/auth/me", get(me))
        .route("/devices/{id}/inventory", get(inventory))
        .route("/devices/{id}/actions", post(action))
        .route_layer(middleware::from_fn_with_state(state.clone(), protect));
    Ok(Router::new()
        .nest("/api/v1", protected)
        .route("/auth/login", post(login))
        .route(
            "/auth/callback",
            get(callback).head(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route("/api/v1/auth/logout", post(logout))
        .route("/livez", get(|| async { Json(json!({"alive":true})) }))
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
        )))
}

#[derive(Clone)]
struct Envelope {
    host: String,
    clock: Arc<dyn rss_observation::Clock>,
    access: Arc<AccessStore>,
    tenant: String,
}
async fn envelope(State(envelope): State<Envelope>, mut request: Request, next: Next) -> Response {
    let started = envelope.clock.now();
    let host = &envelope.host;
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let action = match route {
        "/api/v1/enrollment-grants" => "grant_issue",
        "/api/v1/enrollment-grants/{id}/revoke" => "grant_revoke",
        "/api/v1/registration-requests" => "registration_accept",
        "/api/v1/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        "/auth/login" | "/auth/callback" | "/api/v1/auth/logout" | "/api/v1/auth/me" => {
            "authentication"
        }
        _ => "protected_request",
    };
    let audit = Audit::new(envelope.tenant.clone(), action);
    let request_id = audit.request_id();
    let audited = request.uri().path() != "/livez";
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
    if snapshot.write_outcome != WriteOutcome::CommitNotStarted
        && matches!(
            response.extensions().get::<Error>(),
            Some(Error::Unavailable(Failure::RequestDeadline))
        )
    {
        response = Error::CommitUnknown.into_response();
    }
    let mut audit_failure = matches!(
        response.extensions().get::<Error>(),
        Some(Error::Unavailable(Failure::Audit))
    )
    .then_some(FailureReason::Transaction);
    if audited && snapshot.write_outcome != WriteOutcome::Committed {
        let status = response.status().as_u16();
        let result = if snapshot.write_outcome != WriteOutcome::CommitNotStarted && status >= 500 {
            "unknown"
        } else if status == 401 || status == 403 {
            "denied"
        } else if status >= 400 {
            "failed"
        } else if snapshot.operation_id.is_some() {
            "replay"
        } else {
            "success"
        };
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
async fn authenticate(app: &App, lease: Lease) -> Result<(VerifiedIdentity, Lease), Error> {
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
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<String>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    if !sessions::equal(&auth.lease.csrf, csrf(&headers)?) {
        return Err(Error::Forbidden);
    }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantInput {
    device_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationInput {
    device_id: String,
    grant_id: uuid::Uuid,
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
async fn enrollment(
    app: &App,
    headers: HeaderMap,
    auth: RequestAuth,
    audit: Audit,
    command: Command,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let key = operation_key(&headers)?;
    audit.operation(key, command.action());
    command.validate()?;
    audit.target(command.device());
    if !sessions::equal(&auth.lease.csrf, csrf(&headers)?) {
        return Err(Error::Forbidden);
    }
    let permit = app.policy.enrollment(&auth.proof, command.device())?;
    app.access
        .execute(permit, key, command, &audit)
        .await
        .map(Json)
}
async fn issue_grant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<GrantInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    enrollment(
        &app,
        headers,
        auth,
        audit,
        Command::Issue {
            device_id: input.map_err(|_| Error::Malformed)?.0.device_id,
        },
    )
    .await
}
async fn revoke_grant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<uuid::Uuid>,
    input: Result<Json<GrantInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    enrollment(
        &app,
        headers,
        auth,
        audit,
        Command::Revoke {
            device_id: input.map_err(|_| Error::Malformed)?.0.device_id,
            grant_id: id,
        },
    )
    .await
}
async fn register(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    input: Result<Json<RegistrationInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let input = input.map_err(|_| Error::Malformed)?.0;
    enrollment(
        &app,
        headers,
        auth,
        audit,
        Command::Consume {
            device_id: input.device_id,
            grant_id: input.grant_id,
        },
    )
    .await
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
