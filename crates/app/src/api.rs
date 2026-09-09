//! One protected path: current SDK proof -> MDM capability -> private data access.
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
    origin: String,
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
    match authenticate(&app, &parts.headers).await {
        Ok((proof, lease)) => {
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
    config: &Config,
    clock: Arc<dyn Clock>,
    reader: Arc<InventoryReader>,
) -> Result<Router, Error> {
    config.validate()?;
    let state = Arc::new(App {
        identity: Identity::connect(config, clock.clone()).await?,
        sessions: Sessions::new(clock, 1000, 10000),
        policy: Policy::new(
            &config.identity.tenant_id,
            &config.identity.client_id,
            config.bindings.clone(),
        )?,
        inventory: InventoryService::new(reader),
        origin: config.product_origin.clone(),
    });
    let host = config
        .product_origin
        .strip_prefix("https://")
        .ok_or(Error::Configuration)?
        .to_owned();
    let protected = Router::new()
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
        .layer(middleware::from_fn_with_state(host, envelope)))
}

async fn envelope(State(host): State<String>, request: Request, next: Next) -> Response {
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
        tokio::time::timeout(Duration::from_secs(10), next.run(request))
            .await
            .unwrap_or_else(|_| Error::Unavailable.into_response())
    };
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
async fn authenticate(app: &App, h: &HeaderMap) -> Result<(VerifiedIdentity, Lease), Error> {
    let lease = local(app, h)?;
    let proof = app.identity.validate(&lease).await?;
    app.sessions.get(&lease.id)?; // Reject local logout/replacement during remote verification.
    Ok((proof, lease))
}
fn set_cookie(r: &mut Response, name: &str, value: &str, max_age: i64) -> Result<(), Error> {
    let v = HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    ))
    .map_err(|_| Error::Unavailable)?;
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
#[serde(deny_unknown_fields)]
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
    let browser = cookie(&headers, BROWSER)?.ok_or(Error::Unauthorized)?;
    let old = cookie(&headers, COOKIE)?;
    let pending = app.sessions.consume(&c.state, &browser, old.as_deref())?;
    // Error descriptions and URIs are never followed, rendered or logged.
    let _ = (c.error_description, c.error_uri, c.scope);
    if c.error.is_some()
        || c.iss
            .as_deref()
            .is_some_and(|iss| !app.identity.is_issuer(iss))
    {
        return Err(Error::Unauthorized);
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
    input: Result<Query<Coordinates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<InventoryResponse>, Error> {
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
    input: Result<Json<Action>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
    if !sessions::equal(&auth.lease.csrf, csrf(&headers)?) {
        return Err(Error::Forbidden);
    }
    let _grant = app.policy.dangerous(&auth.proof, &id)?;
    if input.map_err(|_| Error::Malformed)?.0.action != "wipe" {
        return Err(Error::Malformed);
    }
    Err(Error::Unsupported)
}
