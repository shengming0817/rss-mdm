use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, post, route_module};
use crate::{AppState, boundary::*};
use axum::{
    Extension, Json,
    extract::{FromRequest, Query, State},
    http::HeaderMap,
};
use rss_identity_core::SessionId;
use rss_identity_core::{
    account::{LoginKey, Password},
    session::SessionSecret,
};
use rss_identity_postgres::{AttemptSource, AuthenticatedSession, AuthorityError, IssuedSession};
use rss_transactional_messaging::fence::ExecutionBinding;
use serde::Deserialize;

type Result<T> = std::result::Result<T, HttpError>;
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    login: String,
    password: String,
}
pub fn issued_session_parts(
    value: &IssuedSession,
) -> Result<(crate::SessionBody, axum::http::HeaderValue)> {
    let cookie = rss_identity_web_credentials::issued_cookie(value)?;
    Ok((
        project_session(value.identity(), value.view(), cookie.csrf_token),
        cookie.header,
    ))
}
fn issued(value: IssuedSession) -> Result<CookieJson<crate::SessionBody>> {
    let (body, cookie) = issued_session_parts(&value)?;
    Ok(CookieJson {
        body,
        cookie: Some(cookie),
    })
}
fn project_session(
    identity: &rss_identity_postgres::SessionIdentity,
    view: &rss_identity_postgres::SessionView,
    csrf_token: String,
) -> crate::dto::SessionBody {
    use crate::dto::{Identity, SessionBody, SessionInfo};
    SessionBody {
        identity: Identity {
            principal_id: identity.principal_id.as_uuid().to_string(),
            has_local_password: identity.has_local_password,
        },
        session: SessionInfo {
            id: view.id.to_string(),
            issued_at: view.issued_at,
            idle_expires_at: view.idle_expires_at,
            absolute_expires_at: view.absolute_expires_at,
        },
        csrf_token,
    }
}
async fn login(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<Login, LOGIN>,
) -> Result<CookieJson<crate::SessionBody>> {
    if !request_marker(request.headers())? {
        return Err(FORBIDDEN);
    }
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&peer.to_string()).map_err(HttpError::from)?;
    let replacement = match login_cookie(request.headers())? {
        Some(secret) => {
            let token = SessionSecret::parse(secret.expose().into()).map_err(|_| UNAUTH)?;
            match state
                .authority
                .inspect_session(binding, token, budget)
                .await
            {
                Ok(proof) => {
                    csrf(request.headers(), &secret)?;
                    Some(proof)
                }
                Err(AuthorityError::Rejected) => None,
                Err(e) => return Err(e.into()),
            }
        }
        None => None,
    };
    // Only inbound body reading is cancelled here; no write transaction has started.
    let Json(input) = read_body(request, budget, |request| {
        Json::<Login>::from_request(request, &state)
    })
    .await?;
    let password = Password::new(input.password).map_err(|_| UNAUTH)?;
    let login = LoginKey::parse(&input.login).map_err(|_| UNAUTH)?;
    issued(
        state
            .authority
            .login_local(binding, login, password, source, replacement, budget)
            .await?,
    )
}
async fn current(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<PASSIVE>,
) -> Result<Json<crate::SessionBody>> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let csrf = secret.csrf();
    let proof = state
        .authority
        .inspect_session(binding, secret, budget)
        .await?;
    Ok(Json(project_session(proof.identity(), proof.view(), csrf)))
}
async fn refresh(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<ROTATE>,
) -> Result<CookieJson<crate::SessionBody>> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    csrf(&headers, &secret)?;
    issued(
        state
            .authority
            .refresh_session(binding, secret, budget)
            .await?,
    )
}
async fn actor(
    state: &AppState,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    budget: Deadline,
) -> Result<AuthenticatedSession> {
    let secret = cookie(headers)?.ok_or(UNAUTH)?;
    csrf(headers, &secret)?;
    Ok(state
        .authority
        .inspect_session(binding, secret, budget)
        .await?)
}
async fn logout(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<ROTATE>,
) -> Result<SignedOut> {
    let proof = actor(&state, binding, &headers, budget).await?;
    state
        .authority
        .revoke_current_session(proof, budget)
        .await?;
    Ok(SignedOut(
        rss_identity_web_credentials::clear_session_cookie(),
    ))
}
async fn logout_all(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<ROTATE>,
) -> Result<SignedOut> {
    let proof = actor(&state, binding, &headers, budget).await?;
    state.authority.revoke_all_sessions(proof, budget).await?;
    Ok(SignedOut(
        rss_identity_web_credentials::clear_session_cookie(),
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Pagination {
    #[schemars(with = "Option<uuid::Uuid>")]
    cursor: Option<SessionId>,
    limit: Option<u16>,
}
async fn list(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    query: std::result::Result<Query<Pagination>, axum::extract::rejection::QueryRejection>,
    Headers(headers): Headers<PASSIVE>,
) -> Result<Json<crate::dto::SessionPage>> {
    let Query(page) = query.map_err(|_| BAD)?;
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let proof = state
        .authority
        .inspect_session(binding, secret, budget)
        .await?;
    Ok(Json(crate::dto::SessionPage::from(
        state
            .authority
            .list_sessions(proof, page.cursor, page.limit.unwrap_or(50), budget)
            .await?,
    )))
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reauthentication {
    password: String,
}
async fn reauthenticate(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<Reauthentication, WRITE>,
) -> Result<CookieJson<crate::SessionBody>> {
    if !request_marker(request.headers())? {
        return Err(FORBIDDEN);
    }
    let proof = actor(&state, binding, request.headers(), budget).await?;
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&peer.to_string())?;
    let Json(input) = read_body(request, budget, |request| {
        Json::<Reauthentication>::from_request(request, &state)
    })
    .await?;
    issued(
        state
            .authority
            .reauthenticate_local(
                proof,
                Password::new(input.password).map_err(|_| UNAUTH)?,
                source,
                budget,
            )
            .await?,
    )
}

pub fn session_routes(state: Option<&AppState>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Session for [Browser] { login, reauthenticate, current, refresh, logout, logout_all, list } }
    let routes = Session {
        login: Route::new(
            "/api/v1/identity/tenants/{tenant}/login",
            post(login, &IDENTITY, ACTION),
        ),
        reauthenticate: Route::new(
            "/api/v1/identity/tenants/{tenant}/session/reauthenticate",
            post(reauthenticate, &IDENTITY, ACTION),
        ),
        current: Route::new(
            "/api/v1/identity/tenants/{tenant}/session",
            get(current, &IDENTITY, ACTION),
        ),
        refresh: Route::new(
            "/api/v1/identity/tenants/{tenant}/session/refresh",
            post(refresh, &IDENTITY, ACTION),
        ),
        logout: Route::new(
            "/api/v1/identity/tenants/{tenant}/session/logout",
            post(logout, &IDENTITY, ACTION),
        ),
        logout_all: Route::new(
            "/api/v1/identity/tenants/{tenant}/sessions/logout-all",
            post(logout_all, &IDENTITY, ACTION),
        ),
        list: Route::new(
            "/api/v1/identity/tenants/{tenant}/sessions",
            get(list, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, state, 4096).bind_with(state, Clone::clone)
}
pub fn local_routes(
    runtime: Option<(&AppState, &rss_identity_postgres::WebauthnAuthority)>,
) -> Router<(), impl Declaration + use<>> {
    let (state, webauthn) = runtime.unzip();
    route_module! { struct Local for [Browser] { sessions, accounts, profiles, passkeys } }
    Local {
        sessions: session_routes(state),
        accounts: crate::accounts::routes(state),
        profiles: crate::profiles::routes(state),
        passkeys: crate::webauthn::routes(state, webauthn),
    }
    .assemble()
}
