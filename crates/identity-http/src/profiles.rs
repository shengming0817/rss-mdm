use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, put, route_module};
// Profile management shares the cookie/CSRF and transaction policy owners.
use crate::{AppState, accounts::Error, boundary::*};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_identity_core::{PrincipalId, account::AccountKey};
use rss_transactional_messaging::fence::ExecutionBinding;
use uuid::Uuid;
mod dto;

pub fn routes(state: Option<&AppState>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct LocalProfiles for [Browser] { local, update, receipt } }
    let routes = LocalProfiles {
        local: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/profile",
            get(local, &IDENTITY, ACTION),
        ),
        update: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/profile",
            put(update, &IDENTITY, ACTION),
        ),
        receipt: Route::new(
            "/api/v1/identity/tenants/{tenant}/accounts/{principal}/profile/operations/{operation}",
            get(receipt, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, state, 98304).bind_with(state, Clone::clone)
}
pub fn raw_profile_route(state: Option<&AppState>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct CurrentProfile for [Browser] { current } }
    let routes = CurrentProfile {
        current: Route::new(
            "/api/v1/identity/tenants/{tenant}/profile",
            get(current, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, state, 98304).bind_with(state, Clone::clone)
}

async fn actor(
    s: &AppState,
    binding: ExecutionBinding,
    h: &HeaderMap,
    b: Deadline,
    write: bool,
) -> Result<rss_identity_postgres::AuthenticatedSession, Error> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if !request_marker(h)? {
            return Err(FORBIDDEN.into());
        }
        csrf(h, &secret)?;
    }
    Ok(s.authority.inspect_session(binding, secret, b).await?)
}
fn target(t: &str, p: &str) -> Result<AccountKey, Error> {
    Ok(AccountKey {
        tenant: tenant(t)?,
        principal: PrincipalId::parse(p).map_err(|_| BAD)?,
    })
}
async fn current(
    State(s): State<AppState>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
) -> Result<Json<dto::Observation>, Error> {
    let actor = actor(&s, binding, &h, b, false).await?;
    let profile = s.authority.current_profile(&actor, b).await?;
    Ok(Json(dto::Observation::from(profile.view()?)))
}
async fn local(
    State(s): State<AppState>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
) -> Result<Json<dto::Local>, Error> {
    let actor = actor(&s, binding, &h, b, false).await?;
    Ok(Json(dto::Local::from(
        s.authority
            .read_local_profile(&actor, target(&t, &p)?, b)
            .await?,
    )))
}
async fn update(
    State(s): State<AppState>,
    Path((t, p)): Path<(String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Deferred(request, _): Deferred<dto::Change, WRITE>,
) -> Result<Json<dto::Receipt>, Error> {
    let actor = actor(&s, binding, request.headers(), b, true).await?;
    let bytes = read_body(request, b, |request| {
        axum::body::to_bytes(request.into_body(), 98_304)
    })
    .await?;
    let change: dto::Change = serde_json::from_slice(&bytes).map_err(|_| BAD)?;
    let change = change.try_into().map_err(|_| BAD)?;
    Ok(Json(dto::Receipt::from(
        s.authority
            .update_local_profile(actor, target(&t, &p)?, change, b)
            .await?,
    )))
}
async fn receipt(
    State(s): State<AppState>,
    Path((t, p, o)): Path<(String, String, String)>,
    Execution(binding): Execution<false>,
    Extension(b): Extension<Deadline>,
    Headers(h): Headers<PASSIVE>,
) -> Result<Json<Option<dto::Receipt>>, Error> {
    let actor = actor(&s, binding, &h, b, false).await?;
    let operation = Uuid::parse_str(&o)
        .map_err(|_| BAD)?
        .try_into()
        .map_err(|_| BAD)?;
    Ok(Json(
        s.authority
            .local_profile_receipt(&actor, target(&t, &p)?, operation, b)
            .await?
            .map(dto::Receipt::from),
    ))
}
