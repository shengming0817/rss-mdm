use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, post, route_module};
// Explicit programmatic routes; hosts own TLS, trusted ClientAddress and IP admission.
use crate::{AppState, boundary::*};
use axum::{
    Extension, Json,
    extract::{FromRequest, Request, State},
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rss_identity_core::account::{LoginKey, Password};
use rss_identity_postgres::{AttemptSource, AuthorityError};
use rss_identity_web_credentials::{bearer_credential, bearer_presentation};
use serde::Deserialize;

/// Opt-in: mount only after applying the product's programmatic network admission.
/// The browser router does not implicitly enable these routes.
pub fn bearer_routes(state: Option<&AppState>) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Bearer for [Browser] { login, logout } }
    let routes = Bearer {
        login: Route::new(
            "/api/v1/identity/tenants/{tenant}/bearer/login",
            post(login, &IDENTITY, ACTION),
        ),
        logout: Route::new(
            "/api/v1/identity/tenants/{tenant}/bearer/logout",
            post(logout, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    let routes = routes.layer(axum::extract::DefaultBodyLimit::max(4096));
    let routes = match state {
        Some(s) => routes.route_layer(middleware::from_fn_with_state(s.clone(), boundary)),
        None => routes,
    };
    routes
        .settles_transactions()
        .fixed_response_headers(&[
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ])
        .response_headers(Some(401), &[("www-authenticate", "Bearer")])
        .bind_with(state, Clone::clone)
}
async fn boundary(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    if let Err(error) = bind_deadline(&mut request, &state) {
        return error.into_response();
    }
    let admitted = if request.uri().to_string().len() > 8192 || request.uri().query().is_some() {
        Err(BAD)
    } else {
        bearer_presentation(request.headers()).map_err(HttpError::from)
    };
    match admitted {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Login {
    login: String,
    password: String,
}
async fn login(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<Login, PROGRAM_LOGIN>,
) -> Result<Json<BearerSession>, HttpError> {
    if request.headers().contains_key(header::AUTHORIZATION) {
        return Err(BAD);
    }
    let address = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;
    let source = AttemptSource::parse(&address.to_string())?;
    let Json(input) = read_body(request, budget, |request| {
        Json::<Login>::from_request(request, &state)
    })
    .await?;
    let issued = state
        .authority
        .login_local_bearer(
            binding,
            LoginKey::parse(&input.login).map_err(|_| UNAUTH)?,
            Password::new(input.password).map_err(|_| UNAUTH)?,
            source,
            budget,
        )
        .await?;
    let view = issued.view();
    Ok(Json(BearerSession {
        access_token: issued.secret().expose().to_owned(),
        token_type: "Bearer",
        session_id: view.id.to_string(),
        principal_id: issued.identity().principal_id.as_uuid(),
        idle_expires_at: view.idle_expires_at,
        absolute_expires_at: view.absolute_expires_at,
    }))
}
async fn logout(
    State(state): State<AppState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<PROGRAM_LOGOUT>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<204, ()>, HttpError> {
    let proof = state
        .authority
        .inspect_bearer(binding, bearer_credential(&headers)?, budget)
        .await?;
    state
        .authority
        .revoke_current_session(proof, budget)
        .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct BearerSession {
    access_token: String,
    token_type: &'static str,
    session_id: String,
    principal_id: uuid::Uuid,
    idle_expires_at: i64,
    absolute_expires_at: i64,
}
