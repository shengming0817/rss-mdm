use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, post, route_module};
use crate::{boundary::*, *};
use rss_transactional_messaging::fence::ExecutionBinding;

use axum::{
    Extension, Json,
    body::Body,
    extract::{FromRequest, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use rss_identity_core::{
    account::Password, federation::callback::CallbackOutcome, session::SessionSecret,
};

use rss_identity_postgres::{
    AttemptSource, AuthenticatedSession, FederatedOutcome, FederatedRedirect, Federation,
};

use serde::Deserialize;

use rss_identity_web_credentials::{BrowserBinding, issued_cookie, operation_cookie};

#[derive(Clone)]
struct FederationState {
    federation: Federation,
    local: AppState,
}

/// Optional OIDC routes; merge with `router` for local authentication.
pub fn tenant_routes(
    runtime: Option<(&rss_identity_postgres::Federation, &AppState)>,
) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Federation for [Browser] { options, security, begin, link, step_up } }
    let routes = Federation {
        options: Route::new(
            "/api/v1/identity/tenants/{tenant}/login-options",
            get(options, &IDENTITY, ACTION),
        ),
        security: Route::new(
            "/api/v1/identity/tenants/{tenant}/session/security",
            get(security, &IDENTITY, ACTION),
        ),
        begin: Route::new(
            "/api/v1/identity/tenants/{tenant}/oidc/{provider}/login",
            post(begin, &IDENTITY, ACTION),
        ),
        link: Route::new(
            "/api/v1/identity/tenants/{tenant}/oidc/{provider}/link",
            post(link, &IDENTITY, ACTION),
        ),
        step_up: Route::new(
            "/api/v1/identity/tenants/{tenant}/oidc/{provider}/step-up",
            post(step_up, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, runtime.map(|(_, local)| local), 4096).bind_with(
        runtime.as_ref(),
        |(f, s)| FederationState {
            federation: (*f).clone(),
            local: (*s).clone(),
        },
    )
}
pub fn callback_route(
    runtime: Option<(&rss_identity_postgres::Federation, &AppState)>,
) -> Router<(), impl Declaration + use<>> {
    route_module! { struct CallbackRoute for [Browser] { callback } }
    let routes = CallbackRoute {
        callback: Route::new(
            crate::CALLBACK_PATH,
            get(callback, &IDENTITY, ACTION).reject_head(),
        ),
    }
    .assemble();
    crate::browser(routes, runtime.map(|(_, local)| local), 4096).bind_with(
        runtime.as_ref(),
        |(f, s)| FederationState {
            federation: (*f).clone(),
            local: (*s).clone(),
        },
    )
}
pub fn federation_routes(
    runtime: Option<(&rss_identity_postgres::Federation, &AppState)>,
) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Federated for [Browser] { tenants, providers } }
    Federated {
        tenants: tenant_routes(runtime),
        providers: crate::providers::routes(runtime),
    }
    .assemble()
}

async fn options(
    State(s): State<FederationState>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
) -> Result<Json<dto::LoginOptions>, crate::accounts::Error> {
    Ok(Json(dto::LoginOptions {
        providers: s
            .federation
            .login_options(binding, b)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    }))
}
async fn security(
    State(state): State<FederationState>,
    Execution(binding): Execution,
    Extension(budget): Extension<Deadline>,
    Headers(headers): Headers<PASSIVE>,
) -> Result<Json<dto::SessionSecurity>, HttpError> {
    let secret = cookie(&headers)?.ok_or(UNAUTH)?;
    let actor = state
        .local
        .authority
        .inspect_session(binding, secret, budget)
        .await?;
    let security = state
        .federation
        .current_session_security(actor, budget)
        .await?;
    Ok(Json(crate::dto::SessionSecurity::from(security)))
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Begin {
    return_target: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BeginStepUp {
    return_target: String,
    operation: crate::webauthn::Operation,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Link {
    return_target: String,
    password: Option<String>,
}

fn source(request: &Request) -> Result<AttemptSource, HttpError> {
    let peer = request
        .extensions()
        .get::<crate::ClientAddress>()
        .ok_or(HttpError::from(AuthorityError::Unavailable))?
        .0;

    Ok(AttemptSource::parse(&peer.to_string())?)
}

async fn actor(
    local: &AppState,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    budget: Deadline,
    required: bool,
) -> Result<Option<AuthenticatedSession>, HttpError> {
    if !request_marker(headers)? {
        return Err(FORBIDDEN);
    }

    if let Some(secret) = login_cookie(headers)? {
        match local
            .authority
            .inspect_session(
                binding,
                SessionSecret::parse(secret.expose().into()).map_err(|_| UNAUTH)?,
                budget,
            )
            .await
        {
            Ok(proof) => {
                csrf(headers, &secret)?;

                return Ok(Some(proof));
            }

            Err(AuthorityError::Rejected) if !required => {}

            Err(e) => return Err(e.into()),
        }
    }

    if required { Err(UNAUTH) } else { Ok(None) }
}

/// Recheck the current browser session without extending idle a second time.
pub async fn operation_actor(
    local: &AppState,
    binding: ExecutionBinding,
    headers: &HeaderMap,
    deadline: Deadline,
) -> Result<AuthenticatedSession, HttpError> {
    rss_identity_web_credentials::same_origin(headers, &local.config)?;
    actor(local, binding, headers, deadline, true)
        .await?
        .ok_or(UNAUTH)
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationUrl {
    authorization_url: String,
}
pub fn authorization_redirect(
    redirect: FederatedRedirect,
    cookie: Option<header::HeaderValue>,
) -> CookieJson<AuthorizationUrl> {
    CookieJson {
        body: AuthorizationUrl {
            authorization_url: redirect.url,
        },
        cookie,
    }
}

async fn begin(
    State(state): State<FederationState>,
    Path((_raw, crate::boundary::Provider(provider))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<Begin, LOGIN>,
) -> Result<CookieJson<AuthorizationUrl>, HttpError> {
    let actor = actor(&state.local, binding, request.headers(), budget, false).await?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let Json(input) = read_body(request, budget, |request| {
        Json::<Begin>::from_request(request, &state)
    })
    .await?;

    let redirect = state
        .federation
        .begin_login(
            rss_identity_postgres::LoginRequest {
                binding,
                provider,
                browser: browser.value,
                target: input.return_target,
                replacement: actor,
                source,
            },
            budget,
        )
        .await?;

    Ok(authorization_redirect(redirect, browser.set_cookie))
}

async fn step_up(
    State(state): State<FederationState>,
    Path((_raw, crate::boundary::Provider(provider))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<BeginStepUp, WRITE>,
) -> Result<CookieJson<AuthorizationUrl>, HttpError> {
    let actor = actor(&state.local, binding, request.headers(), budget, true).await?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let host = request
        .extensions()
        .get::<rss_identity_core::step_up::StepUpContext>()
        .cloned();
    let Json(input) = read_body(request, budget, |request| {
        Json::<BeginStepUp>::from_request(request, &state)
    })
    .await?;

    let actor = actor.ok_or(UNAUTH)?;
    let context = input.operation.context(&actor, host)?;
    let redirect = state
        .federation
        .begin_step_up(
            rss_identity_postgres::LoginRequest {
                binding,
                provider,
                browser: browser.value,
                target: input.return_target,
                replacement: Some(actor),
                source,
            },
            context,
            budget,
        )
        .await?;

    Ok(authorization_redirect(redirect, browser.set_cookie))
}

async fn link(
    State(state): State<FederationState>,
    Path((_raw, crate::boundary::Provider(provider))): Path<(String, crate::boundary::Provider)>,
    Execution(binding): Execution<false>,
    Extension(budget): Extension<Deadline>,
    Deferred(request, _): Deferred<Link, WRITE>,
) -> Result<CookieJson<AuthorizationUrl>, HttpError> {
    let actor = actor(&state.local, binding, request.headers(), budget, true)
        .await?
        .ok_or(UNAUTH)?;

    let browser = BrowserBinding::start(request.headers())?;

    let source = source(&request)?;

    let Json(input) = read_body(request, budget, |request| {
        Json::<Link>::from_request(request, &state)
    })
    .await?;

    let password = input
        .password
        .map(Password::new)
        .transpose()
        .map_err(|_| UNAUTH)?;

    let redirect = state
        .federation
        .begin_link(
            rss_identity_postgres::LinkRequest {
                actor,
                target_provider: provider,
                password,
                browser: browser.value,
                target: input.return_target,
                source,
            },
            budget,
        )
        .await?;

    Ok(authorization_redirect(redirect, browser.set_cookie))
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
    iss: String,
    #[serde(rename = "error_description")]
    _error_description: Option<String>,
    #[serde(rename = "error_uri")]
    _error_uri: Option<String>,
    #[serde(rename = "session_state")]
    _session_state: Option<String>,
}

async fn callback(
    state: State<FederationState>,
    budget: Option<Extension<Deadline>>,
    Headers(headers): Headers<CALLBACK>,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> CallbackReply {
    let Some(budget) = budget else {
        return CallbackReply(callback_error_response(
            HttpError::from(AuthorityError::Unavailable).into_response(),
        ));
    };
    CallbackReply(match callback_result(state, budget, headers, query).await {
        Ok(response) => response,
        Err(error) => callback_error_response(error.into_response()),
    })
}
pub(crate) fn callback_failure(reason: &str) -> Response {
    // Only closed literals selected in this module reach Location.
    axum::response::Redirect::to(&format!("/auth/error?reason={reason}")).into_response()
}

/// Keep host diagnostics in response parts while replacing the browser projection.
pub async fn protect_callback(request: Request, next: axum::middleware::Next) -> Response {
    let callback =
        request.method() == axum::http::Method::GET && request.uri().path() == crate::CALLBACK_PATH;
    let response = next.run(request).await;
    if callback && (response.status().is_client_error() || response.status().is_server_error()) {
        return callback_error_response(response);
    }
    response
}

pub(crate) fn callback_error_response(response: Response) -> Response {
    let (mut parts, _) = response.into_parts();
    let reason = if parts.status == StatusCode::SERVICE_UNAVAILABLE {
        "unavailable"
    } else {
        "failed"
    };
    let mut projected = (
        parts.extensions,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        callback_failure(reason),
    )
        .into_response();
    for name in [
        header::HeaderName::from_static("x-request-id"),
        header::X_CONTENT_TYPE_OPTIONS,
    ] {
        if let Some(value) = parts.headers.remove(&name) {
            projected.headers_mut().insert(name, value);
        }
    }
    projected
}

async fn callback_result(
    State(state): State<FederationState>,
    Extension(budget): Extension<Deadline>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, HttpError> {
    let Query(query) = query.map_err(|_| BAD)?;
    let outcome = CallbackOutcome::from_parts(query.code, query.error).map_err(|_| BAD)?;

    let browser = BrowserBinding::require(&headers)?;

    let code = match outcome {
        CallbackOutcome::Code(code) => code,
        CallbackOutcome::Denied { cancelled } => {
            state
                .federation
                .cancel(
                    query.state,
                    browser,
                    query.iss,
                    login_cookie(&headers)?,
                    budget,
                )
                .await?;
            return Ok(callback_failure(if cancelled {
                "cancelled"
            } else {
                "failed"
            }));
        }
    };
    let outcome = state
        .federation
        .complete(
            query.state,
            browser,
            code,
            query.iss,
            login_cookie(&headers)?,
            budget,
        )
        .await?;

    let (location, cookie) = match outcome {
        FederatedOutcome::Redirect(redirect) => (redirect.url, None),
        FederatedOutcome::StepUp { grant, return_url } => (
            return_url,
            Some(operation_cookie(&grant, std::time::SystemTime::now())?),
        ),
        FederatedOutcome::Session {
            issued,
            return_url,
            link_result,
        } => {
            let location = if let Some(result) = link_result {
                let mut url = url::Url::parse(&return_url).map_err(|_| BAD)?;
                url.query_pairs_mut()
                    .append_pair("identity_result", result.as_str());
                url.to_string()
            } else {
                return_url
            };
            (location, Some(issued_cookie(&issued)?.header))
        }
    };

    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::empty())
        .map_err(|_| BAD)?;

    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }

    Ok(response)
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    use rss_identity_core::federation::FederationError;
    use rss_identity_postgres::AuthorityError;
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct HostMarker;

    #[tokio::test]
    async fn callback_error_projection_keeps_all_host_extensions_and_hides_body() {
        for (error, reason) in [
            (
                AuthorityError::Federation(FederationError::Claims),
                "failed",
            ),
            (AuthorityError::Unavailable, "unavailable"),
        ] {
            let mut response = HttpError::from(error).into_response();
            response.extensions_mut().insert(HostMarker);
            response.headers_mut().insert(
                header::SET_COOKIE,
                "must-not-forward=secret".parse().unwrap(),
            );
            response
                .headers_mut()
                .insert("x-request-id", "rid".parse().unwrap());
            response
                .headers_mut()
                .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
            let response = callback_error_response(response);
            assert_eq!(response.headers()["x-request-id"], "rid");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("/auth/error?reason={reason}")
            );
            assert_eq!(
                response.extensions().get::<HttpFailure>(),
                Some(&HttpFailure::Authority(error))
            );
            assert_eq!(response.extensions().get::<HostMarker>(), Some(&HostMarker));
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(
                axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

struct CallbackReply(Response);
impl IntoResponse for CallbackReply {
    fn into_response(self) -> Response {
        self.0
    }
}
impl rss_mdm_http_contract::signature::Output for CallbackReply {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Response, Schema};
        let mut r = Response::empty(303);
        for name in ["location", "set-cookie"] {
            r.headers.insert(name.into(), Schema::response::<String>());
        }
        vec![r]
    }
}
