use crate::transport::*;
use crate::{ACTION, Declaration, IDENTITY, Route, Router, get, post, route_module};
// Same-origin self-service ceremonies. Host operation contexts enter through typed extensions.
use crate::{boundary::*, *};
use axum::{
    Extension, Json,
    extract::{Path, Request, State},
    http::HeaderMap,
};
use rss_identity_core::step_up::StepUpContext;
use rss_identity_postgres::{
    AuthenticatedSession, RegistrationAuthorization, RpGeneration, WebauthnAuthority,
};
use rss_identity_web_credentials::{
    clear_operation_cookie, operation_cookie, read_operation_cookie,
};
use rss_transactional_messaging::fence::ExecutionBinding;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Clone)]
struct StateData {
    webauthn: WebauthnAuthority,
    wall_time: fn() -> std::time::SystemTime,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Register,
    Remove { credential: Uuid },
    Recover,
    Host,
}
impl Operation {
    pub(crate) fn context(
        &self,
        actor: &AuthenticatedSession,
        host: Option<StepUpContext>,
    ) -> Result<StepUpContext, HttpError> {
        let (op, credential) = match self {
            Self::Register => ("register", None),
            Self::Remove { credential } => ("remove", Some(*credential)),
            Self::Recover => ("recover", None),
            Self::Host => return host.ok_or(BAD),
        };
        rss_identity_postgres::webauthn_management_context(actor.account(), op, credential)
            .map_err(Into::into)
    }
}
pub fn routes(
    state: Option<&AppState>,
    webauthn: Option<&WebauthnAuthority>,
) -> Router<(), impl Declaration + use<>> {
    route_module! { struct Webauthn for [Browser] { cancel_operation, list, register_begin, register_finish, auth_begin, auth_finish, remove, cancel } }
    let routes = Webauthn {
        cancel_operation: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/operation/cancel",
            post(cancel_operation, &IDENTITY, ACTION),
        ),
        list: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/credentials",
            get(list, &IDENTITY, ACTION),
        ),
        register_begin: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/register/begin",
            post(register_begin, &IDENTITY, ACTION),
        ),
        register_finish: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/register/finish",
            post(register_finish, &IDENTITY, ACTION),
        ),
        auth_begin: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/authenticate/begin",
            post(auth_begin, &IDENTITY, ACTION),
        ),
        auth_finish: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/authenticate/finish",
            post(auth_finish, &IDENTITY, ACTION),
        ),
        remove: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/credentials/{credential}/remove",
            post(remove, &IDENTITY, ACTION),
        ),
        cancel: Route::new(
            "/api/v1/identity/tenants/{tenant}/webauthn/{ceremony}/cancel",
            post(cancel, &IDENTITY, ACTION),
        ),
    }
    .assemble();
    crate::browser(routes, state, 65536).bind_with(state.zip(webauthn).as_ref(), |(s, w)| {
        StateData {
            wall_time: s.wall_time,
            webauthn: (*w).clone(),
        }
    })
}

async fn actor(
    s: &StateData,
    binding: ExecutionBinding,
    h: &HeaderMap,
    b: Deadline,
    write: bool,
) -> Result<AuthenticatedSession, HttpError> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if !request_marker(h)? {
            return Err(BAD);
        }
        csrf(h, &secret)?;
    }
    s.webauthn
        .authority()
        .inspect_session(binding, secret, b)
        .await
        .map_err(Into::into)
}
async fn body<T: serde::de::DeserializeOwned>(
    request: Request,
    b: Deadline,
) -> Result<T, HttpError> {
    let bytes = read_body(request, b, |request| {
        axum::body::to_bytes(request.into_body(), 65536)
    })
    .await?;
    serde_json::from_slice(&bytes).map_err(|_| BAD)
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Credential {
    id: Uuid,
    label: String,
}
impl From<rss_identity_postgres::WebauthnCredentialView> for Credential {
    fn from(v: rss_identity_postgres::WebauthnCredentialView) -> Self {
        Self {
            id: v.id,
            label: v.label,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct RegistrationChallenge {
    id: Uuid,
    #[schemars(schema_with = "crate::challenge::registration_options")]
    options: webauthn_rs_proto::CreationChallengeResponse,
    expires_at: i64,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct Expires {
    expires_at: i64,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Removed {
    removed: bool,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Cancelled {
    cancelled: bool,
}
async fn list(
    State(s): State<StateData>,
    Execution(binding): Execution,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Headers(headers): Headers<PASSIVE>,
) -> Result<Json<Vec<Credential>>, HttpError> {
    let actor = actor(&s, binding, &headers, b, false).await?;
    Ok(Json(
        s.webauthn
            .list(actor, generation, b)
            .await?
            .into_iter()
            .map(Credential::from)
            .collect(),
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Register {
    label: String,
    recover: bool,
}
async fn register_begin(
    State(s): State<StateData>,
    Execution(binding): Execution,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Deferred(request, _): Deferred<Register, WRITE>,
) -> Result<CookieJson<RegistrationChallenge>, HttpError> {
    let actor = actor(&s, binding, request.headers(), b, true).await?;
    let token = read_operation_cookie(request.headers())?;
    let input: Register = body(request, b).await?;
    let authorization = match token {
        Some(token) => RegistrationAuthorization::StepUp(token),
        None if input.recover => return Err(BAD),
        None => RegistrationAuthorization::First,
    };
    let challenge = s
        .webauthn
        .begin_registration(
            actor,
            generation,
            input.label,
            input.recover,
            authorization,
            b,
        )
        .await?;
    Ok(CookieJson {
        body: RegistrationChallenge {
            id: challenge.id,
            options: challenge.options,
            expires_at: challenge.expires_at,
        },
        cookie: Some(clear_operation_cookie()),
    })
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Finish<T> {
    id: Uuid,
    response: T,
}
async fn register_finish(
    State(s): State<StateData>,
    Execution(binding): Execution,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Deferred(request, _): Deferred<Finish<Attestation>, WRITE>,
) -> Result<Json<Credential>, HttpError> {
    let actor = actor(&s, binding, request.headers(), b, true).await?;
    let input: Finish<Attestation> = body(request, b).await?;
    Ok(Json(
        s.webauthn
            .finish_registration(actor, generation, input.id, input.response.0, b)
            .await?
            .into(),
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Begin {
    operation: Operation,
}
async fn auth_begin(
    State(s): State<StateData>,
    Execution(binding): Execution,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Deferred(request, _): Deferred<Begin, WRITE>,
) -> Result<Json<crate::TimedChallenge>, HttpError> {
    let actor = actor(&s, binding, request.headers(), b, true).await?;
    let host = request.extensions().get::<StepUpContext>().cloned();
    let input: Begin = body(request, b).await?;
    let context = input.operation.context(&actor, host)?;
    Ok(Json(crate::TimedChallenge(
        s.webauthn
            .begin_authentication(actor, generation, context, b)
            .await?,
    )))
}
async fn auth_finish(
    State(s): State<StateData>,
    Execution(binding): Execution,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Deferred(request, _): Deferred<Finish<Assertion>, WRITE>,
) -> Result<CookieJson<Expires>, HttpError> {
    let actor = actor(&s, binding, request.headers(), b, true).await?;
    let input: Finish<Assertion> = body(request, b).await?;
    let grant = s
        .webauthn
        .finish_authentication(actor, generation, input.id, input.response.0, b)
        .await?;
    Ok(CookieJson {
        body: Expires {
            expires_at: grant.expires_at,
        },
        cookie: Some(operation_cookie(&grant, (s.wall_time)())?),
    })
}
async fn remove(
    State(s): State<StateData>,
    Path((_t, id)): Path<(String, Uuid)>,
    Execution(binding): Execution<false>,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Headers(headers): Headers<WRITE>,
) -> Result<CookieJson<Removed>, HttpError> {
    let actor = actor(&s, binding, &headers, b, true).await?;
    let token = read_operation_cookie(&headers)?.ok_or(UNAUTH)?;
    s.webauthn.remove(actor, generation, id, token, b).await?;
    Ok(CookieJson {
        body: Removed { removed: true },
        cookie: Some(clear_operation_cookie()),
    })
}
async fn cancel(
    State(s): State<StateData>,
    Path((_t, id)): Path<(String, Uuid)>,
    Execution(binding): Execution<false>,
    ExpectedRp(generation): ExpectedRp,
    Extension(b): Extension<Deadline>,
    Headers(headers): Headers<WRITE>,
) -> Result<Json<Cancelled>, HttpError> {
    let actor = actor(&s, binding, &headers, b, true).await?;
    s.webauthn.cancel(actor, generation, id, b).await?;
    Ok(Json(Cancelled { cancelled: true }))
}

async fn cancel_operation(
    State(s): State<StateData>,
    Execution(binding): Execution,
    Extension(b): Extension<Deadline>,
    Headers(headers): Headers<WRITE>,
) -> Result<CookieJson<Cancelled>, HttpError> {
    let actor = actor(&s, binding, &headers, b, true).await?;
    if let Some(handle) = read_operation_cookie(&headers)? {
        s.webauthn
            .authority()
            .cancel_step_up(actor, handle, b)
            .await?;
    }
    Ok(CookieJson {
        body: Cancelled { cancelled: true },
        cookie: Some(clear_operation_cookie()),
    })
}

struct ExpectedRp(RpGeneration);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ExpectedRp {
    type Rejection = HttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<RpGeneration>()
            .copied()
            .map(Self)
            .ok_or_else(|| HttpError::from(AuthorityError::Unavailable))
    }
}

impl rss_mdm_http_contract::signature::Input for ExpectedRp {
    fn request() -> rss_mdm_http_contract::signature::Request {
        Default::default()
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct Attestation(
    #[schemars(schema_with = "attestation_schema")] webauthn_rs_proto::RegisterPublicKeyCredential,
);
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct Assertion(
    #[schemars(schema_with = "assertion_schema")] webauthn_rs_proto::PublicKeyCredential,
);
fn credential_schema(response: serde_json::Value) -> schemars::Schema {
    let extensions =
        serde_json::json!({"type":"object","description":"WebAuthn client extension results"});
    serde_json::json!({"type":"object","required":["id","rawId","type","response"],"properties":{
        "id":{"type":"string"},"rawId":{"type":"string"},"type":{"type":"string"},
        "response":response,"extensions":extensions,"clientExtensionResults":extensions}})
    .try_into()
    .expect("credential schema")
}
fn attestation_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    credential_schema(
        serde_json::json!({"type":"object","required":["attestationObject","clientDataJSON"],"properties":{
        "attestationObject":{"type":"string"},"clientDataJSON":{"type":"string"},"transports":{"type":["array","null"],"items":{"type":"string"}}}}),
    )
}
fn assertion_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    credential_schema(
        serde_json::json!({"type":"object","required":["authenticatorData","clientDataJSON","signature"],"properties":{
        "authenticatorData":{"type":"string"},"clientDataJSON":{"type":"string"},"signature":{"type":"string"},"userHandle":{"type":["string","null"]}}}),
    )
}
