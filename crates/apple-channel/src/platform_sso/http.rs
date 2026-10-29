use super::*;
use axum::{
    Extension, Json,
    extract::{DefaultBodyLimit, Form, Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::platform_sso::{
    Bootstrap, BrowserBegin, BrowserChallenge, BrowserComplete, GRANT, StatusQuery,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_registration_service::{DevicePrincipal, agent::Service};
use serde::Deserialize;
use serde_json::json;
use service::Action;
use uuid::Uuid;
const COOKIE: &str = "__Host-rss-psso";
#[derive(Clone)]
struct AgentState {
    app: Arc<HttpState>,
    service: Arc<Service>,
}
pub fn agent_routes(
    app: Arc<HttpState>,
    service: Arc<Service>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    mount_agent(Some((app, service)))
}
pub fn mount_agent(
    runtime: Option<(Arc<HttpState>, Arc<Service>)>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct MountAgentModule1 for [Agent] { get_status, post_bootstrap, post_register, post_revoke } }
 MountAgentModule1 { get_status: rss_mdm_http_contract::module::Route::new("/platform-sso/status", get(status, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_bootstrap: rss_mdm_http_contract::module::Route::new("/platform-sso/bootstrap", post(bootstrap, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_register: rss_mdm_http_contract::module::Route::new("/platform-sso/register", post(register, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_revoke: rss_mdm_http_contract::module::Route::new("/platform-sso/sources/{id}/revoke", post(revoke, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])) }.assemble()
}
        .layer(DefaultBodyLimit::max(65536))
        .fixed_response_headers(&[
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ])
        .bind_with(runtime.as_ref(), |(app, service)| AgentState {
            app: app.clone(),
            service: service.clone(),
        })
}
pub fn browser_routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct BrowserRoutesModule1 for [Browser] { get_association, get_jwks, post_nonce, post_token, post_begin, post_complete } }
 BrowserRoutesModule1 { get_association: rss_mdm_http_contract::module::Route::new("/.well-known/apple-app-site-association", get(association, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
get_jwks: rss_mdm_http_contract::module::Route::new("/api/v1/apple/platform-sso/{tenant}/jwks", get(jwks, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_nonce: rss_mdm_http_contract::module::Route::new("/api/v1/apple/platform-sso/{tenant}/nonce", post(nonce, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_token: rss_mdm_http_contract::module::Route::new("/api/v1/apple/platform-sso/{tenant}/token", post(token, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_begin: rss_mdm_http_contract::module::Route::new("/api/v1/apple/platform-sso/{tenant}/browser/begin", post(begin, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])),
post_complete: rss_mdm_http_contract::module::Route::new("/api/v1/apple/platform-sso/{tenant}/browser/complete", post(complete, &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action])) }.assemble()
}
        .layer(DefaultBodyLimit::max(65536))
        .fixed_response_headers(&[
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ])
}
pub fn management_routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct ManagementRoutesModule1 for [Browser] { get_configuration } }
        ManagementRoutesModule1 {
            get_configuration: rss_mdm_http_contract::module::Route::new(
                "/api/v1/apple/platform-sso/configuration",
                get(
                    configuration,
                    &contracts::PLATFORM_SSO_CONFIGURATION,
                    &[RouteOperation::Get],
                ),
            ),
        }
        .assemble()
    }
}
fn tenant(app: &HttpState, t: Uuid) -> Result<(), Error> {
    if app.identity.tenant().to_string() != t.to_string() {
        return Err(Error::Unauthorized);
    }
    runtime(app)?;
    Ok(())
}
async fn principal(
    s: &AgentState,
    h: &HeaderMap,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    audit: &RequestAudit,
) -> Result<DevicePrincipal, Error> {
    if h.contains_key(header::AUTHORIZATION) {
        return Err(Error::Unauthorized);
    }
    let p = s
        .service
        .authenticate(&peer.ok_or(Error::Unauthorized)?.0)
        .await
        .map_err(|e| {
            e.source
                .map(Error::from)
                .unwrap_or(Error::Unavailable(crate::Failure::Database))
        })?;
    audit.identify_device(p.registration());
    audit.registration(p.registration());
    audit.target_device(p.device());
    Ok(p)
}
async fn bootstrap(
    State(s): State<AgentState>,
    AgentHeaders(headers): AgentHeaders,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Bootstrap>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_agent_wire::platform_sso::BootstrapResponse>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Bootstrap(body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .and_then(service::Outcome::bootstrap)
    .map(Json)
}
async fn register(
    State(s): State<AgentState>,
    AgentHeaders(headers): AgentHeaders,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_agent_wire::platform_sso::Registration>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::platform_sso::RegistrationReceipt>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Register(body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .and_then(service::Outcome::registration)
    .map(Json)
}
async fn revoke(
    State(s): State<AgentState>,
    Path(id): Path<Uuid>,
    AgentHeaders(headers): AgentHeaders,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_agent_wire::platform_sso::Revocation>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::platform_sso::RevocationReceipt>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Revoke(id, body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .and_then(service::Outcome::revocation)
    .map(Json)
}
async fn jwks(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
) -> Result<Json<super::Jwks>, Error> {
    tenant(&app, t)?;
    Ok(Json(runtime(&app)?.jwks()))
}
async fn nonce(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<service::Nonce>, Error> {
    tenant(&app, t)?;
    service::mutate(&Context::new(&app), None, &audit, Action::Nonce)
        .await
        .and_then(service::Outcome::nonce)
        .map(Json)
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    platform_sso_version: String,
    grant_type: String,
    assertion: String,
}
impl Drop for Token {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.assertion.zeroize();
    }
}
async fn token(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Form<Token>, axum::extract::rejection::FormRejection>,
) -> Result<JoseResponse, NativeError> {
    tenant(&app, t)?;
    let mut input = body.map_err(|_| Error::Malformed)?.0;
    if input.platform_sso_version != "1.0" || input.grant_type != GRANT {
        return Err(Error::Malformed.into());
    }
    let assertion = zeroize::Zeroizing::new(std::mem::take(&mut input.assertion));
    let context = Context::new(&app);
    let result = if super::password::is_password(&context, &assertion).await? {
        super::password::login(&context, &audit, &assertion).await?
    } else {
        service::mutate(&context, None, &audit, Action::Login(assertion.to_string()))
            .await?
            .login()?
    };
    Ok(JoseResponse(
        result.as_str().ok_or(Error::Malformed)?.to_owned(),
    ))
}

struct NativeError(Error);
impl From<Error> for NativeError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
#[derive(Clone, Copy, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum NativeCode {
    InvalidGrant,
    InvalidRequest,
    TemporarilyUnavailable,
}
impl NativeCode {
    const ALL: [Self; 3] = [
        Self::InvalidGrant,
        Self::InvalidRequest,
        Self::TemporarilyUnavailable,
    ];
    fn status(self) -> u16 {
        match self {
            Self::InvalidGrant | Self::InvalidRequest => 400,
            Self::TemporarilyUnavailable => 503,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct NativeErrorBody {
    error: NativeCode,
}
impl IntoResponse for NativeError {
    fn into_response(self) -> Response {
        let error = match &self.0 {
            Error::Unauthorized | Error::Forbidden | Error::Conflict => NativeCode::InvalidGrant,
            Error::Malformed | Error::CertificateRequest => NativeCode::InvalidRequest,
            _ => NativeCode::TemporarilyUnavailable,
        };
        let mut response = (
            axum::http::StatusCode::from_u16(error.status()).expect("native status"),
            Json(NativeErrorBody { error }),
        )
            .into_response();
        response.extensions_mut().insert(self.0);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for NativeError {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        NativeCode::ALL
            .into_iter()
            .map(|code| {
                let mut response = rss_mdm_http_contract::signature::Response::json::<
                    NativeErrorBody,
                >(code.status());
                response.body.as_mut().unwrap().schema.value["properties"]["error"] =
                    json!({"type":"string","const":code});
                response
            })
            .collect()
    }
}

fn origin(app: &HttpState, h: &HeaderMap) -> Result<(), Error> {
    if h.get_all(header::ORIGIN).iter().count() != 1
        || h.get(header::ORIGIN).and_then(|h| h.to_str().ok())
            != Some(app.authentication.origin.as_str())
        || h.contains_key(header::AUTHORIZATION)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
fn identity_error(e: rss_identity_postgres::AuthorityError) -> Error {
    match e {
        rss_identity_postgres::AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        rss_identity_postgres::AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        rss_identity_postgres::AuthorityError::Rejected => Error::Unauthorized,
        _ => Error::Unavailable(crate::Failure::Database),
    }
}
async fn begin(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    BeginHeaders(headers): BeginHeaders,
    body: Result<Json<BrowserBegin>, axum::extract::rejection::JsonRejection>,
) -> Result<BrowserBeginResponse, Error> {
    tenant(&app, t)?;
    origin(&app, &headers)?;
    let input = body.map_err(|_| Error::Malformed)?.0;
    let browser = crypto::random()?;
    let challenge = app
        .authentication
        .authority
        .begin_platform_login(
            app.identity.tenant(),
            input.binding_id,
            rss_identity_postgres::platform::PlatformPurpose::BrowserLogin,
            browser.clone(),
            rss_identity_postgres::AttemptSource::parse("mdm-platform-sso")
                .map_err(|_| Error::Malformed)?,
            deadline(),
        )
        .await
        .map_err(identity_error)?;
    let cookie = format!(
        "{COOKIE}={}.{}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=120",
        challenge.id, browser
    );
    let challenge = BrowserChallenge {
        id: challenge.id,
        nonce: challenge.nonce,
        expires_at: challenge.expires_at,
        audience: Context::new(&app).runtime()?.browser_audience.clone(),
    };
    Ok(BrowserBeginResponse {
        challenge,
        cookie: HeaderValue::from_str(&cookie).map_err(|_| Error::Malformed)?,
    })
}

async fn complete(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    CompleteHeaders(headers): CompleteHeaders,
    body: Result<Json<BrowserComplete>, axum::extract::rejection::JsonRejection>,
) -> Result<IdentityCompletion, Error> {
    tenant(&app, t)?;
    origin(&app, &headers)?;
    let input = body.map_err(|_| Error::Malformed)?.0;
    let mut cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(k, _)| *k == COOKIE);
    let (_, value) = cookies.next().ok_or(Error::Unauthorized)?;
    if cookies.next().is_some() {
        return Err(Error::Unauthorized);
    }
    let (id, secret) = value.split_once('.').ok_or(Error::Unauthorized)?;
    if id != input.challenge_id.to_string() || crypto::decode(secret)?.len() != 32 {
        return Err(Error::Unauthorized);
    }
    let session = app
        .authentication
        .authority
        .complete_platform_login(
            app.identity.tenant(),
            input.challenge_id,
            input.nonce,
            secret.into(),
            input.proof.into_bytes(),
            deadline(),
        )
        .await
        .map_err(identity_error)?;
    if session.assertion.is_some() {
        return Err(Error::Unauthorized);
    }
    let mut response = rss_identity_http_axum::issued_session_response(session.session);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-rss-psso=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(IdentityCompletion(response))
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationQuery {
    device_id: String,
}
async fn configuration(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
    axum::extract::Query(query): axum::extract::Query<ConfigurationQuery>,
) -> Result<Json<ConfigurationView>, Error> {
    auth.proof
        .manage(rss_mdm_authorization_service::Permission::RegistrationConfigurationRead)?;
    let rt = runtime(&app)?;
    let ctx = Context::new(&app);
    let mut tx = ctx.access.begin(&ctx.tenant.to_string()).await?;
    let object = rss_mdm_device_service::planning::PlanningObjects::paired_in(
        &mut tx,
        ctx.tenant,
        &query.device_id,
    )
    .await
    .map_err(crate::database::db)?;
    let login = super::deployment::configuration_for_object(&mut tx, ctx.tenant, &object).await?;
    let profile = rt.profile(&login)?;
    tx.rollback().await.map_err(crate::database::db)?;
    auth.proof.check_live()?;
    Ok(Json(ConfigurationView {
        configuration: rt.configuration.clone(),
        endpoints: rt.endpoints.clone(),
        profile,
        protocol_version: "1.0",
        login_configuration: login,
        target_sdk: "26.4",
        registration_trust: rss_mdm_agent_wire::platform_sso::RegistrationTrust::MdmBootstrapPop,
        hardware_attested: false,
        refresh_method: "fresh_native_login",
        deployment_order: [
            "signed_application",
            "extensible_sso_profile",
            "device_registration",
            "user_registration",
            "login_ready",
        ],
    }))
}

async fn status(
    State(s): State<AgentState>,
    axum::extract::Query(query): axum::extract::Query<StatusQuery>,
    AgentHeaders(headers): AgentHeaders,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_agent_wire::platform_sso::Status>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    super::status::read(&Context::new(&s.app), &p, query.binding_id)
        .await
        .map(Json)
}

async fn association(State(app): State<Arc<HttpState>>) -> Result<Json<super::Association>, Error> {
    Ok(Json(runtime(&app)?.association()))
}

struct AgentHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AgentHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for AgentHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        request.headers.insert(
            "authorization".into(),
            rss_mdm_http_contract::signature::Schema {
                direction: rss_mdm_http_contract::signature::Direction::Request,
                value: serde_json::Value::Bool(false),
            },
        );
        request
    }
}

struct BeginHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for BeginHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for BeginHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        request.headers.insert(
            "origin".into(),
            rss_mdm_http_contract::signature::Schema::request::<String>(),
        );
        request.required_headers.push("origin");
        request.headers.insert(
            "authorization".into(),
            rss_mdm_http_contract::signature::Schema {
                direction: rss_mdm_http_contract::signature::Direction::Request,
                value: serde_json::Value::Bool(false),
            },
        );
        request
    }
}

struct CompleteHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CompleteHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for CompleteHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        request.headers.insert(
            "origin".into(),
            rss_mdm_http_contract::signature::Schema::request::<String>(),
        );
        request.required_headers.push("origin");
        request.headers.insert(
            "cookie".into(),
            rss_mdm_http_contract::signature::Schema::request::<String>(),
        );
        request.required_headers.push("cookie");
        request.headers.insert(
            "authorization".into(),
            rss_mdm_http_contract::signature::Schema {
                direction: rss_mdm_http_contract::signature::Direction::Request,
                value: serde_json::Value::Bool(false),
            },
        );
        request
    }
}

struct JoseResponse(String);
impl JoseResponse {
    const MEDIA: &'static str = "application/jose";
}
impl IntoResponse for JoseResponse {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, Self::MEDIA)], self.0).into_response()
    }
}
impl rss_mdm_http_contract::signature::Output for JoseResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Representation, Response, Schema};
        let mut response = Response::empty(200);
        response.body = Some(Representation {
            content_type: Self::MEDIA,
            schema: Schema::response::<String>(),
        });
        vec![response]
    }
}
struct BrowserBeginResponse {
    challenge: BrowserChallenge,
    cookie: HeaderValue,
}
impl IntoResponse for BrowserBeginResponse {
    fn into_response(self) -> Response {
        let mut response = Json(self.challenge).into_response();
        response
            .headers_mut()
            .append(header::SET_COOKIE, self.cookie);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for BrowserBeginResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        let mut response =
            rss_mdm_http_contract::signature::Response::json::<BrowserChallenge>(200);
        response.headers.insert(
            "set-cookie".into(),
            rss_mdm_http_contract::signature::Schema::response::<String>(),
        );
        vec![response]
    }
}
struct IdentityCompletion(Response);
impl IntoResponse for IdentityCompletion {
    fn into_response(self) -> Response {
        self.0
    }
}

// External owner: rss-identity-http-axum@ee8e578f9ff36750ff88f36f336400110770dcaa.
// lib.rs::issued_session_response -> handlers.rs::issued/project_session and dto.rs::Issued.
// The foreign serializer still sends the response; this narrow adapter is drift-checked,
// not a claim that Identity's private DTOs are proven by this crate's type system.
impl rss_mdm_http_contract::signature::Output for IdentityCompletion {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Direction, Representation, Response, Schema};
        let mut success = Response::empty(200);
        success.body = Some(Representation::json(Schema {
            direction: Direction::Response,
            value: json!({
                "type":"object", "required":["identity","session","csrfToken"],
                "properties":{
                    "identity":{"type":"object","required":["principalId","hasLocalPassword"],"properties":{
                        "principalId":{"type":"string"},"hasLocalPassword":{"type":"boolean"}
                    }},
                    "session":{"type":"object","required":["id","issuedAt","idleExpiresAt","absoluteExpiresAt"],"properties":{
                        "id":{"type":"string"},"issuedAt":{"type":"integer","format":"int64"},
                        "idleExpiresAt":{"type":"integer","format":"int64"},"absoluteExpiresAt":{"type":"integer","format":"int64"}
                    }},
                    "csrfToken":{"type":"string"}
                },
                "x-rss-owner":"rss-identity-http-axum::issued_session_response"
            }),
        }));
        // The foreign renderer can reject a zero-age or non-cookie issued session.
        let mut failure = Response::empty(503);
        failure.body = Some(Representation::json(Schema {
            direction: Direction::Response,
            value: json!({
                "type":"object","required":["code"],"properties":{"code":{"type":"string","const":"identity_unavailable"}},
                "x-rss-owner":"rss-identity-http-axum::issued_session_response"
            }),
        }));
        for response in [&mut success, &mut failure] {
            response
                .headers
                .insert("set-cookie".into(), Schema::response::<String>());
            for (name, value) in [
                ("cache-control", "no-store"),
                ("referrer-policy", "no-referrer"),
            ] {
                let mut schema = Schema::response::<String>();
                schema.value["const"] = value.into();
                response.headers.insert(name.into(), schema);
            }
        }
        vec![success, failure]
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ConfigurationView {
    configuration: rss_mdm_agent_wire::platform_sso::Configuration,
    endpoints: rss_mdm_agent_wire::platform_sso::Endpoints,
    profile: rss_mdm_apple_mdm::native::profiles::ProfileInput,
    protocol_version: &'static str,
    login_configuration: rss_mdm_agent_wire::platform_sso::LoginConfiguration,
    target_sdk: &'static str,
    registration_trust: rss_mdm_agent_wire::platform_sso::RegistrationTrust,
    hardware_attested: bool,
    refresh_method: &'static str,
    deployment_order: [&'static str; 5],
}
