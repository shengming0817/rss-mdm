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
use serde_json::{Value, json};
use service::Action;
use uuid::Uuid;
const COOKIE: &str = "__Host-rss-psso";
#[derive(Clone)]
struct AgentState {
    app: Arc<HttpState>,
    service: Arc<Service>,
}
pub fn agent_routes(app: Arc<HttpState>, service: Arc<Service>) -> Router {
    Router::new()
        .route(
            "/platform-sso/status",
            get(status).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/platform-sso/bootstrap",
            post(bootstrap).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/platform-sso/register",
            post(register).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/platform-sso/sources/{id}/revoke",
            post(revoke).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .layer(DefaultBodyLimit::max(65536))
        .layer(axum::middleware::map_response(private_response))
        .with_state(AgentState { app, service })
}
pub fn browser_routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/.well-known/apple-app-site-association",
            get(association).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/api/v1/apple/platform-sso/{tenant}/jwks",
            get(jwks).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/api/v1/apple/platform-sso/{tenant}/nonce",
            post(nonce).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/api/v1/apple/platform-sso/{tenant}/token",
            post(token).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/api/v1/apple/platform-sso/{tenant}/browser/begin",
            post(begin).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/api/v1/apple/platform-sso/{tenant}/browser/complete",
            post(complete).owned(
                &contracts::PROTOCOL_APPLE_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .layer(DefaultBodyLimit::max(65536))
        .layer(axum::middleware::map_response(private_response))
}
pub fn management_routes() -> Router<Arc<HttpState>> {
    Router::new().route(
        "/api/v1/apple/platform-sso/configuration",
        get(configuration).owned(
            &contracts::PLATFORM_SSO_CONFIGURATION,
            &[RouteOperation::Get],
        ),
    )
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
    headers: HeaderMap,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Bootstrap>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Bootstrap(body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .map(Json)
}
async fn register(
    State(s): State<AgentState>,
    headers: HeaderMap,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_agent_wire::platform_sso::Registration>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Register(body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .map(Json)
}
async fn revoke(
    State(s): State<AgentState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<
        Json<rss_mdm_agent_wire::platform_sso::Revocation>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    service::mutate(
        &Context::new(&s.app),
        Some(&p),
        &audit,
        Action::Revoke(id, body.map_err(|_| Error::Malformed)?.0),
    )
    .await
    .map(Json)
}
async fn jwks(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    tenant(&app, t)?;
    Ok(Json(runtime(&app)?.jwks()))
}
async fn nonce(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Value>, Error> {
    tenant(&app, t)?;
    service::mutate(&Context::new(&app), None, &audit, Action::Nonce)
        .await
        .map(Json)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    platform_sso_version: String,
    grant_type: String,
    assertion: String,
}
async fn token(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Form<Token>, axum::extract::rejection::FormRejection>,
) -> Result<Response, NativeError> {
    tenant(&app, t)?;
    let input = body.map_err(|_| Error::Malformed)?.0;
    if input.platform_sso_version != "1.0" || input.grant_type != GRANT {
        return Err(Error::Malformed.into());
    }
    let result = service::mutate(
        &Context::new(&app),
        None,
        &audit,
        Action::Login(input.assertion),
    )
    .await?;
    Ok((
        [(header::CONTENT_TYPE, "application/jose")],
        result.as_str().ok_or(Error::Malformed)?.to_owned(),
    )
        .into_response())
}
async fn private_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
struct NativeError(Error);
impl From<Error> for NativeError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
impl IntoResponse for NativeError {
    fn into_response(self) -> Response {
        use axum::http::StatusCode;
        let (status, code) = match &self.0 {
            Error::Unauthorized | Error::Forbidden | Error::Conflict => {
                (StatusCode::BAD_REQUEST, "invalid_grant")
            }
            Error::Malformed | Error::CertificateRequest => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            _ => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        };
        let mut response = (status, Json(json!({"error":code}))).into_response();
        response.extensions_mut().insert(self.0);
        response
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
    headers: HeaderMap,
    body: Result<Json<BrowserBegin>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
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
    let mut response = Json(BrowserChallenge {
        id: challenge.id,
        nonce: challenge.nonce,
        expires_at: challenge.expires_at,
        audience: Context::new(&app).runtime()?.browser_audience.clone(),
    })
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| Error::Malformed)?,
    );
    Ok(response)
}
async fn complete(
    State(app): State<Arc<HttpState>>,
    Path(t): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<BrowserComplete>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, Error> {
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
    let mut response = rss_identity_http_axum::issued_session_response(session);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-rss-psso=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}
async fn configuration(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<rss_mdm_authorization_service::context::RequestAuth>,
) -> Result<Json<Value>, Error> {
    auth.proof
        .manage(rss_mdm_authorization_service::Permission::RegistrationConfigurationRead)?;
    let rt = runtime(&app)?;
    let profile = rt.profile()?;
    auth.proof.check_live()?;
    Ok(Json(
        json!({"configuration":rt.configuration,"endpoints":rt.endpoints,"profile":profile,"protocolVersion":"1.0","authenticationMethod":"UserSecureEnclaveKey","targetSdk":"26.4","registrationTrust":"mdm_bootstrap_pop","hardwareAttested":false,"refreshMethod":"fresh_native_login","deploymentOrder":["signed_application","extensible_sso_profile","device_registration","user_registration","login_ready"]}),
    ))
}

async fn status(
    State(s): State<AgentState>,
    axum::extract::Query(query): axum::extract::Query<StatusQuery>,
    headers: HeaderMap,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_agent_wire::platform_sso::Status>, Error> {
    let p = principal(&s, &headers, peer, &audit).await?;
    super::status::read(&Context::new(&s.app), &p, query.binding_id)
        .await
        .map(Json)
}

async fn association(State(app): State<Arc<HttpState>>) -> Result<Json<Value>, Error> {
    Ok(Json(runtime(&app)?.association()))
}
