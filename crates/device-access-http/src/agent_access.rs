//! Existing Agent wire with independent DA business and explicit current delivery authorization.
use crate::agent_transport::{AgentError, bounded};
use crate::business_error::Error;
use axum::{Extension, Json, extract::State};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{
    Operation as RouteOperation, Router, catalog as contracts,
    routing::{get, post},
    signature::NoStore,
};
use std::sync::Arc;
pub struct Services {
    pub authentication: crate::platform_sso::Authentication,
    pub identity: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub business: Arc<rss_mdm_device_access_postgres::Service>,
    pub admission: Arc<dyn rss_mdm_device_access_postgres::device_access::Admission>,
}
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}
fn domain(e: rss_mdm_device_access_postgres::Error) -> AgentError {
    match e {
        rss_mdm_device_access_postgres::Error::Agent(code) => AgentError::Enrollment(code),
        e => AgentError::Business(e.into()),
    }
}
pub fn routes(
    runtime: Option<Arc<Services>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct AccessRoutes for [Agent,Da]{get_access_directory,post_access_begin,post_access_confirm,post_access_recovery_use}}
    AccessRoutes {
        get_access_directory: rss_mdm_http_contract::module::Route::new(
            "/device-access",
            get(
                access_directory,
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        post_access_begin: rss_mdm_http_contract::module::Route::new(
            "/device-access/begin",
            post(
                access_begin,
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        post_access_confirm: rss_mdm_http_contract::module::Route::new(
            "/device-access/confirm",
            post(
                access_confirm,
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        post_access_recovery_use: rss_mdm_http_contract::module::Route::new(
            "/device-access/recovery-uses",
            post(
                access_recovery_use,
                &contracts::PROTOCOL_AGENT_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
    }
    .assemble()
    .bind_with(runtime.as_ref(), Clone::clone)
}
async fn access_begin(
    State(app): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    rss_mdm_http_contract::agent::RuntimeHeaders(headers): rss_mdm_http_contract::agent::RuntimeHeaders,
    input: Body<wire::AccessBegin>,
) -> Result<NoStore<Json<wire::AccessChallenge>>, AgentError> {
    bounded(async {
        let p = principal(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        let employee = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        let input = body(input)?;
        let value = app
            .business
            .begin_device_access(&p, &employee, &input, app.admission.as_ref(), &audit)
            .await
            .map_err(domain)?;
        Ok(NoStore(Json(wire::AccessChallenge {
            id: value.id,
            nonce: value.nonce,
            expires_at: value.expires_at,
            local_session: value.local_session,
        })))
    })
    .await
}
async fn access_confirm(
    State(app): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    rss_mdm_http_contract::agent::RuntimeHeaders(headers): rss_mdm_http_contract::agent::RuntimeHeaders,
    input: Body<wire::AccessConfirm>,
) -> Result<Json<wire::AccessBindingStatus>, AgentError> {
    bounded(async {
        let p = principal(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        let employee = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        let input = body(input)?;
        let value = app
            .business
            .confirm_device_access(&p, &employee, &input, app.admission.as_ref(), &audit)
            .await
            .map_err(domain)?;
        Ok(Json(value.status()))
    })
    .await
}

async fn access_recovery_use(
    State(app): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    rss_mdm_http_contract::agent::RuntimeHeaders(headers): rss_mdm_http_contract::agent::RuntimeHeaders,
    input: Body<wire::AccessRecoveryUse>,
) -> Result<Json<RecoveryUseAccepted>, AgentError> {
    bounded(async {
        let p = principal(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        app.business
            .record_access_recovery_use(&p, &body(input)?, &audit)
            .await
            .map_err(domain)?;
        Ok(Json(RecoveryUseAccepted { accepted: true }))
    })
    .await
}

async fn access_directory(
    State(app): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    rss_mdm_http_contract::agent::RuntimeHeaders(headers): rss_mdm_http_contract::agent::RuntimeHeaders,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<AccessDirectory>,
    >,
) -> Result<NoStore<Json<wire::AccessDirectory>>, AgentError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    bounded(async {
        let (page, _) = query.parse().map_err(|_| Error::Malformed)?;
        let p = principal(&app, &headers, peer.as_ref().map(|v| &v.0), &audit, false).await?;
        let employee = employee(&app, &headers, &audit)
            .await?
            .ok_or(Error::Unauthorized)?;
        let request = rss_mdm_authorization_service::context::RequestAuth {
            proof: Arc::new(employee),
            sessions: app.identity.as_ref().clone(),
            deadline,
        };
        let value = app
            .business
            .device_access_directory(&p, &request, &page, app.admission.as_ref())
            .await
            .map_err(domain)?;
        Ok(NoStore(Json(value)))
    })
    .await
}

struct AccessDirectory;
impl rss_mdm_http_contract::query::WindowOwner for AccessDirectory {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_device_access_postgres::device_access::DISCOVERY
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct RecoveryUseAccepted {
    accepted: bool,
}

async fn principal(
    app: &Services,
    headers: &axum::http::HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    audit: &RequestAudit,
    _tasks: bool,
) -> Result<rss_mdm_registration_service::DevicePrincipal, AgentError> {
    if headers.contains_key("authorization") || headers.contains_key("cookie") {
        return Err(Error::Unauthorized.into());
    }
    let p = app
        .authentication
        .authenticate(peer.ok_or(Error::Unauthorized)?)
        .await
        .map_err(|e| AgentError::Enrollment(e.code))?;
    audit.identify_device(p.registration());
    audit.registration(p.registration());
    audit.target_device(p.device());
    Ok(p)
}
async fn employee(
    app: &Services,
    headers: &axum::http::HeaderMap,
    audit: &RequestAudit,
) -> Result<Option<rss_mdm_authorization_service::context::AuthorizedPrincipal>, AgentError> {
    let headers = headers
        .get_all("x-rss-user-session")
        .iter()
        .collect::<Vec<_>>();
    if headers.len() != 1 {
        return Err(Error::Unauthorized.into());
    }
    let secret = rss_identity_core::session::SessionSecret::parse(
        headers[0].to_str().map_err(|_| Error::Unauthorized)?.into(),
    )
    .map_err(|_| Error::Unauthorized)?;
    let p = app
        .identity
        .authenticate(
            &app.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Cookie(secret),
        )
        .await?;
    p.bind_audit(audit).map_err(Error::from)?;
    Ok(Some(p))
}
