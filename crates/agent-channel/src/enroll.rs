//! Enrollment endpoints accept bootstrap material; activation requires actual TLS possession.
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire::enroll as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::HandshakePeer;
use rss_mdm_registration_service::agent::{Failure, Service};
use std::sync::Arc;
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(v: Body<T>) -> Result<T, Failure> {
    v.map(|v| v.0)
        .map_err(|_| rss_mdm_registration_service::Error::Malformed.into())
}
pub fn router(service: Arc<Service>, envelope: crate::boundary::Envelope) -> Router {
    crate::boundary::wrap_enroll(
        Router::new()
            .route("/requests", post(request))
            .route("/certificates", post(issue))
            .route("/activate", post(activate))
            .route("/status", post(status))
            .route("/renewal-grants", post(renew))
            .route("/trust", get(trust))
            .route("/trust/acknowledgements", post(acknowledge))
            .with_state(service),
        envelope,
    )
}
fn bootstrap(headers: &HeaderMap) -> Result<(), Failure> {
    if headers.contains_key(header::AUTHORIZATION) {
        Err(rss_mdm_registration_service::Error::Unauthorized.into())
    } else {
        Ok(())
    }
}
async fn request(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.request(&body(input)?, &a).await?))
}
async fn issue(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Body<wire::CertificateRequest>,
) -> Result<Json<wire::Candidate>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.issue(&body(input)?, &a).await?))
}
async fn activate(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<HandshakePeer>>,
    headers: HeaderMap,
    input: Body<wire::ActivationRequest>,
) -> Result<Json<wire::ActivationReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    Ok(Json(s.activate(&peer.0, &body(input)?, &a).await?))
}
async fn status(
    State(s): State<Arc<Service>>,
    headers: HeaderMap,
    input: Body<wire::StatusRequest>,
) -> Result<Json<wire::Progress>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.poll(&body(input)?).await?))
}
async fn renew(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<HandshakePeer>>,
    headers: HeaderMap,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    Ok(Json(s.renew(&peer.0, &body(input)?, &a).await?))
}
pub struct HttpFailure(pub Failure);
impl From<Failure> for HttpFailure {
    fn from(v: Failure) -> Self {
        Self(v)
    }
}
impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        let mut response = failure_response(self.0.code, self.0.issuance_id);
        if let Some(error) = self.0.source {
            response.extensions_mut().insert(crate::Error::from(error));
        }
        response
    }
}
pub(crate) fn failure_response(code: wire::ErrorCode, id: Option<uuid::Uuid>) -> Response {
    use wire::ErrorCode as C;
    let status = match code {
        C::MalformedRequest => StatusCode::BAD_REQUEST,
        C::InvalidIdentity
        | C::CertificateExpired
        | C::CredentialRevoked
        | C::CredentialRetired => StatusCode::UNAUTHORIZED,
        C::PermissionDenied | C::GrantRevoked | C::GrantExpired => StatusCode::FORBIDDEN,
        C::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
        C::OperationConflict => StatusCode::CONFLICT,
        C::IssuanceUnknown | C::ActivationUnknown | C::ServiceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    (
        status,
        Json(wire::ErrorBody {
            code,
            issuance_id: id,
        }),
    )
        .into_response()
}

async fn trust(
    State(s): State<Arc<Service>>,
    peer: Option<Extension<HandshakePeer>>,
    headers: HeaderMap,
) -> Result<Json<rss_mdm_agent_wire::pki::Trust>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.device_trust(peer.as_ref().map(|v| &v.0)).await?))
}
async fn acknowledge(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<HandshakePeer>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::pki::Acknowledgement>,
) -> Result<StatusCode, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.acknowledge_trust(&peer.0, &body(input)?, &a).await?;
    Ok(StatusCode::NO_CONTENT)
}
