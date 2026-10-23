//! Enrollment endpoints accept bootstrap material; activation requires actual TLS possession.
use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::enroll as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
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
            .route(
                "/requests",
                post(request).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/native-grants",
                post(native_grant).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/bootstrap/scep/challenge",
                post(bootstrap_challenge).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/bootstrap/scep/notify",
                post(bootstrap_notify).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/configurations/exchange",
                post(exchange).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/configurations/status",
                post(exchange_status).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/reservations/cancel",
                post(cancel).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/certificates",
                post(issue).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/activate",
                post(activate).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/status",
                post(status).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/renewal-grants",
                post(renew).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/renewal-grants/status",
                post(renewal_status).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/connections",
                get(connections).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/connections/failures",
                post(connection_failure).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/connections/acknowledgements",
                post(acknowledge_connections).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/trust",
                get(trust).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/trust/observations",
                post(observe_trust).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
            .route(
                "/trust/acknowledgements",
                post(acknowledge).owned(
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            )
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
    peer: Option<Extension<ClientCertificateEvidence>>,
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
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    Ok(Json(s.renew(&peer.0, &body(input)?, &a).await?))
}
async fn renewal_status(
    State(s): State<Arc<Service>>,
    headers: HeaderMap,
    input: Body<wire::RenewalStatusRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.renewal_status(&body(input)?).await?))
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
        C::EnrollmentPaused => StatusCode::CONFLICT,
        C::PermissionDenied | C::GrantRevoked | C::GrantExpired => StatusCode::FORBIDDEN,
        C::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
        C::OperationConflict
        | C::ConnectionDeploymentUnobserved
        | C::ConnectionRetirementBlocked => StatusCode::CONFLICT,
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

async fn connections(
    State(s): State<Arc<Service>>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
) -> Result<Json<rss_mdm_agent_wire::connections::SignedConfiguration>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.authenticate(&peer.0).await?;
    Ok(Json(s.connection_configuration().await?))
}
async fn acknowledge_connections(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    Extension(origin): Extension<rss_mdm_certificate::GatewayOrigin>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::connections::Acknowledgement>,
) -> Result<StatusCode, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.acknowledge_connections(&peer.0, &body(input)?, &origin, &a)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn trust(
    State(s): State<Arc<Service>>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
) -> Result<Json<rss_mdm_agent_wire::pki::Trust>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.device_trust(peer.as_ref().map(|v| &v.0)).await?))
}
async fn acknowledge(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::pki::Acknowledgement>,
) -> Result<StatusCode, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.acknowledge_trust(&peer.0, &body(input)?, &a).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn exchange(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Body<wire::configuration::Exchange>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.exchange_configuration(&body(input)?, &a).await?))
}
async fn exchange_status(
    State(s): State<Arc<Service>>,
    headers: HeaderMap,
    input: Body<wire::configuration::ExchangeStatus>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.configuration_exchange_status(&body(input)?).await?))
}
async fn cancel(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Body<wire::configuration::Cancel>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    Ok(Json(s.cancel_reservation(&body(input)?, &a).await?))
}

async fn native_grant(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<wire::NativeGrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    Ok(Json(s.native_grant(&peer.0, &body(input)?, &a).await?))
}
async fn bootstrap_challenge(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, HttpFailure> {
    let cfg = s.bootstrap_configuration()?;
    let input = cfg
        .webhooks
        .verify(
            rss_mdm_pki_service::scep::Stage::Challenge,
            &headers,
            &bytes,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    Ok(Json(s.bootstrap_challenge(input, &a).await?))
}
async fn bootstrap_notify(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, HttpFailure> {
    let cfg = s.bootstrap_configuration()?;
    let input = cfg
        .webhooks
        .verify(
            rss_mdm_pki_service::scep::Stage::Notify,
            &headers,
            &bytes,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.bootstrap_notify(input, &a).await?;
    Ok(Json(serde_json::json!({"allow":true})))
}

async fn observe_trust(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::pki::Observation>,
) -> Result<Json<rss_mdm_agent_wire::pki::Observation>, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    let input = body(input)?;
    s.observe_trust(&peer.0, &input, &a).await?;
    Ok(Json(input))
}

async fn connection_failure(
    State(s): State<Arc<Service>>,
    Extension(a): Extension<RequestAudit>,
    Extension(origin): Extension<rss_mdm_certificate::GatewayOrigin>,
    peer: Option<Extension<ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Body<rss_mdm_agent_wire::connections::FailureReport>,
) -> Result<StatusCode, HttpFailure> {
    bootstrap(&headers)?;
    let peer =
        peer.ok_or_else(|| Failure::from(rss_mdm_registration_service::Error::Unauthorized))?;
    s.report_connection_failure(&peer.0, &body(input)?, &origin, &a)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
