//! Independent CMS ingress: device authentication, no employee session or task capability.
use crate::{AgentError, Error};
use axum::{
    Extension, Json,
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
};
use rss_mdm_agent_wire::{filevault as w, runtime::ErrorCode};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{
    Operation, Router, catalog,
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;
struct Services {
    enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    recovery: Arc<rss_mdm_recovery_credentials::FilevaultService>,
}
pub fn routes(
    enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    recovery: Option<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
) -> Router {
    let Some(recovery) = recovery else {
        return Router::new();
    };
    Router::new()
        .route(
            "/filevault/configuration",
            get(configuration).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .route(
            "/filevault/escrows",
            post(upload).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .route(
            "/filevault/operations/{id}",
            get(receipt).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .layer(DefaultBodyLimit::max(w::REQUEST_BYTES))
        .with_state(Arc::new(Services {
            enrollment,
            recovery,
        }))
}
fn error(e: rss_mdm_recovery_credentials::Error) -> AgentError {
    use rss_mdm_recovery_credentials::Error as E;
    AgentError::Wire(match e {
        E::Malformed | E::Integrity => ErrorCode::MalformedRequest,
        E::Forbidden | E::Unauthorized => ErrorCode::PermissionDenied,
        E::Conflict => ErrorCode::OperationConflict,
        E::NotFound => ErrorCode::ReportNotFound,
        _ => ErrorCode::ServiceUnavailable,
    })
}
async fn principal(
    s: &Services,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    audit: &RequestAudit,
) -> Result<rss_mdm_registration_service::DevicePrincipal, AgentError> {
    let p = crate::authenticate(&s.enrollment, headers, peer).await?;
    audit.identify_device(p.registration());
    audit.registration(p.registration());
    audit.target_device(p.device());
    Ok(p)
}
async fn configuration(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
) -> Result<Json<w::Configuration>, AgentError> {
    crate::bounded(async {
        let p = principal(&s, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.recovery.configuration(&p).await.map(Json).map_err(error)
    })
    .await
}
async fn upload(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Result<Json<w::Upload>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<w::Receipt>, AgentError> {
    crate::bounded(async {
        let p = principal(&s, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        let Json(input) = input.map_err(|_| Error::Malformed)?;
        s.recovery
            .receive(&p, &input, &audit)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
}
async fn receipt(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Option<w::Receipt>>, AgentError> {
    crate::bounded(async {
        let p = principal(&s, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.recovery.receipt(&p, id).await.map(Json).map_err(error)
    })
    .await
}
