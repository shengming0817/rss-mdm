//! This ingress owns request admission, body limits, audit settlement and wire errors.
use crate::{Error, Failure};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::{
    RequestAudit,
    completion::{Replacement, ResponseFailure},
};
use rss_mdm_http_contract::Router;
use std::{sync::Arc, time::Duration};
#[derive(Clone)]
pub struct Envelope {
    pub admission: Arc<tokio::sync::Semaphore>,
    pub host: String,
    pub clock: Arc<dyn rss_observation::Clock>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub requests: Arc<tokio::sync::Semaphore>,
    pub tenant: String,
}
pub fn wrap(router: Router, envelope: Envelope) -> Router {
    router.layer(middleware::from_fn_with_state(envelope, admit))
}
fn classify(error: Option<&Error>) -> Option<ResponseFailure> {
    match error {
        Some(Error::CommitUnknown) => Some(ResponseFailure::CommitUnknown),
        Some(Error::RollbackFailed) => Some(ResponseFailure::RollbackFailed),
        Some(Error::Unauthorized) => Some(ResponseFailure::Denied),
        Some(Error::Forbidden) => Some(ResponseFailure::Forbidden),
        Some(Error::Unavailable(Failure::RequestDeadline)) => Some(ResponseFailure::Deadline),
        Some(Error::Unavailable(Failure::AuditIntegrity)) => Some(ResponseFailure::AuditIntegrity),
        Some(Error::Unavailable(
            Failure::AuditContract | Failure::AuditIsolation | Failure::AuditAdmission,
        )) => Some(ResponseFailure::AuditContract),

        Some(Error::Unavailable(Failure::Audit)) => Some(ResponseFailure::AuditUnavailable),
        _ => None,
    }
}
pub async fn admit(State(envelope): State<Envelope>, mut request: Request, next: Next) -> Response {
    let started = envelope.clock.now();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let audit = RequestAudit::new(
        envelope.tenant.clone(),
        route_action(route),
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let id = audit.request_id();
    let _permit = match envelope.admission.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            audit.finalize(None);
            return limited(id);
        }
    };
    request.extensions_mut().insert(audit.clone());
    let lifecycle = request
        .extensions()
        .get::<rss_runtime::AdmissionGate>()
        .cloned();
    let ingress_lease = request
        .extensions()
        .get::<Arc<Vec<tokio::sync::OwnedSemaphorePermit>>>()
        .cloned();
    let input = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(envelope.host.as_str())
    {
        Err(project(Error::Malformed))
    } else {
        body(request, envelope.requests.clone()).await
    };
    let Some(permit) = lifecycle.and_then(|gate| gate.try_admit().ok()) else {
        audit.finalize(None);
        return limited(id);
    };
    let work = async move {
        let _lifecycle_permit = permit;
        let _permit = _permit;
        let _ingress_lease = ingress_lease;
        let mut response = match input {
            Ok(request) => next.run(request).await,
            Err(response) => response,
        };
        let failure = classify(response.extensions().get::<Error>());
        if let Some(replacement) = rss_mdm_audit_integration::completion::complete(
            &envelope.audit_store,
            &audit,
            response.status().as_u16(),
            failure,
        )
        .await
        {
            response = project(match replacement {
                Replacement::CommitUnknown => Error::CommitUnknown,
                Replacement::RollbackFailed => Error::RollbackFailed,
                Replacement::Audit(e) => e.into(),
            });
        }

        let snapshot = audit.snapshot();
        if let Some(key) = snapshot.operation_id {
            response.headers_mut().insert(
                "idempotency-key",
                HeaderValue::from_str(&key.to_string()).expect("UUID"),
            );
        }
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_request","request_id":id,"operation_id":snapshot.operation_id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis(),"error":response.extensions().get::<Error>()})
        );
        secure(response, id)
    };
    tokio::spawn(work).await.unwrap_or_else(|_| limited(id))
}
fn secure(mut response: Response, id: uuid::Uuid) -> Response {
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id.to_string()).expect("UUID"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn limited(id: uuid::Uuid) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({"code":"request_limited"})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    secure(response, id)
}
async fn body(
    request: Request,
    requests: Arc<tokio::sync::Semaphore>,
) -> Result<Request, Response> {
    let _requests = requests;
    let limit = 2 * 1024 * 1024;
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(Duration::from_secs(8), axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(Request::from_parts(parts, axum::body::Body::from(bytes))),
        Ok(Err(_)) => Err(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
        Err(_) => Err(project(Error::Unavailable(Failure::RequestDeadline))),
    }
}
fn project(error: Error) -> Response {
    error.into_response()
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/checkin" => "apple_checkin",
        "/native/apple/ddm/assets/{operation}/{identifier}" => "apple_asset",
        "/mdm" => "apple_management",
        "/api/v1/apple/scep/challenge" | "/api/v1/apple/scep/notify" => "apple_scep",
        p if p.starts_with("/api/v1/enrollments/") && p.ends_with("/profile") => "apple_profile",
        _ => "protected_request",
    }
}
