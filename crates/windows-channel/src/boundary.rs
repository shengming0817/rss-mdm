//! This ingress owns request admission, body limits, audit settlement and wire errors.
use crate::{Error, Failure};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::{
    RequestAudit,
    completion::{Replacement, ResponseFailure},
};
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
        Some(Error::Unauthorized | Error::Forbidden) => Some(ResponseFailure::Denied),
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
    let soap = route.starts_with("/EnrollmentServer/");
    let agent = route == "/api/agent/v5/managed-registrations";
    let audit = RequestAudit::new(envelope.tenant.clone(), route_action(route));
    let id = audit.request_id();
    let _permit = match envelope.admission.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            audit.finalize(None);
            return if agent {
                secure(agent_response(limited(id)), id)
            } else {
                limited(id)
            };
        }
    };
    request.extensions_mut().insert(audit.clone());
    let mut response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .uri()
            .authority()
            .is_some_and(|a| a.as_str() != envelope.host)
        || request.uri().scheme_str().is_some_and(|s| s != "https")
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(envelope.host.as_str())
    {
        project(Error::Malformed)
    } else {
        body(request, next, envelope.requests).await
    };
    if agent {
        response = agent_response(response);
    }
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
    if soap
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"application/soap+xml"))
        && let Some(error) = response.extensions().get::<Error>().cloned()
    {
        response = crate::fault(None, error);
    }
    if agent {
        response = agent_response(response);
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
async fn body(request: Request, next: Next, requests: Arc<tokio::sync::Semaphore>) -> Response {
    let _requests = requests;
    let limit = 2 * 1024 * 1024;
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(Duration::from_secs(8), axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Ok(Err(_)) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => project(Error::Unavailable(Failure::RequestDeadline)),
    }
}
fn project(error: Error) -> Response {
    error.into_response()
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/api/agent/v5/managed-registrations" => "agent_registration",
        "/EnrollmentConfiguration" | "/EnrollmentServer/Discovery.svc" => "windows_discovery",
        "/EnrollmentServer/LinkedPolicy.svc" | "/EnrollmentServer/Policy.svc" => "windows_policy",
        "/EnrollmentServer/LinkedEnrollment.svc" | "/EnrollmentServer/Enrollment.svc" => {
            "enrollment_issue"
        }
        "/ManagementServer/MDM.svc" => "windows_management",
        _ => "protected_request",
    }
}

fn agent_response(response: Response) -> Response {
    if response.status().is_success() {
        return response;
    }
    use rss_mdm_execution_service::channels::Rejection as R;
    let rejection = response
        .extensions()
        .get::<Error>()
        .cloned()
        .map(R::from)
        .unwrap_or_else(|| {
            if response.status().is_client_error()
                && response.status() != StatusCode::TOO_MANY_REQUESTS
            {
                R::Malformed
            } else {
                R::Storage
            }
        });
    let (status, body) = response
        .extensions()
        .get::<rss_mdm_agent_wire::ErrorBody>()
        .copied()
        .map(|body| (400, body))
        .unwrap_or_else(|| rejection.agent_error());
    let (parts, _) = response.into_parts();
    let mut projected = (
        StatusCode::from_u16(status).expect("closed status"),
        Json(body),
    )
        .into_response();
    projected.extensions_mut().extend(parts.extensions);
    if let Some(retry) = parts.headers.get(header::RETRY_AFTER) {
        projected
            .headers_mut()
            .insert(header::RETRY_AFTER, retry.clone());
    }
    projected
}
