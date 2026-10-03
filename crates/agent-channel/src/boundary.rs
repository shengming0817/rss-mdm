//! This ingress owns request admission, body limits, audit settlement and wire errors.
use crate::{Error, Failure};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, header},
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
    let audit = RequestAudit::new(envelope.tenant.clone(), route_action(route));
    let id = audit.request_id();
    let _permit = match envelope.admission.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            audit.finalize(None);
            return limited(id);
        }
    };
    request.extensions_mut().insert(audit.clone());
    let mut response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
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
    let mut response = crate::ingress_error(rss_mdm_agent_wire::ErrorCode::ServiceUnavailable);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    secure(response, id)
}
async fn body(request: Request, next: Next, requests: Arc<tokio::sync::Semaphore>) -> Response {
    let _permit = match requests.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return crate::ingress_error(rss_mdm_agent_wire::ErrorCode::ServiceUnavailable),
    };
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let limit = if route.ends_with("/tasks/{id}/events") {
        rss_mdm_agent_wire::MAX_TASK_REQUEST_BYTES
    } else {
        rss_mdm_agent_wire::MAX_REQUEST_BYTES
    };
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(Duration::from_secs(8), axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Ok(Err(_)) => crate::ingress_error(rss_mdm_agent_wire::ErrorCode::MalformedRequest),
        Err(_) => project(Error::Unavailable(Failure::RequestDeadline)),
    }
}
fn project(error: Error) -> Response {
    crate::AgentError::Service(error).into_response()
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/api/agent/v6/registrations" | "/registrations" => "agent_registration",
        "/api/agent/v6/reports" | "/reports" => "agent_report",
        "/api/agent/v6/reports/{id}" | "/reports/{id}" => "agent_report_read",
        _ => "protected_request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_rejections_keep_the_agent_action() {
        assert_eq!(
            route_action("/api/agent/v6/registrations"),
            "agent_registration"
        );
    }
}
