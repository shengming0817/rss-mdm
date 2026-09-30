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
        Some(Error(rss_mdm_flow_service::Error::CommitUnknown)) => {
            Some(ResponseFailure::CommitUnknown)
        }
        Some(Error(rss_mdm_flow_service::Error::RollbackFailed)) => {
            Some(ResponseFailure::RollbackFailed)
        }
        Some(
            Error(rss_mdm_flow_service::Error::Unauthorized)
            | Error(rss_mdm_flow_service::Error::Forbidden),
        ) => Some(ResponseFailure::Denied),
        Some(Error(rss_mdm_flow_service::Error::Unavailable(Failure::RequestDeadline))) => {
            Some(ResponseFailure::Deadline)
        }
        Some(Error(rss_mdm_flow_service::Error::Unavailable(Failure::AuditIntegrity))) => {
            Some(ResponseFailure::AuditIntegrity)
        }
        Some(Error(rss_mdm_flow_service::Error::Unavailable(
            Failure::AuditContract | Failure::AuditIsolation | Failure::AuditAdmission,
        ))) => Some(ResponseFailure::AuditContract),
        Some(Error(rss_mdm_flow_service::Error::Unavailable(Failure::Audit))) => {
            Some(ResponseFailure::AuditUnavailable)
        }
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
    request.extensions_mut().insert(envelope.clock.clone());
    let mut response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(envelope.host.as_str())
    {
        project(Error(rss_mdm_flow_service::Error::Malformed))
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
            Replacement::CommitUnknown => Error(rss_mdm_flow_service::Error::CommitUnknown),
            Replacement::RollbackFailed => Error(rss_mdm_flow_service::Error::RollbackFailed),
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
/// Identity commits its own security event. Transport diagnostics must never replace
/// a settled SDK response (which may contain a rotated session credential).
pub async fn authentication(
    State(envelope): State<Envelope>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let audit = RequestAudit::new(envelope.tenant.clone(), "authentication");
    let id = audit.request_id();
    request.extensions_mut().insert(audit.clone());
    request.extensions_mut().insert(envelope.clock.clone());
    let response = if request.headers().get_all(header::HOST).iter().count() != 1
        || request.uri().to_string().len() > 8192
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(envelope.host.as_str())
    {
        project(Error(rss_mdm_flow_service::Error::Malformed))
    } else {
        body(request, next, envelope.requests).await
    };
    audit.finalize(None);
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_request","request_id":id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis()})
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
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    if (route == "/api/v3/resources/{id}/content" && request.method() == axum::http::Method::POST)
        || (route == "/api/v3/resources/{id}/uploads/{upload}"
            && request.method() == axum::http::Method::PATCH)
    {
        return next.run(request).await;
    }
    let limit = if route == "/api/v3/resources/{id}" {
        8 * 1024 * 1024
    } else {
        2 * 1024 * 1024
    };
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(Duration::from_secs(8), axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
                .await
        }
        Ok(Err(_)) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => project(Error(rss_mdm_flow_service::Error::Unavailable(
            Failure::RequestDeadline,
        ))),
    }
}
fn project(error: Error) -> Response {
    error.into_response()
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/api/v2/runtime/diagnostics" => "runtime_diagnostics_read",
        "/api/v1/authorization" => "authorization_effective_read",
        "/api/v1/authorization/rules" => "authorization_rules_read",
        "/api/v1/authorization/user-groups" => "authorization_groups_read",
        "/api/v1/authorization/user-groups/{id}/members" => "authorization_members_read",
        "/api/v1/authorization/departments" => "authorization_departments_read",
        "/api/v1/authorization/rules/{id}" | "/api/v1/authorization/user-groups/{id}" => {
            "authorization_write"
        }
        "/api/v3/enrollments" => "enrollment_create",
        "/api/v3/enrollments/{id}" => "enrollment_read",
        "/api/v3/devices/{device}/registrations" => "registration_read",
        "/api/v3/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v3/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v3/devices/{device}/registrations/{registration}/revoke" => "credential_revoke",
        "/api/v2/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/collection-runs" => "collection_start",
        "/api/v1/devices/{id}/collection-runs/{run}" => "collection_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        _ => "protected_request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_actions_precede_handler_rejections() {
        assert_eq!(
            route_action("/api/v3/devices/{device}/registrations"),
            "registration_read"
        );
        assert_eq!(
            route_action("/api/v3/devices/{device}/registrations/{registration}/revoke"),
            "credential_revoke"
        );
        assert_eq!(
            route_action("/api/v1/devices/{id}/collection-runs"),
            "collection_start"
        );
    }
}
