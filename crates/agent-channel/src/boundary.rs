//! This ingress owns request admission, body limits, audit settlement and wire errors.
use crate::{Error, Failure};
use axum::{
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::{
    RequestAudit,
    completion::{Replacement, ResponseFailure},
};
use rss_mdm_http_contract::Router;
use std::sync::Arc;
#[derive(Clone)]
pub struct Envelope {
    pub request_budget: rss_axum::RequestBudget,
    pub profile: rss_mdm_install_support::StorageProfile,
    pub host: String,
    pub clock: Arc<dyn rss_observation::Clock>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub buffered_bytes: Arc<tokio::sync::Semaphore>,
}
pub fn wrap<M: rss_mdm_http_contract::module::Declaration>(
    router: Router<(), M>,
    envelope: Envelope,
) -> Router<(), M> {
    wrap_family(router, envelope, false)
}
pub fn wrap_enroll<M: rss_mdm_http_contract::module::Declaration>(
    router: Router<(), M>,
    envelope: Envelope,
) -> Router<(), M> {
    wrap_family(router, envelope, true)
}
fn wrap_family<M: rss_mdm_http_contract::module::Declaration>(
    router: Router<(), M>,
    envelope: Envelope,
    enrollment: bool,
) -> Router<(), M> {
    let budget = envelope.request_budget;
    router
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(
            (envelope, enrollment),
            admit,
        ))
        .layer(middleware::from_fn_with_state(
            (budget, enrollment),
            controlled,
        ))
}
#[derive(Clone, Copy)]
struct Completed;
async fn controlled(
    State((budget, enrollment)): State<(rss_axum::RequestBudget, bool)>,
    mut request: Request,
    next: Next,
) -> Response {
    // The worker retains audit ownership when the transport stops waiting.
    let observed = Arc::new(std::sync::OnceLock::<RequestAudit>::new());
    request.extensions_mut().insert(observed.clone());
    let mut response = rss_axum::request_control(State(budget), request, next).await;
    if response.extensions_mut().remove::<Completed>().is_some() {
        return response;
    }
    use rss_mdm_audit_integration::WriteOutcome;
    let snapshot = observed.get().map(RequestAudit::snapshot);
    let error = match snapshot.as_ref().map(|s| s.write_outcome) {
        Some(WriteOutcome::Unknown | WriteOutcome::Committed) => Error::CommitUnknown,
        Some(WriteOutcome::RollbackFailed) => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::RequestDeadline),
    };
    let mut response = family(project(error), enrollment);
    if let Some(id) = snapshot.as_ref().and_then(|s| s.operation_id) {
        response.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_str(&id.to_string()).expect("UUID"),
        );
    }
    secure(
        response,
        observed
            .get()
            .map_or_else(uuid::Uuid::new_v4, RequestAudit::request_id),
    )
}
fn family(response: Response, enrollment: bool) -> Response {
    if !enrollment {
        return response;
    }
    let Some(body) = response
        .extensions()
        .get::<rss_mdm_agent_wire::runtime::ErrorBody>()
        .copied()
    else {
        return response;
    };
    use rss_mdm_agent_wire::{enroll::ErrorCode as C, runtime::ErrorCode as R};
    let code = match body.code {
        R::MalformedRequest => C::MalformedRequest,
        R::InvalidIdentity => C::InvalidIdentity,
        R::PermissionDenied => C::PermissionDenied,
        R::OperationConflict => C::OperationConflict,
        R::OperationUnknown => C::ActivationUnknown,
        _ => C::ServiceUnavailable,
    };
    let (parts, _) = response.into_parts();
    let mut output = crate::enroll::failure_response(code, None);
    output.extensions_mut().extend(parts.extensions);
    output.headers_mut().extend(parts.headers);
    output
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
pub async fn admit(
    State((envelope, enrollment)): State<(Envelope, bool)>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(control) = request
        .extensions()
        .get::<rss_axum::RequestControl>()
        .cloned()
    else {
        return project(Error::Unavailable(Failure::RequestDeadline));
    };
    let deadline = control.deadline();
    let started = envelope.clock.now();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let action = if (request.method() == axum::http::Method::GET
        || request.method() == axum::http::Method::HEAD)
        && matches!(
            route,
            "/api/v1/agent/runtime/current-user" | "/current-user"
        ) {
        "agent_current_user_read"
    } else {
        route_action(route)
    };
    let audit = RequestAudit::unresolved(
        rss_mdm_audit_integration::Origin::Request,
        envelope.profile,
        action,
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    if let Some(observed) = request
        .extensions()
        .get::<Arc<std::sync::OnceLock<RequestAudit>>>()
    {
        let _ = observed.set(audit.clone());
    }
    let id = audit.request_id();
    let gateway_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned);
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_request_received","request_id":id,"gateway_request_id":gateway_id,
        "method":request.method().as_str(),"path":request.uri().path()})
    );
    request.extensions_mut().insert(audit.clone());
    let host_lease = request
        .extensions()
        .get::<Arc<tokio::sync::OwnedSemaphorePermit>>()
        .cloned();
    let lifecycle = request
        .extensions()
        .get::<rss_runtime::AdmissionGate>()
        .cloned();
    let ingress_lease = request
        .extensions()
        .get::<Arc<Vec<tokio::sync::OwnedSemaphorePermit>>>()
        .cloned();
    let Some(permit) = lifecycle.and_then(|gate| gate.try_admit().ok()) else {
        audit.finalize(None);
        let mut response = family(limited(id), enrollment);
        response.extensions_mut().insert(Completed);
        return response;
    };
    let work = async move {
        let input = if request.headers().get_all(header::HOST).iter().count() != 1
            || request.uri().to_string().len() > 8192
            || request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|host| !envelope.host.is_empty() && host != envelope.host)
        {
            Err(project(Error::Malformed))
        } else {
            use rss_request_context::CancellationObserver;
            tokio::select! {
                biased;
                () = control.cancelled() => Err(project(Error::Unavailable(Failure::RequestDeadline))),
                result = body(request,envelope.buffered_bytes.clone(),deadline) => result,
            }
        };
        let (input, requests_permit) = match input {
            Ok((request, permit)) => (Ok(request), Some(permit)),
            Err(response) => (Err(response), None),
        };
        let _requests_permit = requests_permit;
        let _lifecycle_permit = permit;
        let _ingress_lease = ingress_lease;
        let _host_lease = host_lease;
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
            deadline,
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
            serde_json::json!({"event":"mdm_request","request_id":id,"gateway_request_id":gateway_id,"operation_id":snapshot.operation_id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis(),"error":response.extensions().get::<Error>()})
        );
        secure(family(response, enrollment), id)
    };
    let mut response = tokio::spawn(work).await.unwrap_or_else(|_| limited(id));
    response.extensions_mut().insert(Completed);
    response
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
    let mut response =
        crate::ingress_error(rss_mdm_agent_wire::runtime::ErrorCode::ServiceUnavailable);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    secure(response, id)
}
async fn body(
    request: Request,
    requests: Arc<tokio::sync::Semaphore>,
    deadline: rss_request_context::Deadline,
) -> Result<(Request, tokio::sync::OwnedSemaphorePermit), Response> {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let limit = if route.contains("/telemetry/") {
        4 * 1024 * 1024
    } else if route.ends_with("/reports") {
        rss_mdm_agent_wire::runtime::MAX_REPORT_BYTES
    } else if route.contains("/self-service/") {
        131072
    } else if route.ends_with("/tasks/{id}/events") {
        rss_mdm_agent_wire::runtime::MAX_TASK_REQUEST_BYTES
    } else if request.uri().path().contains("/enroll/") {
        65536
    } else {
        rss_mdm_agent_wire::runtime::MAX_REQUEST_BYTES
    };
    let permit = requests
        .try_acquire_many_owned(2 * limit as u32)
        .map_err(|_| limited(uuid::Uuid::new_v4()))?;
    let (parts, body) = request.into_parts();
    match tokio::time::timeout_at(deadline.instant().into(), axum::body::to_bytes(body, limit))
        .await
    {
        Ok(Ok(bytes)) => Ok((
            Request::from_parts(parts, axum::body::Body::from(bytes)),
            permit,
        )),
        Ok(Err(_)) => Err(crate::ingress_error(
            rss_mdm_agent_wire::runtime::ErrorCode::MalformedRequest,
        )),
        Err(_) => Err(project(Error::Unavailable(Failure::RequestDeadline))),
    }
}
fn project(error: Error) -> Response {
    crate::AgentError::Service(error).into_response()
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/api/v1/agent/enroll/connections" | "/connections" => "agent_connections_read",
        "/api/v1/agent/enroll/connections/acknowledgements" | "/connections/acknowledgements" => {
            "agent_connections_ack"
        }
        "/api/v1/agent/enroll/connections/failures" | "/connections/failures" => {
            "agent_connections_failure"
        }
        "/api/v1/agent/enroll/native-grants" | "/native-grants" => "agent_native_grant",
        "/api/v1/agent/enroll/bootstrap/scep/challenge" | "/bootstrap/scep/challenge" => {
            "agent_bootstrap_sign"
        }
        "/api/v1/agent/enroll/bootstrap/scep/notify" | "/bootstrap/scep/notify" => {
            "agent_bootstrap_issued"
        }
        "/api/v1/agent/enroll/certificates" | "/certificates" => "device_certificate_authorize",
        "/api/v1/agent/enroll/activate" | "/activate" => "device_certificate_activate",
        "/api/v1/agent/runtime/current-user" | "/current-user" => "agent_current_user_change",
        "/api/v1/agent/runtime/reports" | "/reports" => "agent_report",
        "/api/v1/agent/runtime/reports/{id}" | "/reports/{id}" => "agent_report_read",
        "/api/v1/agent/runtime/self-service" | "/self-service" => "command_read",
        "/api/v1/agent/runtime/self-service/invocations" | "/self-service/invocations" => {
            "command_accept"
        }
        "/api/v1/agent/runtime/self-service/invocations/{id}"
        | "/self-service/invocations/{id}" => "command_read",
        _ => "protected_request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_rejections_keep_the_agent_action() {
        assert_eq!(
            route_action("/api/v1/agent/enroll/activate"),
            "device_certificate_activate"
        );
    }
}
