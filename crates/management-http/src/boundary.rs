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
use std::sync::Arc;
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
    let endpoints = Arc::new(router.endpoints().to_vec());
    router.layer(middleware::from_fn_with_state((envelope, endpoints), admit))
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
        Some(Error::Unavailable(Failure::AuditBackpressure)) => {
            Some(ResponseFailure::AuditBackpressure)
        }
        Some(Error::Unavailable(Failure::AuditReserveExhausted)) => {
            Some(ResponseFailure::AuditReserveExhausted)
        }
        Some(Error::Unavailable(Failure::Audit)) => Some(ResponseFailure::AuditUnavailable),
        _ => None,
    }
}
pub async fn admit(
    State((envelope, endpoints)): State<(Envelope, Arc<Vec<rss_mdm_http_contract::Endpoint>>)>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let uri_limit = if route == "/api/v1/resources" {
        rss_mdm_query::MAX_RAW_QUERY_BYTES + "/api/v1/resources?".len()
    } else {
        8192
    };
    let intent = endpoints
        .iter()
        .find(|endpoint| endpoint.path == route && endpoint.method == request.method().as_str())
        .map_or(
            rss_mdm_audit_integration::AuditIntent::Routine,
            request_intent,
        );
    let audit = RequestAudit::new(envelope.tenant.clone(), route_action(route), intent);
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
        || request.uri().to_string().len() > uri_limit
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
    let failure = response
        .extensions()
        .get::<ResponseFailure>()
        .copied()
        .or_else(|| classify(response.extensions().get::<Error>()));
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
/// Identity commits its own security event. Transport diagnostics must never replace
/// a settled SDK response (which may contain a rotated session credential).
pub async fn authentication(
    State(envelope): State<Envelope>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let audit = RequestAudit::new(
        envelope.tenant.clone(),
        "authentication",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let id = audit.request_id();
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
        project(Error::Malformed)
    } else {
        body(request, next, envelope.requests).await
    };
    if response
        .extensions()
        .get::<crate::api_access::AdmissionRejected>()
        .is_some()
    {
        if let Some(replacement) = rss_mdm_audit_integration::completion::complete(
            &envelope.audit_store,
            &audit,
            response.status().as_u16(),
            classify(response.extensions().get::<Error>()),
        )
        .await
        {
            response = project(match replacement {
                Replacement::CommitUnknown => Error::CommitUnknown,
                Replacement::RollbackFailed => Error::RollbackFailed,
                Replacement::Audit(e) => e.into(),
            });
        }
    } else {
        audit.finalize(None);
    }
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
    let crate::body_policy::BodyPolicy::Buffered(limit) =
        crate::body_policy::for_route(route, request.method())
    else {
        return next.run(request).await;
    };
    match crate::body_policy::buffer(request, limit).await {
        Ok(request) => next.run(request).await,
        Err(error) => project(error),
    }
}

fn project(error: Error) -> Response {
    error.into_response()
}
// Bind known disclosures before authentication. Remaining choices consume the route owner's
// semantic operation declaration, never a GET/POST or action-suffix heuristic.
fn request_intent(
    endpoint: &rss_mdm_http_contract::Endpoint,
) -> rss_mdm_audit_integration::AuditIntent {
    use rss_mdm_audit_integration::{AuditIntent as I, SensitiveAction as S};
    use rss_mdm_http_contract::Operation as O;
    match endpoint.path.as_str() {
        "/api/v1/devices/{device}/recovery-credentials/{id}/versions/{version}/secret"
        | "/api/v1/devices/{device}/device-access/materials/{id}/versions/{version}/secret" => {
            I::Sensitive(S::CredentialReveal)
        }
        "/api/v1/certificate-archive/export" => I::Sensitive(S::CertificatePrivateExport),
        "/api/v1/certificate-archive/vault/unlock"
        | "/api/v1/api-keys/{id}/rotate"
        | "/api/v1/software/content/cleanup"
        | "/api/v1/pki/rotations"
        | "/api/v1/pki/signing/recover"
        | "/api/v1/pki/crls"
        | "/api/v1/pki/{purpose}/rotations" => I::Management,
        "/api/v1/audit-events" => I::Sensitive(S::AuditHistoryRead),
        "/api/v1/resources/{id}/versions/{version}/script" => I::Sensitive(S::ScriptContentRead),
        _ if endpoint
            .operations
            .iter()
            .any(|op| matches!(op, O::Create | O::Update | O::Delete | O::Lifecycle)) =>
        {
            I::Management
        }
        _ => I::Routine,
    }
}
fn route_action(route: &str) -> &'static str {
    match route {
        "/api/v1/agent-connections" | "/api/v1/agent-connections/configuration" => {
            "agent_connections_read"
        }
        "/api/v1/agent-connections/publish" => "agent_connections_publish",
        "/api/v1/agent-connection-operations/{id}" => "agent_connections_operation_read",
        "/api/v1/agent-connections/devices"
        | "/api/v1/agent-connections/devices/{device}/observation" => {
            "agent_connections_devices_read"
        }
        "/api/v1/agent-issuances/{id}/recovery-operations/{operation}" => {
            "agent_certificate_recovery_read"
        }
        "/api/v1/device-associations" => "device_association_confirm",
        "/api/v1/device-associations/{id}/revoke" => "device_association_revoke",
        "/api/v1/device-associations/changes"
        | "/api/v1/device-associations/{id}"
        | "/api/v1/devices/{device}/association-candidates" => "device_association_read",
        "/api/v1/device-retirements/{id}" => "device_retirement_read",
        "/api/v1/device-retirements/{id}/force-revoke" => "device_retirement_force_revoke",
        "/api/v1/device-views/{kind}/{id}/asset-state" => "device_asset_state",
        "/api/v1/agent-requests/{id}/reenroll/{device}" => "agent_grant_authorize",
        "/api/v1/device-views"
        | "/api/v1/device-views/{kind}/{id}"
        | "/api/v1/device-views/{kind}/{id}/inventory-lists/{field}" => "device_view_read",
        "/api/v1/certificate-archive/vault/unlock" => "certificate_archive_unlock",
        "/api/v1/certificate-archive/vault/lock" => "certificate_archive_lock",
        "/api/v1/devices/{device}/timeline" => "timeline_read",
        "/api/v1/audit-events" => "audit_search",
        "/api/v1/runtime/diagnostics" => "runtime_diagnostics_read",
        "/api/v1/authorization" | "/api/v1/tenant-administration/authorization" => {
            "authorization_effective_read"
        }
        "/api/v1/authorization/rules" | "/api/v1/tenant-administration/authorization/rules" => {
            "authorization_rules_read"
        }
        "/api/v1/authorization/user-groups" => "authorization_groups_read",
        "/api/v1/authorization/user-groups/{id}/members" => "authorization_members_read",
        "/api/v1/authorization/departments" => "authorization_departments_read",
        "/api/v1/authorization/rules/{id}"
        | "/api/v1/authorization/user-groups/{id}"
        | "/api/v1/tenant-administration/authorization/rules/{id}" => "authorization_write",
        "/api/v1/enrollments" | "/api/v1/self-enrollments" => "enrollment_create",
        "/api/v1/self-enrollments/agent" => "agent_grant_create",
        "/api/v1/self-enrollments/agent/{id}/cancel" => "agent_grant_revoke",
        "/api/v1/registration-quotas/me"
        | "/api/v1/registration-quotas/users/{instance}/{principal}/usage" => {
            "registration_quota_read"
        }
        "/api/v1/registration-quotas/defaults"
        | "/api/v1/registration-quotas/users/{instance}/{principal}" => "registration_quota_change",
        "/api/v1/devices/{device}/registration-user" => "registration_user_change",
        "/api/v1/enrollments/{id}" => "enrollment_read",
        "/api/v1/devices/{device}/registrations" => "registration_read",
        "/api/v1/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v1/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v1/devices/{device}/registrations/{registration}/revoke" => "credential_revoke",
        "/api/v1/devices/{id}/inventory" => "inventory_read",
        "/api/v1/devices/{id}/collections/{run}"
        | "/api/v1/devices/{id}/collections/{run}/fields/{field}/items" => "collection_read",
        "/api/v1/devices/{id}/actions" => "device_action",
        _ => "protected_request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pki_mutations_are_management_but_trust_queries_are_routine() {
        use rss_mdm_audit_integration::AuditIntent;
        let routes = crate::pki::routes();
        for mut endpoint in routes.endpoints().iter().cloned() {
            endpoint.path = format!("/api/v1{}", endpoint.path);
            let expected = match endpoint.method {
                "POST" => AuditIntent::Management,
                "GET" => AuditIntent::Routine,
                method => panic!("unexpected PKI method: {method}"),
            };
            assert_eq!(request_intent(&endpoint), expected, "{}", endpoint.path);
        }
    }
    #[test]
    fn route_templates_select_audit_actions() {
        assert_eq!(
            route_action("/api/v1/devices/{device}/registrations"),
            "registration_read"
        );
        assert_eq!(
            route_action("/api/v1/devices/{device}/registrations/{registration}/revoke"),
            "credential_revoke"
        );
        assert_eq!(
            route_action("/api/v1/devices/{id}/collections/{run}"),
            "collection_read"
        );
    }
    #[tokio::test]
    async fn registration_errors_retain_typed_completion_and_secure_projection() {
        use rss_mdm_audit_integration::Error as A;
        use rss_mdm_registration_service::Error as R;
        let audit = |error| R::Audit(Arc::new(error));
        for (error, status, code, expected) in [
            (
                R::Unauthorized,
                401,
                "invalid_identity",
                Some(ResponseFailure::Denied),
            ),
            (
                R::Forbidden,
                403,
                "permission_denied",
                Some(ResponseFailure::Forbidden),
            ),
            (
                R::CommitUnknown,
                503,
                "operation_unknown",
                Some(ResponseFailure::CommitUnknown),
            ),
            (
                R::RollbackFailed,
                503,
                "operation_rollback_unconfirmed",
                Some(ResponseFailure::RollbackFailed),
            ),
            (
                R::Deadline,
                503,
                "service_unavailable",
                Some(ResponseFailure::Deadline),
            ),
            (
                audit(A::Receipt),
                500,
                "audit_integrity_error",
                Some(ResponseFailure::AuditIntegrity),
            ),
            (
                audit(A::Isolation),
                500,
                "audit_contract_error",
                Some(ResponseFailure::AuditContract),
            ),
            (
                audit(A::Admission),
                500,
                "audit_contract_error",
                Some(ResponseFailure::AuditContract),
            ),
            (
                audit(A::Audit(rss_audit_postgres::Error::InvalidBound)),
                500,
                "audit_contract_error",
                Some(ResponseFailure::AuditContract),
            ),
            (
                audit(A::Audit(rss_audit_postgres::Error::StorageContract)),
                500,
                "audit_integrity_error",
                Some(ResponseFailure::AuditIntegrity),
            ),
            (R::Storage, 503, "service_unavailable", None),
            (R::Malformed, 400, "malformed_request", None),
            (R::Conflict, 409, "operation_conflict", None),
        ] {
            let response = Error::from(error).into_response();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(classify(response.extensions().get::<Error>()), expected);
            if expected == Some(ResponseFailure::Deadline) {
                assert!(matches!(
                    response.extensions().get::<Error>(),
                    Some(Error::Unavailable(Failure::RequestDeadline))
                ));
            }
            let audit = RequestAudit::new(
                "11111111-1111-4111-8111-111111111111".into(),
                "protected_request",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let id = audit.request_id();
            let response = secure(response, id);
            if code == "invalid_identity" {
                assert!(
                    uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap())
                        .is_ok()
                );
                assert_eq!(response.headers()["x-request-id"], id.to_string());
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
                assert_eq!(
                    response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                    "nosniff"
                );
            }
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"code": code})
            );
        }
    }
    #[tokio::test]
    async fn unavailable_causes_remain_internal() {
        use crate::{Error, Failure};
        use axum::response::IntoResponse;
        for reason in [
            Failure::RequestDeadline,
            Failure::IdentityStorage,
            Failure::AssetsStorage,
            Failure::InventoryQuery,
            Failure::ManualQuery,
            Failure::CollectionQuery,
            Failure::AssetObjectLimit,
            Failure::AssetSourceLimit,
            Failure::AssetBytesLimit,
            Failure::Clock,
            Failure::Capacity,
        ] {
            let response = Error::Unavailable(reason).into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(matches!(
                response.extensions().get::<Error>(),
                Some(Error::Unavailable(_))
            ));
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"code":"service_unavailable"})
            );
        }
    }
}
