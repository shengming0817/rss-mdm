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
    pub request_timeout: std::time::Duration,
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
    wrap_with(router, envelope, Admission::Bound)
}

// The software ingress uses this for reads whose authorization is resolved by the handler.
pub(crate) fn wrap_unresolved<M: rss_mdm_http_contract::module::Declaration>(
    router: Router<(), M>,
    envelope: Envelope,
    action: &'static str,
) -> Router<(), M> {
    wrap_with(router, envelope, Admission::Unresolved(action))
}
#[derive(Clone, Copy)]
enum Admission {
    Bound,
    Unresolved(&'static str),
}
#[derive(Clone, Copy)]
struct DownstreamResponse;
fn wrap_with<M: rss_mdm_http_contract::module::Declaration>(
    router: Router<(), M>,
    envelope: Envelope,
    admission: Admission,
) -> Router<(), M> {
    let endpoints = Arc::new(router.endpoints().to_vec());
    router
        .layer(middleware::from_fn_with_state(
            envelope.buffered_bytes.clone(),
            controlled_body,
        ))
        .layer(middleware::from_fn_with_state(
            (envelope, endpoints, admission),
            admit,
        ))
}
// The marker identifies a completed downstream response without inspecting its status or body.
async fn controlled_body(
    State(requests): State<Arc<tokio::sync::Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = if request.extensions().get::<AuthenticatedBody>().is_some() {
        next.run(request).await
    } else {
        body(request, next, requests).await
    };
    response.extensions_mut().insert(DownstreamResponse);
    response
}
#[derive(Clone)]
struct AuthenticatedBody(Arc<tokio::sync::Semaphore>);
pub(crate) async fn after_authentication(mut request: Request, next: Next) -> Response {
    match request.extensions_mut().remove::<AuthenticatedBody>() {
        Some(budget) => body(request, next, budget.0).await,
        None => next.run(request).await,
    }
}
fn classify(error: Option<&Error>) -> Option<ResponseFailure> {
    match error {
        Some(Error::CommitUnknown) => Some(ResponseFailure::CommitUnknown),
        Some(Error::RollbackFailed) => Some(ResponseFailure::RollbackFailed),
        Some(Error::Unauthorized) => Some(ResponseFailure::Denied),
        Some(Error::Forbidden) => Some(ResponseFailure::Forbidden),
        Some(Error::RequestDeadline | Error::Unavailable(Failure::RequestDeadline))
        | Some(Error::RecoveryCredentials(rss_mdm_recovery_credentials::Error::Deadline)) => {
            Some(ResponseFailure::Deadline)
        }
        Some(Error::Unavailable(Failure::AuditIntegrity)) => Some(ResponseFailure::AuditIntegrity),
        Some(Error::Unavailable(
            Failure::AuditContract | Failure::AuditIsolation | Failure::AuditAdmission,
        )) => Some(ResponseFailure::AuditContract),

        Some(Error::Unavailable(Failure::Audit)) => Some(ResponseFailure::AuditUnavailable),
        _ => None,
    }
}
fn cutoff(request: &Request, envelope: &Envelope) -> rss_request_context::Deadline {
    let installed = rss_request_context::Deadline::from_timeout(
        &rss_mdm_audit_integration::budget::RuntimeTimer,
        envelope.request_timeout,
    )
    .expect("compiled host request timeout");
    request
        .extensions()
        .get::<rss_request_context::Deadline>()
        .map_or(installed, |parent| installed.shortened_to(parent.instant()))
}
async fn admit(
    State((envelope, endpoints, admission)): State<(
        Envelope,
        Arc<Vec<rss_mdm_http_contract::Endpoint>>,
        Admission,
    )>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = envelope.clock.now();
    let total = cutoff(&request, &envelope);
    let binding = request
        .extensions()
        .get::<rss_transactional_messaging::fence::ExecutionBinding>()
        .copied();
    if matches!(admission, Admission::Bound) && binding.is_none() {
        return rejection(Error::Forbidden);
    }
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let uri_limit = if route == "/api/v1/tenants/{tenant}/resources" {
        rss_mdm_query::MAX_RAW_QUERY_BYTES + "/api/v1/tenants/{tenant}/resources?".len()
    } else {
        8192
    };
    let endpoint = endpoints
        .iter()
        .find(|endpoint| endpoint.path == route && endpoint.method == request.method().as_str());
    let protected = endpoint.is_some_and(|endpoint| endpoint.authentication.is_some());
    let intent = endpoint.map_or(
        rss_mdm_audit_integration::AuditIntent::Routine,
        request_intent,
    );
    let audit = match admission {
        Admission::Bound => RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            envelope.profile,
            binding.expect("bound admission"),
            route_action(route),
            intent,
        ),
        Admission::Unresolved(action) => RequestAudit::unresolved(
            rss_mdm_audit_integration::Origin::Request,
            envelope.profile,
            action,
            rss_mdm_audit_integration::AuditIntent::Routine,
        ),
    };
    if protected {
        request
            .extensions_mut()
            .insert(AuthenticatedBody(envelope.buffered_bytes.clone()));
    }
    let id = audit.request_id();
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
        let remaining = total.remaining(envelope.clock.now()).unwrap_or_default();
        let operation =
            if audit.snapshot().intent == rss_mdm_audit_integration::AuditIntent::Routine {
                remaining
            } else {
                remaining - (remaining / 4).min(std::time::Duration::from_secs(2))
            };
        let mut response = match rss_axum::RequestBudget::new(operation) {
            Ok(budget) => rss_axum::request_control(State(budget), request, next).await,
            Err(_) => project(Error::RequestDeadline),
        };
        if response
            .extensions_mut()
            .remove::<DownstreamResponse>()
            .is_none()
        {
            response = project(Error::Unavailable(Failure::RequestDeadline));
        }
        response
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
        total,
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
    let total = cutoff(&request, &envelope);
    request.extensions_mut().insert(total);
    let audit = request
        .extensions()
        .get::<rss_transactional_messaging::fence::ExecutionBinding>()
        .map(|binding| {
            RequestAudit::new(
                rss_mdm_audit_integration::Origin::Request,
                envelope.profile,
                *binding,
                "authentication",
                rss_mdm_audit_integration::AuditIntent::Routine,
            )
        });
    let id = audit
        .as_ref()
        .map_or_else(uuid::Uuid::new_v4, RequestAudit::request_id);
    if let Some(audit) = &audit {
        request.extensions_mut().insert(audit.clone());
    }
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
        body(request, next, envelope.buffered_bytes).await
    };
    if let Some(audit) = &audit
        && response
            .extensions()
            .get::<crate::api_access::AdmissionRejected>()
            .is_some()
    {
        if let Some(replacement) = rss_mdm_audit_integration::completion::complete(
            &envelope.audit_store,
            audit,
            response.status().as_u16(),
            classify(response.extensions().get::<Error>()),
            total,
        )
        .await
        {
            response = project(match replacement {
                Replacement::CommitUnknown => Error::CommitUnknown,
                Replacement::RollbackFailed => Error::RollbackFailed,
                Replacement::Audit(e) => e.into(),
            });
        }
    } else if let Some(audit) = &audit {
        audit.finalize(None);
    }
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_request","request_id":id,"status":response.status().as_u16(),"latency_ms":envelope.clock.now().saturating_duration_since(started).as_millis()})
    );
    secure(response, id)
}
/// Product response decoration, preserving the response owner's cache contract.
pub fn secure(mut response: Response, id: uuid::Uuid) -> Response {
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id.to_string()).expect("UUID"),
    );
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
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
/// A pre-admission failure still has the product wire contract and server-owned diagnostics.
pub fn rejection(error: Error) -> Response {
    secure(project(error), uuid::Uuid::new_v4())
}
/// Describe exactly the response decorations on a product rejection.
pub fn rejection_contract(
    mut response: rss_mdm_http_contract::signature::Response,
) -> rss_mdm_http_contract::signature::Response {
    use rss_mdm_http_contract::signature::Schema;
    response
        .headers
        .insert("x-request-id".into(), Schema::response::<uuid::Uuid>());
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
    ] {
        let mut schema = Schema::response::<String>();
        schema.value["const"] = value.into();
        response.headers.insert(name.into(), schema);
    }
    response
}
pub(crate) fn rejections(_: &str, _: &str) -> Vec<rss_mdm_http_contract::signature::Response> {
    use rss_mdm_http_contract::signature::Output;
    let errors = [
        Error::Malformed,
        Error::Forbidden,
        Error::RequestTooLarge,
        Error::RequestDeadline,
        Error::CommitUnknown,
        Error::RollbackFailed,
        Error::Unavailable(Failure::AuditIntegrity),
        Error::Unavailable(Failure::AuditContract),
    ];
    let mut responses = errors
        .iter()
        .map(|error| rejection_contract(error.response_contract()))
        .collect::<Vec<_>>();
    let mut limited = <Error as Output>::responses()
        .into_iter()
        .find(|response| {
            response.body.as_ref().is_some_and(|body| {
                body.schema.value["properties"]["code"]["const"] == "request_limited"
            })
        })
        .expect("closed request limit code");
    let mut retry = rss_mdm_http_contract::signature::Schema::response::<String>();
    retry.value["const"] = "1".into();
    limited.headers.insert("retry-after".into(), retry);
    responses.push(rejection_contract(limited));
    responses
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
async fn body(request: Request, next: Next, bytes: Arc<tokio::sync::Semaphore>) -> Response {
    use crate::body_policy::BodyPolicy;
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str())
        .unwrap_or("");
    let policy = crate::body_policy::for_route(route, request.method());
    let limit = match policy {
        BodyPolicy::Streaming => return next.run(request).await,
        BodyPolicy::Buffered(limit) | BodyPolicy::Sdk(limit) => limit,
    };
    let normal = crate::body_limits().default_bytes();
    // Keep one default-size request available while a larger wire body is resident.
    // Two full-size requests compete for admission before either reads its first frame.
    let admission = if limit > normal {
        crate::BodyLimits::reservation(limit)
    } else {
        limit
    };
    let Ok(mut reservation) =
        bytes.try_acquire_many_owned(u32::try_from(admission).expect("compiled route admission"))
    else {
        let id = request
            .extensions()
            .get::<RequestAudit>()
            .map_or_else(uuid::Uuid::new_v4, RequestAudit::request_id);
        return limited(id);
    };
    if admission > limit {
        drop(
            reservation
                .split(normal)
                .expect("reserved small-request headroom"),
        );
    }
    if matches!(policy, BodyPolicy::Sdk(_)) {
        return next.run(request).await;
    }
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
        "/api/v1/tenants/{tenant}/devices/{device}/recovery-credentials/{id}/versions/{version}/secret"
        | "/api/v1/tenants/{tenant}/devices/{device}/device-access/materials/{id}/versions/{version}/secret" => {
            I::Sensitive(S::CredentialReveal)
        }
        "/api/v1/tenants/{tenant}/certificate-archive/export" => {
            I::Sensitive(S::CertificatePrivateExport)
        }
        "/api/v1/tenants/{tenant}/audit-events" => I::Sensitive(S::AuditHistoryRead),
        "/api/v1/tenants/{tenant}/resources/{id}/versions/{version}/script" => {
            I::Sensitive(S::ScriptContentRead)
        }
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
        "/api/v1/tenants/{tenant}/agent-connections"
        | "/api/v1/tenants/{tenant}/agent-connections/configuration" => "agent_connections_read",
        "/api/v1/tenants/{tenant}/agent-connections/publish" => "agent_connections_publish",
        "/api/v1/tenants/{tenant}/agent-connection-operations/{id}" => {
            "agent_connections_operation_read"
        }
        "/api/v1/tenants/{tenant}/agent-connections/devices"
        | "/api/v1/tenants/{tenant}/agent-connections/devices/{device}/observation" => {
            "agent_connections_devices_read"
        }
        "/api/v1/tenants/{tenant}/agent-issuances/{id}/recovery-operations/{operation}" => {
            "agent_certificate_recovery_read"
        }
        "/api/v1/tenants/{tenant}/device-associations" => "device_association_confirm",
        "/api/v1/tenants/{tenant}/device-associations/{id}/revoke" => "device_association_revoke",
        "/api/v1/tenants/{tenant}/device-associations/changes"
        | "/api/v1/tenants/{tenant}/device-associations/{id}"
        | "/api/v1/tenants/{tenant}/devices/{device}/association-candidates" => {
            "device_association_read"
        }
        "/api/v1/tenants/{tenant}/device-retirements/{id}" => "device_retirement_read",
        "/api/v1/tenants/{tenant}/device-retirements/{id}/force-revoke" => {
            "device_retirement_force_revoke"
        }
        "/api/v1/tenants/{tenant}/device-views/{kind}/{id}/asset-state" => "device_asset_state",
        "/api/v1/tenants/{tenant}/agent-requests/{id}/reenroll/{device}" => "agent_grant_authorize",
        "/api/v1/tenants/{tenant}/device-views"
        | "/api/v1/tenants/{tenant}/device-views/{kind}/{id}"
        | "/api/v1/tenants/{tenant}/device-views/{kind}/{id}/inventory-lists/{field}" => {
            "device_view_read"
        }
        "/api/v1/tenants/{tenant}/certificate-archive/vault/unlock" => "certificate_archive_unlock",
        "/api/v1/tenants/{tenant}/certificate-archive/vault/lock" => "certificate_archive_lock",
        "/api/v1/tenants/{tenant}/devices/{device}/timeline" => "timeline_read",
        "/api/v1/tenants/{tenant}/audit-events" => "audit_search",
        "/api/v1/tenants/{tenant}/runtime/diagnostics" => "runtime_diagnostics_read",
        "/api/v1/tenants/{tenant}/authorization"
        | "/api/v1/tenant-administration/authorization" => "authorization_effective_read",
        "/api/v1/tenants/{tenant}/authorization/rules"
        | "/api/v1/tenant-administration/authorization/rules" => "authorization_rules_read",
        "/api/v1/tenants/{tenant}/authorization/user-groups" => "authorization_groups_read",
        "/api/v1/tenants/{tenant}/authorization/user-groups/{id}/members" => {
            "authorization_members_read"
        }
        "/api/v1/tenants/{tenant}/authorization/departments" => "authorization_departments_read",
        "/api/v1/tenants/{tenant}/authorization/rules/{id}"
        | "/api/v1/tenants/{tenant}/authorization/user-groups/{id}"
        | "/api/v1/tenant-administration/authorization/rules/{id}" => "authorization_write",
        "/api/v1/tenants/{tenant}/enrollments" | "/api/v1/tenants/{tenant}/self-enrollments" => {
            "enrollment_create"
        }
        "/api/v1/tenants/{tenant}/self-enrollments/agent" => "agent_grant_create",
        "/api/v1/tenants/{tenant}/self-enrollments/agent/{id}/cancel" => "agent_grant_revoke",
        "/api/v1/tenants/{tenant}/registration-quotas/me"
        | "/api/v1/tenants/{tenant}/registration-quotas/users/{instance}/{principal}/usage" => {
            "registration_quota_read"
        }
        "/api/v1/tenants/{tenant}/registration-quotas/defaults"
        | "/api/v1/tenants/{tenant}/registration-quotas/users/{instance}/{principal}" => {
            "registration_quota_change"
        }
        "/api/v1/tenants/{tenant}/devices/{device}/registration-user" => "registration_user_change",
        "/api/v1/tenants/{tenant}/enrollments/{id}" => "enrollment_read",
        "/api/v1/tenants/{tenant}/devices/{device}/registration" => "registration_read",
        "/api/v1/tenants/{tenant}/enrollments/{id}/resume" => "enrollment_resume",
        "/api/v1/tenants/{tenant}/enrollments/{id}/cancel" => "enrollment_cancel",
        "/api/v1/tenants/{tenant}/devices/{device}/registration/revoke" => "credential_revoke",
        "/api/v1/tenants/{tenant}/devices/{id}/inventory" => "inventory_read",
        "/api/v1/tenants/{tenant}/devices/{id}/collections/{run}"
        | "/api/v1/tenants/{tenant}/devices/{id}/collections/{run}/fields/{field}/items" => {
            "collection_read"
        }
        "/api/v1/tenants/{tenant}/devices/{id}/actions" => "device_action",
        "/api/v1/tenants/{tenant}/devices/{device}/device-access/operations/{id}/offboarding/identity"
        | "/api/v1/tenants/{tenant}/devices/{device}/device-access/operations/{id}/offboarding/idp" => {
            "device_access_external_phase"
        }
        "/api/v1/tenants/{tenant}/webhooks/subscriptions/{id}/test"
        | "/api/v1/tenants/{tenant}/webhooks/deliveries/{id}/replay" => "webhook_write",
        "/api/v1/tenants/{tenant}/webhooks/deliveries/{id}/redrive" => "webhook_redrive",
        "/api/v1/tenants/{tenant}/agent-packages/save" => "software_installer_save",
        "/api/v1/tenants/{tenant}/devices/{device}/recovery-credentials/operations" => {
            "command_accept"
        }
        "/api/v1/tenants/{tenant}/devices/{device}/recovery-credentials/filevault/configuration" => {
            "filevault_collection_configure"
        }
        "/api/v1/tenants/{tenant}/devices/{device}/recovery-credentials/filevault/link" => {
            "filevault_custody_link"
        }
        _ => "protected_request",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recovery_identity_deadline_keeps_its_diagnostic() {
        let error = crate::Error::from(rss_mdm_recovery_credentials::Error::from(
            rss_mdm_authorization_service::Error::Deadline,
        ));
        assert!(matches!(
            super::classify(Some(&error)),
            Some(super::ResponseFailure::Deadline)
        ));
        use axum::response::IntoResponse;
        assert_eq!(
            error.into_response().status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn secure_preserves_the_private_content_cache_contract() {
        let response = axum::response::IntoResponse::into_response((
            [(axum::http::header::CACHE_CONTROL, "private, no-store")],
            "private content",
        ));
        let response = super::secure(response, uuid::Uuid::new_v4());
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "private, no-store"
        );
    }

    use super::*;
    #[test]
    fn pki_mutations_are_management_but_trust_queries_are_routine() {
        use rss_mdm_audit_integration::AuditIntent;
        let routes = crate::pki::routes();
        for mut endpoint in routes.endpoints().iter().cloned() {
            endpoint.path = format!("/api/v1/tenants/{{tenant}}{}", endpoint.path);
            let expected = match endpoint.method {
                "POST" => AuditIntent::Management,
                "GET" => AuditIntent::Routine,
                method => panic!("unexpected PKI method: {method}"),
            };
            assert_eq!(request_intent(&endpoint), expected, "{}", endpoint.path);
        }
    }
    fn assert_intents<S: Clone + Send + Sync + 'static>(
        router: Router<S, impl rss_mdm_http_contract::module::Declaration>,
        expected: &[(&str, &str, rss_mdm_audit_integration::AuditIntent)],
    ) {
        let mounted = {
            rss_mdm_http_contract::route_module! { struct AssertIntentsModule1 for [Browser] { api_v1 at "/api/v1/tenants/{tenant}" } }
            AssertIntentsModule1 { api_v1: router }.assemble()
        };
        for (path, method, intent) in expected {
            let endpoint = mounted
                .endpoints()
                .iter()
                .find(|e| e.path == *path && e.method == *method)
                .expect("real mounted endpoint");
            assert_eq!(request_intent(endpoint), *intent, "{method} {path}");
        }
    }
    #[test]
    fn action_mutations_and_preparation_queries_have_distinct_ingress_intents() {
        use rss_mdm_audit_integration::AuditIntent::{Management, Routine, Sensitive};
        assert_intents(
            crate::software_catalog::routes(),
            &[
                (
                    "/api/v1/tenants/{tenant}/agent-packages/save",
                    "POST",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/agent-packages/uploads",
                    "POST",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/agent-packages/uploads/{id}",
                    "POST",
                    Routine,
                ),
                (
                    "/api/v1/tenants/{tenant}/agent-packages/operations/{id}",
                    "GET",
                    Routine,
                ),
                (
                    "/api/v1/tenants/{tenant}/software/resources/{id}/versions/{version}/content",
                    "GET",
                    Routine,
                ),
            ],
        );
        assert_intents(
            crate::content::http::routes(),
            &[
                (
                    "/api/v1/tenants/{tenant}/resources/{id}/content",
                    "POST",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/resources/{id}/uploads/{upload}",
                    "POST",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/resources/{id}/uploads/{upload}",
                    "PATCH",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/resources/{id}/uploads/{upload}",
                    "GET",
                    Routine,
                ),
                (
                    "/api/v1/tenants/{tenant}/resources/{id}/versions/{version}/script",
                    "GET",
                    Sensitive(rss_mdm_audit_integration::SensitiveAction::ScriptContentRead),
                ),
            ],
        );
        assert_intents(
            crate::telemetry::routes(None),
            &[
                (
                    "/api/v1/tenants/{tenant}/telemetry/maintenance",
                    "POST",
                    Management,
                ),
                (
                    "/api/v1/tenants/{tenant}/telemetry/history",
                    "POST",
                    Routine,
                ),
                (
                    "/api/v1/tenants/{tenant}/telemetry/aggregate",
                    "POST",
                    Routine,
                ),
            ],
        );
    }
    #[test]
    fn route_templates_select_audit_actions() {
        assert_eq!(
            route_action("/api/v1/tenants/{tenant}/devices/{device}/registration"),
            "registration_read"
        );
        assert_eq!(
            route_action("/api/v1/tenants/{tenant}/devices/{device}/registration/revoke"),
            "credential_revoke"
        );
        assert_eq!(
            route_action("/api/v1/tenants/{tenant}/devices/{id}/collections/{run}"),
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
                504,
                "request_deadline",
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
                rss_mdm_audit_integration::Origin::Request,
                rss_mdm_install_support::StorageProfile::Mdm,
                rss_transactional_messaging::fence::ExecutionBinding::new(
                    rss_transactional_messaging::fence::StorageIdentity::new([1; 16], [2; 16])
                        .unwrap(),
                    rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
                        .unwrap(),
                    rss_transactional_messaging::fence::Epoch::new(1).unwrap(),
                ),
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
