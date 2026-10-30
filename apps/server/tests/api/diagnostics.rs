use super::*;
use axum::http::{Request, StatusCode, header};
use rss_mdm_management_http::Failure;
use rss_mdm_management_http::boundary::{Envelope, wrap};
use serde_json::json;
#[tokio::test]
#[ignore = "make t2 MODULE=api.diagnostics: admission and real management Audit failure"]
async fn management_audit_failure_logs_preserve_action_and_redaction() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    const CHILD: &str = "MDM_AUDIT_LOG_TEST";
    if std::env::var_os(CHILD).is_some() {
        let (pool, runtime, audit_store) =
            crate::audit_test_support::request_store().await.unwrap();
        runtime.close().await;
        pool.close().await;
        let admission = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let handler = entered.clone();
        let router = {
            rss_mdm_http_contract::route_module! { struct ManagementAuditFailureLogsPreserveActionAndRedactionModule1 for [Browser] { get_move } }
            ManagementAuditFailureLogsPreserveActionAndRedactionModule1 {
                get_move: rss_mdm_http_contract::module::Route::new(
                    "/api/v1/devices/{id}/inventory",
                    get(
                        move |axum::Extension(audit): axum::Extension<
                            rss_mdm_audit_integration::RequestAudit,
                        >| {
                            let handler = handler.clone();
                            async move {
                                audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
                                    rss_mdm_audit_integration::SensitiveAction::InventoryBulkExport,
                                ));
                                handler.fetch_add(1, Ordering::SeqCst);
                                Json(json!({"sensitive":"inventory-result"}))
                            }
                        },
                        &contracts::PROTOCOL_MANAGEMENT_HTTP,
                        &[RouteOperation::Action],
                    ),
                ),
            }
            .assemble()
        };
        let router = wrap(
            router,
            Envelope {
                admission: admission.clone(),
                host: "mdm.example.test".into(),
                clock: monotonic(),
                audit_store,
                requests: Arc::new(tokio::sync::Semaphore::new(4)),
                tenant: crate::test_support::case::tenant().into(),
            },
        );
        let request = || {
            Request::builder()
                .uri("/api/v1/devices/sensitive-target/inventory")
                .header("host", "mdm.example.test")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let limited = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()[header::RETRY_AFTER], "1");
        assert!(uuid::Uuid::parse_str(limited.headers()["x-request-id"].to_str().unwrap()).is_ok());
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        admission.add_permits(1);
        let response = router.oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(entered.load(Ordering::SeqCst), 1);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "assembly::http::tests::management_audit_failure_logs_preserve_action_and_redaction",
            "--ignored",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<Value> = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "audit_failure")
        .collect();
    assert_eq!(events.len(), 1, "{stderr}");
    assert_eq!(events[0]["reason"], "persistent_audit_unavailable");
    assert_eq!(events[0]["action"], "inventory_read");
    assert!(!stderr.contains("sensitive-target"));
    assert!(!stderr.contains("inventory-result"));
}
#[allow(
    clippy::disallowed_methods,
    reason = "test fixture selects the monotonic provider outside request handling"
)]
fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}

#[derive(Clone, Copy, Debug)]
enum DeviceProtocol {
    Agent,
    Windows,
    Apple,
}
impl DeviceProtocol {
    fn resource(self) -> &'static rss_mdm_http_contract::Resource {
        match self {
            Self::Agent => &contracts::PROTOCOL_AGENT_CHANNEL,
            Self::Windows => &contracts::PROTOCOL_WINDOWS_CHANNEL,
            Self::Apple => &contracts::PROTOCOL_APPLE_CHANNEL,
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Agent => "/reports",
            Self::Windows => "/EnrollmentServer/Enrollment.svc",
            Self::Apple => "/mdm",
        }
    }
    fn success(self) -> axum::response::Response {
        match self {
            Self::Agent => Json(json!({"sensitive":"device-result"})).into_response(),
            Self::Windows => ([(header::CONTENT_TYPE, "application/soap+xml")],
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>sensitive-device-result</s:Body></s:Envelope>").into_response(),
            Self::Apple => ([(header::CONTENT_TYPE, "application/xml")],
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CommandUUID</key><string>sensitive-device-result</string></dict></plist>").into_response(),
        }
    }
    fn wrap<M: rss_mdm_http_contract::module::Declaration>(
        self,
        router: Router<(), M>,
        store: Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Router<(), M> {
        macro_rules! wrap {
            ($channel:ident) => {
                $channel::boundary::wrap(
                    router,
                    $channel::boundary::Envelope {
                        admission: Arc::new(tokio::sync::Semaphore::new(4)),
                        host: "mdm.example.test".into(),
                        clock: monotonic(),
                        audit_store: store,
                        requests: Arc::new(tokio::sync::Semaphore::new(4)),
                        tenant: crate::test_support::case::tenant().into(),
                    },
                )
            };
        }
        let owner = crate::test_support::runtime::NativeRequests::new();
        let router = match self {
            Self::Agent => wrap!(rss_mdm_agent_channel),
            Self::Windows => wrap!(rss_mdm_windows_channel),
            Self::Apple => wrap!(rss_mdm_apple_channel),
        };
        router
            .layer(axum::Extension(owner.gate.clone()))
            .layer(axum::Extension(owner))
    }
    fn category(self, response: &axum::response::Response) -> &'static str {
        match self {
            DeviceProtocol::Agent => {
                match response.extensions().get::<rss_mdm_agent_channel::Error>() {
                    Some(rss_mdm_agent_channel::Error::CommitUnknown) => "operation_unknown",
                    Some(rss_mdm_agent_channel::Error::RollbackFailed) => {
                        "operation_rollback_unconfirmed"
                    }
                    Some(rss_mdm_agent_channel::Error::Unavailable(
                        rss_mdm_agent_channel::Failure::Audit,
                    )) => "service_unavailable",
                    other => panic!("{self:?}: unexpected {other:?}"),
                }
            }
            DeviceProtocol::Windows => match response
                .extensions()
                .get::<rss_mdm_windows_channel::Error>()
            {
                Some(rss_mdm_windows_channel::Error::CommitUnknown) => "operation_unknown",
                Some(rss_mdm_windows_channel::Error::RollbackFailed) => {
                    "operation_rollback_unconfirmed"
                }
                Some(rss_mdm_windows_channel::Error::Unavailable(
                    rss_mdm_windows_channel::Failure::Audit,
                )) => "service_unavailable",
                other => panic!("{self:?}: unexpected {other:?}"),
            },
            DeviceProtocol::Apple => {
                match response.extensions().get::<rss_mdm_apple_channel::Error>() {
                    Some(rss_mdm_apple_channel::Error::CommitUnknown) => "operation_unknown",
                    Some(rss_mdm_apple_channel::Error::RollbackFailed) => {
                        "operation_rollback_unconfirmed"
                    }
                    Some(rss_mdm_apple_channel::Error::Unavailable(
                        rss_mdm_apple_channel::Failure::Audit,
                    )) => "service_unavailable",
                    other => panic!("{self:?}: unexpected {other:?}"),
                }
            }
        }
    }
    async fn assert_wire(
        self,
        response: axum::response::Response,
        expected: &str,
    ) -> anyhow::Result<()> {
        let status = response.status();
        let content_type = response.headers()[header::CONTENT_TYPE]
            .to_str()?
            .to_owned();
        let bytes = axum::body::to_bytes(response.into_body(), 16384).await?;
        assert!(!String::from_utf8_lossy(&bytes).contains("sensitive-device-result"));
        match self {
            DeviceProtocol::Windows => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert!(content_type.starts_with("application/soap+xml"));
                let soap = String::from_utf8(bytes.to_vec())?;
                assert!(soap.contains(":Fault>") && soap.contains("EnrollmentServer"));
            }
            DeviceProtocol::Agent | DeviceProtocol::Apple => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(content_type, "application/json");
                let code = if matches!(self, DeviceProtocol::Agent)
                    && expected == "operation_rollback_unconfirmed"
                {
                    "operation_unknown"
                } else {
                    expected
                };
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes)?,
                    json!({"code": code})
                );
            }
        }
        Ok(())
    }
    fn original(self, error: rss_mdm_management_http::Error) -> axum::response::Response {
        macro_rules! project {
            ($owner:ident) => {{
                let error = match error {
                    rss_mdm_management_http::Error::CommitUnknown => $owner::Error::CommitUnknown,
                    rss_mdm_management_http::Error::RollbackFailed => $owner::Error::RollbackFailed,
                    rss_mdm_management_http::Error::Conflict => $owner::Error::Conflict,
                    rss_mdm_management_http::Error::Unavailable(Failure::RequestDeadline) => {
                        $owner::Error::Unavailable($owner::Failure::RequestDeadline)
                    }
                    _ => panic!("unexpected fixture error"),
                };
                error.into_response()
            }};
        }
        match self {
            Self::Agent => project!(rss_mdm_agent_channel),
            Self::Windows => project!(rss_mdm_windows_channel),
            Self::Apple => project!(rss_mdm_apple_channel),
        }
    }
}

async fn failed_device_settlement(protocol: DeviceProtocol) -> anyhow::Result<()> {
    use rss_mdm_audit_integration::{RequestAudit, WriteOutcome as W};
    use rss_mdm_management_http::Error as E;
    use tower::ServiceExt;
    let (pool, runtime, store) = crate::audit_test_support::request_store().await?;
    let request = || {
        Request::builder()
            .uri(protocol.path())
            .header(header::HOST, "mdm.example.test")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    // Establish that this real admitted store can settle the same ingress before failure.
    let healthy = protocol
        .wrap(
            {
 rss_mdm_http_contract::route_module! { struct FailedDeviceSettlementModule1 for [Browser] { get_move } }
 FailedDeviceSettlementModule1 { get_move: rss_mdm_http_contract::module::Route::new(protocol.path(), get(
                    move || async move { DiagnosticResponse(protocol.success()) },
                    protocol.resource(),
                    &[RouteOperation::Action],
                )) }.assemble()
},
            store.clone(),
        )
        .oneshot(request())
        .await?;
    assert_eq!(healthy.status(), StatusCode::OK);
    runtime.close().await;
    pool.close().await;
    let operation = uuid::Uuid::new_v4();
    for (outcome, original, expected) in [
        (W::CommitNotStarted, None, "service_unavailable"),
        (
            W::Unknown,
            Some(E::Unavailable(Failure::RequestDeadline)),
            "operation_unknown",
        ),
        (
            W::RollbackFailed,
            Some(E::Conflict),
            "operation_rollback_unconfirmed",
        ),
        (
            W::CommitNotStarted,
            Some(E::CommitUnknown),
            "operation_unknown",
        ),
        (
            W::CommitNotStarted,
            Some(E::RollbackFailed),
            "operation_rollback_unconfirmed",
        ),
    ] {
        let router = {
            rss_mdm_http_contract::route_module! { struct FailedDeviceSettlementModule2 for [Browser] { get_move } }
            FailedDeviceSettlementModule2 {
                get_move: rss_mdm_http_contract::module::Route::new(
                    protocol.path(),
                    get(
                        move |axum::Extension(audit): axum::Extension<RequestAudit>| {
                            let original = original.clone();
                            async move {
                                audit.operation(
                                    operation,
                                    "protected_request",
                                    rss_mdm_audit_integration::AuditIntent::Management,
                                );
                                audit.require_final_request();
                                match outcome {
                                    W::Committed => {
                                        audit.mark_commit_started();
                                        audit.mark_committed();
                                    }
                                    W::Unknown => audit.mark_commit_started(),
                                    W::RolledBack => audit.mark_rolled_back(),
                                    W::RollbackFailed => audit.mark_rollback_failed(),
                                    W::CommitNotStarted => (),
                                }
                                DiagnosticResponse(original.map_or_else(
                                    || protocol.success(),
                                    |error| protocol.original(error),
                                ))
                            }
                        },
                        protocol.resource(),
                        &[RouteOperation::Action],
                    ),
                ),
            }
            .assemble()
        };
        let response = protocol
            .wrap(router, store.clone())
            .oneshot(request())
            .await?;
        assert_eq!(response.headers()["idempotency-key"], operation.to_string());
        assert!(uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str()?).is_ok());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        // The protocol adapter must retain the closed uncertainty category, even
        // where the wire protocol deliberately collapses both failures.
        let category = protocol.category(&response);
        assert_eq!(category, expected, "{protocol:?} {outcome:?}");
        protocol.assert_wire(response, expected).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=api.diagnostics: real Audit pool failure at Agent response settlement"]
async fn agent_audit_settlement_preserves_wire_and_uncertainty() -> anyhow::Result<()> {
    failed_device_settlement(DeviceProtocol::Agent).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=api.diagnostics: real Audit pool failure at Windows SOAP settlement"]
async fn windows_audit_settlement_preserves_wire_and_uncertainty() -> anyhow::Result<()> {
    failed_device_settlement(DeviceProtocol::Windows).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=api.diagnostics: real Audit pool failure before Apple plist delivery"]
async fn apple_audit_settlement_preserves_wire_and_uncertainty() -> anyhow::Result<()> {
    failed_device_settlement(DeviceProtocol::Apple).await
}

// Only the failure-injection fixture can produce these synthetic protocol replies.
// Production handlers retain their own typed success and error owners.
struct DiagnosticResponse(axum::response::Response);
impl axum::response::IntoResponse for DiagnosticResponse {
    fn into_response(self) -> axum::response::Response {
        self.0
    }
}
impl rss_mdm_http_contract::signature::Output for DiagnosticResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::Response;
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Sensitive {
            sensitive: String,
        }
        let mut result = vec![Response::json::<Sensitive>(200)];
        for content_type in ["application/soap+xml", "application/xml"] {
            let mut response = Response::text(200);
            response.body.as_mut().unwrap().content_type = content_type;
            result.push(response);
        }
        result.extend(rss_mdm_agent_channel::Error::responses());
        result.extend(rss_mdm_windows_channel::Error::responses());
        result.extend(rss_mdm_apple_channel::Error::responses());
        result
    }
}

#[test]
fn application_administration_routes_keep_original_authentication_boundaries() {
    let document = http_contract_document().expect("complete application route contract");
    let endpoints = document["endpoints"]
        .as_array()
        .expect("endpoint descriptions");
    for (method, path, alternatives) in [
        ("GET", "/api/v1/user-attribute-definitions", 3),
        ("GET", "/api/v1/settings/catalog", 3),
        ("PUT", "/api/v1/settings/first-use", 3),
        ("GET", "/api/v1/tenant-administration/settings/catalog", 1),
    ] {
        let matches = endpoints
            .iter()
            .filter(|endpoint| endpoint["method"] == method && endpoint["path"] == path)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "each application endpoint has exactly one canonical registration: {method} {path}"
        );
        assert_eq!(
            matches[0]["authentication"]["alternatives"]
                .as_array()
                .expect("protected endpoint")
                .len(),
            alternatives,
            "{path}"
        );
        if method == "PUT" {
            assert_eq!(
                matches[0]["authentication"]["alternatives"][0]["required_headers"],
                json!(["cookie", "origin", "x-identity-request", "x-csrf-token"])
            );
        }
    }
}
