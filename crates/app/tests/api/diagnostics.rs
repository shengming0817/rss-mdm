use super::*;
use axum::http::{Request, StatusCode, header};
use rss_mdm_flow_service::Failure;
use rss_mdm_management_http::{
    Error,
    boundary::{Envelope, admit as envelope},
};
#[tokio::test]
#[ignore = "make t2: close an admitted Audit pool before protected response settlement"]
async fn audit_failure_logs_preserve_action_and_origin() {
    use tower::ServiceExt;
    const CHILD: &str = "MDM_AUDIT_LOG_TEST";
    if let Ok(mode) = std::env::var(CHILD) {
        let (pool, audit_store) = crate::audit_test_support::request_store().await.unwrap();
        pool.close().await;
        let router = Router::new()
            .route(
                "/api/v2/devices/{id}/inventory",
                get(move || async move {
                    if mode == "transaction" {
                        Error(rss_mdm_flow_service::Error::Unavailable(Failure::Audit))
                            .into_response()
                    } else {
                        Json(json!({"sensitive":"inventory-result"})).into_response()
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(
                Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(32)),
                    host: "mdm.example.test".into(),
                    clock: monotonic(),
                    audit_store,
                    requests: Arc::new(tokio::sync::Semaphore::new(4)),
                    tenant: crate::test_support::case::tenant().into(),
                },
                envelope,
            ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v2/devices/sensitive-target/inventory")
                    .header("host", "mdm.example.test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        return;
    }
    for mode in ["read", "transaction"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "api::tests::audit_failure_logs_preserve_action_and_origin",
                "--ignored",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, mode)
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
        assert_eq!(events.len(), 1, "{mode}: {stderr}");
        assert_eq!(events[0]["reason"], "persistent_audit_unavailable");
        assert_eq!(events[0]["action"], "inventory_read");
        assert!(!stderr.contains("sensitive-target"));
        assert!(!stderr.contains("inventory-result"));
    }
}
#[allow(
    clippy::disallowed_methods,
    reason = "test fixture selects the monotonic provider outside request handling"
)]
fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}
#[tokio::test]
#[ignore = "make t2: production envelope has an admitted Audit capability"]
async fn request_diagnostics_keep_causes_internal_and_issue_request_ids() {
    use tower::ServiceExt;
    let (pool, audit_store) = crate::audit_test_support::request_store().await.unwrap();
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
        let router = Router::new()
            .route(
                "/livez",
                get(move || async move { Error(rss_mdm_flow_service::Error::Unavailable(reason)) }),
            )
            .layer(middleware::from_fn_with_state(
                Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(32)),
                    host: "mdm.example.test".to_owned(),
                    clock: monotonic(),
                    audit_store: audit_store.clone(),
                    requests: Arc::new(tokio::sync::Semaphore::new(4)),
                    tenant: crate::test_support::case::tenant().into(),
                },
                envelope,
            ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/livez")
                    .header("host", "mdm.example.test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).is_ok()
        );
        assert!(matches!(
            response.extensions().get::<Error>(),
            Some(Error(rss_mdm_flow_service::Error::Unavailable(_)))
        ));
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"code":"service_unavailable"})
        );
    }
    pool.close().await;
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler = entered.clone();
    let router = Router::new()
        .route(
            "/api/protected",
            get(move || {
                let handler = handler.clone();
                async move {
                    handler.store(true, std::sync::atomic::Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            Envelope {
                admission: Arc::new(tokio::sync::Semaphore::new(0)),
                host: "mdm.example.test".into(),
                clock: monotonic(),
                audit_store,
                requests: Arc::new(tokio::sync::Semaphore::new(4)),
                tenant: crate::test_support::case::tenant().into(),
            },
            envelope,
        ));
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/protected")
                .header("host", "mdm.example.test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
}

#[derive(Clone, Copy, Debug)]
enum DeviceProtocol {
    Agent,
    Windows,
    Apple,
}
impl DeviceProtocol {
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
    fn wrap(self, router: Router, store: Arc<rss_mdm_audit_integration::AuditStore>) -> Router {
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
        match self {
            Self::Agent => wrap!(rss_mdm_agent_channel),
            Self::Windows => wrap!(rss_mdm_windows_channel),
            Self::Apple => wrap!(rss_mdm_apple_channel),
        }
    }
    fn category(self, response: &axum::response::Response) -> &'static str {
        use rss_mdm_flow_service::Error as E;
        match self {
            DeviceProtocol::Agent => match response.extensions().get::<E>() {
                Some(E::CommitUnknown) => "operation_unknown",
                Some(E::RollbackFailed) => "operation_rollback_unconfirmed",
                Some(E::Unavailable(Failure::Audit)) => "service_unavailable",
                other => panic!("{self:?}: unexpected {other:?}"),
            },
            DeviceProtocol::Windows => match response
                .extensions()
                .get::<rss_mdm_windows_channel::Error>()
            {
                Some(rss_mdm_windows_channel::Error::CommitUnknown) => "operation_unknown",
                Some(rss_mdm_windows_channel::Error::RollbackFailed) => {
                    "operation_rollback_unconfirmed"
                }
                Some(rss_mdm_windows_channel::Error::Service(E::Unavailable(Failure::Audit))) => {
                    "service_unavailable"
                }
                other => panic!("{self:?}: unexpected {other:?}"),
            },
            DeviceProtocol::Apple => {
                match response.extensions().get::<rss_mdm_apple_channel::Error>() {
                    Some(rss_mdm_apple_channel::Error::CommitUnknown) => "operation_unknown",
                    Some(rss_mdm_apple_channel::Error::RollbackFailed) => {
                        "operation_rollback_unconfirmed"
                    }
                    Some(rss_mdm_apple_channel::Error::Service(E::Unavailable(Failure::Audit))) => {
                        "service_unavailable"
                    }
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
    fn original(self, error: rss_mdm_flow_service::Error) -> axum::response::Response {
        match self {
            Self::Agent => {
                // Feed the service result into the real Agent boundary, without exposing
                // its handler-only error wrapper to an external consumer.
                let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
                response.extensions_mut().insert(error);
                response
            }
            Self::Windows => rss_mdm_windows_channel::Error::from(error).into_response(),
            Self::Apple => rss_mdm_apple_channel::Error::from(error).into_response(),
        }
    }
}

async fn failed_device_settlement(protocol: DeviceProtocol) -> anyhow::Result<()> {
    use rss_mdm_audit_integration::{RequestAudit, WriteOutcome as W};
    use rss_mdm_flow_service::Error as E;
    use tower::ServiceExt;
    let (pool, store) = crate::audit_test_support::request_store().await?;
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
            Router::new().route(
                protocol.path(),
                get(move || async move { protocol.success() }),
            ),
            store.clone(),
        )
        .oneshot(request())
        .await?;
    assert_eq!(healthy.status(), StatusCode::OK);
    pool.close().await;
    let operation = uuid::Uuid::new_v4();
    for (outcome, original, expected) in [
        (W::CommitNotStarted, None, "service_unavailable"),
        (W::RolledBack, Some(E::Conflict), "service_unavailable"),
        (W::Committed, None, "operation_unknown"),
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
        let router = Router::new().route(
            protocol.path(),
            get(
                move |axum::Extension(audit): axum::Extension<RequestAudit>| {
                    let original = original.clone();
                    async move {
                        audit.operation(operation, "protected_request");
                        audit.require_request_settlement();
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
                        original
                            .map_or_else(|| protocol.success(), |error| protocol.original(error))
                    }
                },
            ),
        );
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
