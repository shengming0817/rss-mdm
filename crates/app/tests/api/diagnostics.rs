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
