//! The real HTTP boundary must withhold sensitive content when durable audit fails.
use crate::authority_t2_support::*;
use anyhow::Result;
use axum::{Extension, Json, extract::State};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_http_contract::{Operation, catalog, module::Route, routing::get};
use std::sync::Arc;
use tower::ServiceExt;

const CONTENT: &str = "foundation-sensitive-content";
async fn content(
    State(proof): State<Arc<AuthorizedPrincipal>>,
    Extension(audit): Extension<RequestAudit>,
) -> std::result::Result<Json<String>, rss_mdm_management_http::Error> {
    proof.bind_audit(&audit)?;
    proof.require(Permission::AuditRead, None)?;
    Ok(Json(CONTENT.into()))
}

#[allow(
    clippy::disallowed_methods,
    reason = "test composition supplies the production monotonic clock"
)]
#[tokio::test]
#[ignore = "T2: real HTTP projection and durable SQL audit"]
async fn sensitive_http_body_is_withheld_when_audit_cannot_commit() -> Result<()> {
    let context = Context::open("audit", &[]).await?;
    let account = context.account(&[Permission::AuditRead]).await?;
    let proof = Arc::new(context.authenticate(&account).await?);
    rss_mdm_http_contract::route_module! { struct AuditBoundaryProof for [Browser] { read } }
    let routes = AuditBoundaryProof {
        read: Route::new(
            "/api/v1/audit-events",
            get(content, &catalog::AUDIT, &[Operation::List]),
        ),
    }
    .assemble()
    .with_state(proof);
    let router = rss_mdm_management_http::boundary::wrap(
        routes,
        rss_mdm_management_http::boundary::Envelope {
            profile: rss_mdm_install_support::StorageProfile::Mdm,
            admission: Arc::new(tokio::sync::Semaphore::new(2)),
            host: "mdm.example.test".into(),
            clock: Arc::new(crate::Monotonic(std::time::Instant::now)),
            audit_store: context.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(2)),
            tenant: context.tenant.to_string(),
        },
    )
    .into_axum();
    let request = || {
        axum::http::Request::builder()
            .uri("/api/v1/audit-events")
            .header("host", "mdm.example.test")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(request()).await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let request_id = response.headers()["x-request-id"].to_str()?.to_owned();
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert_eq!(serde_json::from_slice::<String>(&body)?, CONTENT);
    assert_eq!(context.audit_count("mdm.request", &request_id).await?, 1);
    context.disable_audit().await?;
    let response = router.oneshot(request()).await?;
    assert!(response.status().is_server_error());
    let failed_request_id = response.headers()["x-request-id"].to_str()?.to_owned();
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8_lossy(&body).contains(CONTENT));
    assert_eq!(
        context
            .audit_count("mdm.request", &failed_request_id)
            .await?,
        0
    );
    context.close().await;
    Ok(())
}
