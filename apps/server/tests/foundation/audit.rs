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
            "/api/v1/tenants/{tenant}/audit-events",
            get(content, &catalog::AUDIT, &[Operation::List]),
        ),
    }
    .assemble()
    .with_state(proof);
    let router = rss_mdm_management_http::boundary::wrap(
        routes,
        rss_mdm_management_http::boundary::Envelope {
            request_timeout: std::time::Duration::from_secs(8),
            profile: rss_mdm_install_support::StorageProfile::Mdm,

            host: "mdm.example.test".into(),
            clock: Arc::new(crate::Monotonic(std::time::Instant::now)),
            audit_store: context.audit.clone(),
            buffered_bytes: Arc::new(tokio::sync::Semaphore::new(128 * 1024 * 1024)),
        },
    )
    .into_axum()
    .layer(Extension(context.execution()));
    let request = || {
        axum::http::Request::builder()
            .uri(format!("/api/v1/tenants/{}/audit-events", context.tenant))
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

#[tokio::test]
#[ignore = "T2: current large Audit records retain their full payload and selected pages enforce independent row/byte limits"]
async fn large_audit_records_and_complete_query_pages_share_current_capacity() -> Result<()> {
    use rss_mdm_audit_integration::{
        AuditIntent, AuditStore, Fact, Origin, budget::AuditBudget, operation::OperationOwner,
    };
    use rss_mdm_timeline_service::{Query, QueryBudget};
    use std::time::Duration;
    for ledger in [false, true] {
        let key = tempfile::NamedTempFile::new()?;
        std::fs::write(key.path(), [47; 32])?;
        let config = if ledger {
            crate::config::AuditConfig::Ledger {
                key_id: "capacity".into(),
                key_file: key.path().into(),
            }
        } else {
            crate::config::AuditConfig::Plain
        };
        let profile = if ledger {
            "audit_ledger"
        } else {
            "audit_plain"
        };
        let c = Context::open_with_audit(profile, &config).await?;
        let account = c.account(&[Permission::AuditRead]).await?;
        let proof = c.authenticate(&account).await?;
        let pool = c.inputs.pool(profile, "mdm_access").await?;
        let integrity = config.integrity()?;
        let budget = AuditBudget::new(Duration::from_secs(30));
        let store = Arc::new(
            AuditStore::new(
                pool.clone(),
                integrity,
                c.runtime.clone(),
                c.execution(),
                &budget.control(),
            )
            .await?,
        );
        let audit = RequestAudit::new(
            Origin::Background,
            rss_mdm_install_support::StorageProfile::Mdm,
            c.execution(),
            "capacity_read",
            AuditIntent::Management,
        );
        proof.bind_audit(&audit)?;
        let details = serde_json::json!({"evidence":"\\\"".repeat(24000)});
        let facts = (0..2)
            .map(|i| {
                Fact::business(
                    &audit,
                    OperationOwner::Resource,
                    &format!("capacity{i}{}", "x".repeat(246)),
                    200,
                    "success",
                    None,
                )?
                .with_details(details.clone())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let append = store
            .write(
                c.execution(),
                &budget.source_control(),
                (&store, &facts),
                |(store, facts), tx| {
                    Box::pin(async move {
                        for fact in *facts {
                            store.append(tx, fact).await?;
                        }
                        Ok::<_, rss_mdm_audit_integration::Error>(())
                    })
                },
            )
            .await;
        append.fold(
            Ok,
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
        )?;
        let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND event_id=ANY($2) ORDER BY event_id")
            .bind(c.tenant.to_string()).bind(facts.iter().map(|f| f.identity().event_id().as_str()).collect::<Vec<_>>()).fetch_all(&c.operator).await?;
        assert_eq!(stored.len(), 2);
        for bytes in stored {
            assert!(bytes.len() > 65536 && bytes.len() <= 128 * 1024);
            let decoded = rss_audit_core::decode_untrusted(&bytes)?;
            let payload: serde_json::Value =
                serde_json::from_slice(decoded.event().context().payload().as_bytes())?;
            assert_eq!(payload["details"], details);
        }
        let full = c.database.timeline(
            store.clone(),
            &[37; 32],
            QueryBudget::new(20, 8 * 1024 * 1024)?,
        )?;
        assert_eq!(
            full.query(
                &proof,
                "audit",
                &Query::parse("action=capacity_read", false)?
            )
            .await?
            .items
            .len(),
            2
        );
        assert!(matches!(
            full.query(&proof, "audit", &Query::parse("limit=50", false)?)
                .await,
            Err(rss_mdm_timeline_service::Error::BudgetExceeded)
        ));
        let one_document: i64 = sqlx::query_scalar("SELECT max(octet_length(document::text))::bigint FROM mdm_timeline.facts WHERE tenant_id=$1::uuid AND action='capacity_read'")
            .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
        let timeline = c.database.timeline(
            store.clone(),
            &[37; 32],
            QueryBudget::new(1024, u64::try_from(one_document)?)?,
        )?;
        let query = Query {
            action: Some("capacity_read".into()),
            limit: Some(1),
            ..Query::default()
        };
        let first = timeline.query(&proof, "audit", &query).await?;
        assert_eq!(first.items.len(), 1);
        assert!(first.next_cursor.is_some());
        assert!(matches!(
            timeline
                .query(
                    &proof,
                    "audit",
                    &Query {
                        limit: Some(2),
                        ..query
                    }
                )
                .await,
            Err(rss_mdm_timeline_service::Error::BudgetExceeded)
        ));
        let complete = c
            .database
            .timeline(
                store.clone(),
                &[37; 32],
                QueryBudget::new(1024, 8 * 1024 * 1024)?,
            )?
            .query(
                &proof,
                "audit",
                &Query {
                    action: Some("capacity_read".into()),
                    limit: Some(1024),
                    ..Query::default()
                },
            )
            .await?;
        assert_eq!(complete.items.len(), 2);
        assert!(complete.next_cursor.is_none());
        verify_full_identity_restore(&c, profile, &facts[0], &budget).await?;
        audit.finalize(None);
        drop(timeline);
        drop(store);
        pool.close().await;
        c.close().await;
    }
    Ok(())
}

// Backup consumes all installed audit sources, including sources with the public maximum identity.
// Product business fact IDs remain their stable hashes; this record exercises the read/restore seam.
#[expect(
    clippy::cognitive_complexity,
    reason = "one persisted source identity is decoded and verified by the real backup path in both integrity modes"
)]
async fn verify_full_identity_restore(
    c: &Context,
    profile: &str,
    fact: &rss_mdm_audit_integration::Fact,
    budget: &rss_mdm_audit_integration::budget::AuditBudget,
) -> Result<()> {
    use rss_audit_core::{AuditEventV1, EventId, RecordIdentity, SourceId, SourceIdentity};
    let at = rss_contract::Timepoint::try_from(1_700_000_000)?;
    let original = fact.event(at)?;
    let event = AuditEventV1::new(
        RecordIdentity::new(
            c.tenant,
            SourceIdentity::new(
                SourceId::parse(&"s".repeat(255))?,
                original.identity().source().contract().clone(),
            ),
            EventId::parse(&"e".repeat(255))?,
        ),
        rss_audit_core::EventFacts::new(
            rss_audit_core::ActorRef::new(
                original.facts().actor().kind().clone(),
                original.facts().actor().id().clone(),
            ),
            original.facts().action().clone(),
            rss_audit_core::ResourceRef::new(
                original.facts().resource().kind().clone(),
                original.facts().resource().id().clone(),
            ),
            original.facts().outcome(),
            original.facts().occurred_at(),
        ),
        rss_audit_core::EventContext::new(
            rss_audit_core::Coordinates::new(None, None, None),
            rss_audit_core::AuditPayload::new(original.context().payload().as_bytes().to_vec())?,
        ),
    );
    let prepared = rss_audit_core::prepare(event, at)?;
    assert_eq!(prepared.append_request()?.record_id().as_str().len(), 514);
    let expected = prepared.canonical_bytes().to_vec();
    let integrity = c.audit.integrity().clone();
    c.runtime
        .local_tx_with_context(
            c.execution(),
            deadline(),
            (&integrity, &prepared),
            |(integrity, prepared), tx| {
                Box::pin(async move {
                    rss_mdm_audit_integration::budget::identity_write_budget(1)?
                        .append_in(tx, integrity, prepared)
                        .await
                        .map_err(Into::into)
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
            |e| Err(anyhow::anyhow!("{e:?}")),
        )?;
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3")
        .bind(c.tenant.to_string()).bind("s".repeat(255)).bind("e".repeat(255)).fetch_one(&c.operator).await?;
    assert_eq!(bytes, expected);
    let restored = rss_audit_core::PreparedAuditV1::from_canonical_bytes(&bytes)?;
    assert_eq!(restored.identity().tenant(), c.tenant);
    assert_eq!(
        restored.identity().source().source_id().as_str(),
        "s".repeat(255)
    );
    assert_eq!(restored.identity().event_id().as_str(), "e".repeat(255));
    let key_id = if c.audit.uses_ledger() {
        Some("capacity")
    } else {
        None
    };
    let tenants = [c.tenant.to_string()];
    let options = c.inputs.options(profile, "postgres")?;
    let heads = rss_mdm_audit_integration::backup::verify_operator(
        rss_mdm_install_support::StorageProfile::Mdm,
        integrity.clone(),
        key_id,
        &tenants,
        &options,
        budget,
        rss_ledger_postgres::ReadLimit::new(1, 4 * 1024 * 1024)?,
    )
    .await?;
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].tenant, c.tenant.to_string());
    if c.audit.uses_ledger() {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
                .bind(c.tenant.to_string())
                .fetch_one(&c.operator)
                .await?;
        assert!(count >= 3);
        assert_eq!(heads[0].verified_records, Some(u64::try_from(count)?));
    } else {
        assert!(heads[0].verified_records.is_none());
    }
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let cancelled = rss_mdm_audit_integration::budget::AuditBudget::with_cancellation(
        std::time::Duration::from_secs(30),
        cancel,
    );
    assert!(
        rss_mdm_audit_integration::backup::verify_operator(
            rss_mdm_install_support::StorageProfile::Mdm,
            integrity,
            key_id,
            &tenants,
            &options,
            &cancelled,
            rss_ledger_postgres::ReadLimit::new(1024, 4 * 1024 * 1024)?,
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "T2: actual request budget preserves audited unknown outcomes and completed downstream responses"]
async fn request_timeout_is_projected_after_audit_settlement() -> Result<()> {
    use axum::response::IntoResponse;
    use std::time::Duration;
    async fn slow(
        Extension(audit): Extension<RequestAudit>,
        axum::extract::Path(mode): axum::extract::Path<String>,
    ) -> Json<String> {
        audit.identify_service("budget-proof");
        if mode == "commit" {
            audit.mark_commit_started();
        }
        std::future::pending::<Json<String>>().await
    }
    struct Settled;
    impl rss_mdm_http_contract::signature::Output for Settled {
        fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
            vec![rss_mdm_http_contract::signature::Response::json::<String>(
                503,
            )]
        }
    }
    impl IntoResponse for Settled {
        fn into_response(self) -> axum::response::Response {
            let mut response = (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"code":"downstream"})),
            )
                .into_response();
            response.headers_mut().insert(
                "set-cookie",
                "settled=credential; Secure; HttpOnly".parse().unwrap(),
            );
            response
        }
    }
    async fn settled() -> Settled {
        Settled
    }
    let c = Context::open("audit_plain", &[]).await?;
    rss_mdm_http_contract::route_module! { struct BudgetProof for [Browser] { slow, settled } }
    let routes = BudgetProof {
        slow: Route::new(
            "/budget/{mode}",
            get(slow, &catalog::AUDIT, &[Operation::List]),
        ),
        settled: Route::new(
            "/settled",
            get(settled, &catalog::AUDIT, &[Operation::List]),
        ),
    }
    .assemble();
    let router = rss_mdm_management_http::boundary::wrap(
        routes,
        rss_mdm_management_http::boundary::Envelope {
            request_timeout: Duration::from_millis(30),
            profile: rss_mdm_install_support::StorageProfile::Mdm,

            host: "mdm.example.test".into(),
            clock: crate::clock::monotonic(),
            audit_store: c.audit.clone(),
            buffered_bytes: Arc::new(tokio::sync::Semaphore::new(128 * 1024 * 1024)),
        },
    )
    .into_axum()
    .layer(Extension(c.execution()));
    for (path, expected) in [
        ("/budget/read", "request_deadline"),
        ("/budget/commit", "operation_unknown"),
        ("/settled", "downstream"),
    ] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .header("host", "mdm.example.test")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(
            response.status(),
            if path == "/budget/read" { 504 } else { 503 }
        );
        uuid::Uuid::parse_str(response.headers()["x-request-id"].to_str()?)?;
        assert_eq!(response.headers()["cache-control"], "no-store");
        if path == "/settled" {
            assert_eq!(
                response.headers()["set-cookie"],
                "settled=credential; Secure; HttpOnly"
            );
        }
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body, serde_json::json!({"code":expected}));
    }
    c.close().await;
    Ok(())
}
