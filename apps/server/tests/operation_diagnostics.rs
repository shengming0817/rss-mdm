//! Original owner reads through real HTTP authentication, independently of the audit index.
use crate::authority_t2_support::{Context, deadline};
use anyhow::Result;
use rss_mdm_authorization_service::{self as access, Change, Permission, Rule, Scope, Subject};
use rss_mdm_management_http::operation_diagnostics::Services;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;
#[path = "operation_diagnostics/installation.rs"]
mod installation;
#[path = "operation_diagnostics/receipts.rs"]
mod receipts;

/// Exercise the actual product composition, including its real owner pools and HTTP authority.
#[tokio::test]
#[ignore = "T2: production App diagnostics, original receipt namespaces and evidence continuation"]
#[allow(clippy::disallowed_methods, reason = "real host monotonic clock")]
async fn product_http_uses_original_owner_namespaces_and_consumable_cursors() -> Result<()> {
    use serde_json::{Value, json};
    let c = Context::open("shared", &[]).await?;
    let manager = c
        .account(&[
            Permission::PolicyRead,
            Permission::RegistrationConfigurationRead,
            Permission::SecurityOperate,
            Permission::EnterpriseApplicationsRead,
            Permission::AccountWrite,
            Permission::ResourceRead,
            Permission::ScopeRead,
            Permission::GroupRead,
            Permission::InventorySensitiveRead,
            Permission::InventoryRead,
            Permission::InventoryFieldsWrite,
            Permission::ReleaseRead,
            Permission::ComplianceRuleRead,
            Permission::AgentEnrollmentRead,
            Permission::Credentials,
            Permission::CertificateArchiveRead,
            Permission::WebhookRead,
            Permission::AuditRead,
            Permission::OperationRead,
        ])
        .await?;
    let proof = c.authenticate(&manager).await?;
    let operation = Uuid::new_v4();
    let cases = receipts::seed(&c, &proof, operation).await?;
    let instance = Uuid::new_v4();
    let foreign_operation = Uuid::new_v4();
    receipts::actor_receipts(&c, &proof, foreign_operation, instance).await?;
    // Request retries are independently settled; the original response remains one durable row.
    for _ in 0..55 {
        let attempt = c.request(&proof)?;
        attempt.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Resource,
            operation,
            "resource_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        attempt.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        c.audit
            .settle_request(&attempt, 200, "success", &budget.source_control())
            .await?;
        attempt.finalize(None);
    }
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let config = crate::host_t2_support::configuration(
        &c.inputs,
        "shared",
        c.tenant,
        address,
        Uuid::new_v4(),
    )?;
    let config = serde_json::from_value(config)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()?;
    let access::credential::RequestCredential::Cookie(cookie) = manager.credential()? else {
        anyhow::bail!("cookie required")
    };
    let cookie = format!("__Host-identity-session={}", cookie.expose());
    let send = |path: String| {
        let request = client
            .get(format!("http://{address}{path}"))
            .header("host", "mdm.example.test")
            .header("x-rss-public-origin", "https://mdm.example.test")
            .header("x-forwarded-for", "127.0.0.1")
            .header("cookie", &cookie);
        async move {
            let response = request.send().await?;
            let status = response.status();
            Ok::<_, anyhow::Error>((status, response.json::<Value>().await?))
        }
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    drop(reservation);
    let server = crate::serve(
        config,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    );
    tokio::pin!(server);
    let exercise = async {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if send("/readyz".into()).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?;
        for (owner, case_id, query, expected) in &cases {
            let path = format!("/api/v1/operation-diagnostics/operations/{owner}/{case_id}{query}");
            let (status, body) = send(path).await?;
            assert_eq!(status, 200, "{owner}: {body}");
            assert_eq!(body["operation"]["owner"], *owner);
            assert_eq!(
                body["originalResult"]["availability"], "available",
                "{owner}: {body}"
            );
            for (key, value) in expected.as_object().unwrap() {
                assert_eq!(
                    &body["originalResult"]["value"][key], value,
                    "{owner}.{key}"
                );
            }
            assert_eq!(body["auditEvidence"]["availability"], "not_requested");
        }
        let damaged = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_assets.group_operations(tenant_id,id,actor,instance,fingerprint,response) VALUES($1::uuid,$2,$3,$4::uuid,$5,'{\"damaged\":true}')")
            .bind(c.tenant.to_string()).bind(damaged).bind(proof.principal_id()).bind(proof.instance_id()).bind(vec![17_u8;32]).execute(&c.operator).await?;
        let (status, value) = send(format!(
            "/api/v1/operation-diagnostics/operations/group/{damaged}?includeAudit=true"
        ))
        .await?;
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["originalResult"]["availability"], "unavailable");
        assert_eq!(value["auditEvidence"]["availability"], "available");
        let (status, value) = send(format!(
            "/api/v1/operation-diagnostics/operations/certificate_archive/{}?includeAudit=true",
            Uuid::new_v4()
        ))
        .await?;
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["originalResult"]["availability"], "not_found");
        assert_eq!(value["auditEvidence"]["availability"], "available");
        for owner in receipts::ACTOR_OWNERS {
            let path =
                format!("/api/v1/operation-diagnostics/operations/{owner}/{foreign_operation}");
            let (status, body) = send(path.clone()).await?;
            assert_eq!(status, 200, "{owner}: {body}");
            assert_eq!(
                body["originalResult"]["availability"], "not_found",
                "stored foreign instance must not become current instance"
            );
            assert_eq!(send(format!("{path}?instance={instance}")).await?.0, 403);
        }
        let path = format!(
            "/api/v1/operation-diagnostics/operations/resource/{operation}?includeAudit=true"
        );
        let mut cursor: Option<String> = None;
        let mut requests = std::collections::BTreeSet::new();
        for _ in 0..3 {
            let url = if let Some(cursor) = &cursor {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(cursor.as_bytes()).collect();
                format!("{path}&cursor={encoded}")
            } else {
                path.clone()
            };
            let (status, body) = send(url).await?;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["originalResult"]["value"]["revision"], 7);
            assert_eq!(
                body["requestEvidence"]["availability"], "available",
                "{body}"
            );
            for item in body["requestEvidence"]["value"]["items"]
                .as_array()
                .unwrap()
            {
                requests.insert(item["fact"]["requestId"].as_str().unwrap().to_owned());
            }
            cursor = body["requestEvidence"]["value"]["nextCursor"]
                .as_str()
                .map(str::to_owned);
            if let Some(cursor) = &cursor {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(cursor.as_bytes()).collect();
                assert_eq!(send(format!("/api/v1/operation-diagnostics/operations/scope/{operation}?includeAudit=true&cursor={encoded}")).await?.0, 409);
            } else {
                break;
            }
        }
        assert_eq!(
            requests.len(),
            55,
            "continuation reaches the oldest request attempt"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_resource_catalog.operations WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(operation).fetch_one(&c.operator).await?;
        assert_eq!(count, 1);
        assert_eq!(
            c.audit_count("mdm.business", &operation.to_string())
                .await?,
            0,
            "reads and request settlement never manufacture original business facts"
        );
        Ok::<_, anyhow::Error>(json!({"requests":requests.len()}))
    };
    let outcome = tokio::select! { result = &mut server => anyhow::bail!("host exited during diagnostics proof: {result:?}"), result = exercise => result };
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(70), &mut server).await??;
    c.close().await;
    outcome?;
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "production boundary monotonic clock in a real HTTP proof"
)]
#[tokio::test]
#[ignore = "T2: real Identity, receipt owner, HTTP and audit index failure"]
async fn original_result_survives_lost_response_new_config_and_index_failure() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let manager = c
        .account(&[
            Permission::AuthorizationRead,
            Permission::AuthorizationWrite,
        ])
        .await?;
    let proof = c.authenticate(&manager).await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let change = Change {
        operation_id: operation,
        expected_revision: 0,
        value: Some(Rule {
            subject: Subject::User {
                user: manager.user.clone(),
            },
            grants: vec![access::Grant {
                operation: Permission::ResourceRead,
                scope: Scope::Tenant,
            }],
        }),
    };
    let first = c.request(&proof)?;
    let first_request = first.request_id();
    let receipt = access::store::change_rule(&c.audit, &proof, id, change.clone(), &first).await?;
    first.finalize(None);
    assert_eq!(receipt.revision, 1);
    let next = c.request(&proof)?;
    access::store::change_rule(
        &c.audit,
        &proof,
        id,
        Change::<Rule> {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            value: None,
        },
        &next,
    )
    .await?;
    next.finalize(None);
    let retry = c.request(&proof)?;
    assert_eq!(
        access::store::change_rule(&c.audit, &proof, id, change, &retry)
            .await?
            .revision,
        1
    );
    retry.finalize(None);
    assert_eq!(
        c.audit_count("mdm.business", &operation.to_string())
            .await?,
        1
    );
    let bytes:Vec<u8>=sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business' AND convert_from(canonical,'UTF8') LIKE '%'||$2||'%' LIMIT 1").bind(c.tenant.to_string()).bind(operation.to_string()).fetch_one(&c.operator).await?;
    assert!(String::from_utf8(bytes)?.contains(&first_request.to_string()));
    let timeline = c.database.timeline(c.audit.clone(), c.tenant, &[41; 32])?;
    let services = Arc::new(Services {
        timeline: timeline.clone(),
        reads: Arc::new(super::operation_diagnostics::Installation {
            tenant: c.tenant,
            tenants: None,
            audit: c.audit.clone(),
            timeline,
        }),
    });
    let webauthn = rss_identity_postgres::WebauthnAuthority::connect(
        c.authority.clone(),
        "localhost".into(),
        url::Url::parse("https://localhost")?,
        deadline(),
    )
    .await?;
    let authentication = Arc::new(
        rss_mdm_management_http::authorization::http::AuthenticationState {
            identity: Arc::new(rss_mdm_management_http::identity::Identity {
                authority: c.authority.clone(),
                webauthn,
                http: rss_identity_http_axum::HttpConfig::new(
                    "https://localhost",
                    Duration::from_secs(8),
                )?,
                tenant: c.tenant,
            }),
            access: c.access(),
            requests: Arc::new(tokio::sync::Semaphore::new(8)),
        },
    );
    rss_mdm_http_contract::route_module! {struct DiagnosticsProof for [Browser]{diagnostics at "/api/v1"}}
    let routes = DiagnosticsProof {
        diagnostics: rss_mdm_management_http::operation_diagnostics::routes().with_state(services),
    }
    .assemble();
    let routes = rss_mdm_management_http::authorization::http::mount_protection(
        routes,
        Some(authentication),
        false,
    );
    let router = rss_mdm_management_http::boundary::wrap(
        routes,
        rss_mdm_management_http::boundary::Envelope {
            profile: rss_mdm_install_support::StorageProfile::Mdm,
            admission: Arc::new(tokio::sync::Semaphore::new(8)),
            host: "localhost".into(),
            clock: Arc::new(crate::Monotonic(std::time::Instant::now)),
            audit_store: c.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(8)),
            tenant: c.tenant.to_string(),
        },
    )
    .into_axum();
    let access::credential::RequestCredential::Cookie(secret) = manager.credential()? else {
        anyhow::bail!("cookie required")
    };
    let send = |uri: String| {
        let router = router.clone();
        let cookie = format!("__Host-identity-session={}", secret.expose());
        async move {
            let response = router
                .oneshot(
                    axum::http::Request::builder()
                        .uri(uri)
                        .header("host", "localhost")
                        .header("cookie", cookie)
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
            Ok::<_, anyhow::Error>((status, serde_json::from_slice::<serde_json::Value>(&body)?))
        }
    };
    let path = format!("/api/v1/operation-diagnostics/operations/authorization/{operation}");
    let (status, body) = send(format!("{path}?includeAudit=true")).await?;
    assert_eq!(status, 200);
    assert_eq!(body["originalResult"]["value"]["revision"], 1);
    assert_eq!(body["auditEvidence"]["availability"], "restricted");
    assert_eq!(
        send(format!(
            "/api/v1/operation-diagnostics/requests/{first_request}"
        ))
        .await?
        .0,
        403
    );
    assert_eq!(send(format!("{path}?actor=another-author")).await?.0, 403);
    let auditor = c.account(&[Permission::AuthorizationWrite]).await?;
    let auditor = c.authenticate(&auditor).await?;
    let a = c.request(&auditor)?;
    access::store::change_rule(
        &c.audit,
        &auditor,
        manager.rule,
        Change {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            value: Some(Rule {
                subject: Subject::User {
                    user: manager.user.clone(),
                },
                grants: vec![
                    access::Grant {
                        operation: Permission::AuthorizationRead,
                        scope: Scope::Tenant,
                    },
                    access::Grant {
                        operation: Permission::AuditRead,
                        scope: Scope::Tenant,
                    },
                ],
            }),
        },
        &a,
    )
    .await?;
    a.finalize(None);
    // Corrupt only this tenant's rebuildable cache. Original Audit and receipt rows remain intact.
    sqlx::query("INSERT INTO mdm_timeline.facts(tenant_id,position,source,event_id,recorded_at,instance_id,operation_id,actor,action,outcome,devices,operations,document,digest) SELECT tenant_id,position,source_id,event_id,recorded_at,$2::uuid,$3,$4,'authorization_write','succeeded','{}','{}',jsonb_build_object('operation',jsonb_build_object('owner','authorization')),decode(repeat('00',32),'hex') FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business' AND convert_from(canonical,'UTF8') LIKE '%'||$3::text||'%' LIMIT 1")
        .bind(c.tenant.to_string()).bind(proof.instance_id()).bind(operation).bind(proof.principal_id()).execute(&c.operator).await?;
    let (status, body) = send(format!("{path}?includeAudit=true")).await?;
    assert_eq!(status, 200);
    assert_eq!(body["originalResult"]["value"]["revision"], 1);
    assert_eq!(body["auditEvidence"]["availability"], "unavailable");
    let a = c.request(&auditor)?;
    access::store::change_rule(
        &c.audit,
        &auditor,
        manager.rule,
        Change::<Rule> {
            operation_id: Uuid::new_v4(),
            expected_revision: 2,
            value: None,
        },
        &a,
    )
    .await?;
    a.finalize(None);
    assert_eq!(send(path.clone()).await?.0, 403);
    let access::credential::RequestCredential::Cookie(revoke_secret) = manager.credential()? else {
        anyhow::bail!("cookie required")
    };
    let session = c
        .authority
        .inspect_session(c.tenant, revoke_secret, deadline())
        .await?;
    c.authority
        .revoke_current_session(session, deadline())
        .await?;
    assert_eq!(send(path).await?.0, 401);
    drop(router);
    c.close().await;
    Ok(())
}
