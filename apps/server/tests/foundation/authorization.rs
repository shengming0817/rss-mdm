//! Current product authority and the actual authorization/Audit source transaction.
use crate::authority_t2_support::*;
use anyhow::Result;
use rss_mdm_authorization_service::{self as access, Change, Permission, Rule, Scope, Subject};
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: actual Identity and product PostgreSQL authority"]
async fn same_session_reloads_current_grants_and_durable_authority_expires() -> Result<()> {
    let other = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    let context = Context::open("shared", &[other]).await?;
    let manager = context.account(&[Permission::AuthorizationWrite]).await?;
    let reader = context.account(&[Permission::ResourceRead]).await?;
    let proof = context.authenticate(&reader).await?;
    proof.require(Permission::ResourceRead, None)?;
    let authority = access::OperationAuthority::tenant(
        proof.authorization()?,
        &proof,
        Permission::ResourceRead,
    )?;
    assert!(
        context
            .authority_valid(&authority, Permission::ResourceRead)
            .await?
    );
    let manager = context.authenticate(&manager).await?;
    access::store::change_rule(
        &context.audit,
        &manager,
        reader.rule,
        Change::<Rule> {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            value: None,
        },
        &context.request(&manager)?,
    )
    .await?;
    let reloaded = context.authenticate(&reader).await?;
    assert!(matches!(
        reloaded.require(Permission::ResourceRead, None),
        Err(access::Error::Forbidden)
    ));
    assert!(
        !context
            .authority_valid(&authority, Permission::ResourceRead)
            .await?
    );
    assert!(
        matches!(
            access::session::SessionAuthority::new(context.authority.clone(), other)
                .authenticate(&context.access(), reader.credential()?)
                .await,
            Err(access::Error::Unauthorized)
        ),
        "a second legally admitted tenant must reject the first tenant's credential"
    );
    context.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: actual source transaction and SQL audit failure"]
async fn authorization_receipt_and_final_fact_share_commit_and_rollback() -> Result<()> {
    let context = Context::open("transaction", &[]).await?;
    let manager = context.account(&[Permission::AuthorizationWrite]).await?;
    let proof = context.authenticate(&manager).await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let rule = Rule {
        subject: Subject::User {
            user: manager.user.clone(),
        },
        grants: vec![access::Grant {
            operation: Permission::ResourceRead,
            scope: Scope::Tenant,
        }],
    };
    let change = Change {
        operation_id: operation,
        expected_revision: 0,
        value: Some(rule),
    };
    let audit = context.request(&proof)?;
    let receipt =
        access::store::change_rule(&context.audit, &proof, id, change.clone(), &audit).await?;
    assert_eq!(receipt.revision, 1);
    assert_eq!(
        context
            .audit_count("mdm.business", &operation.to_string())
            .await?,
        1
    );
    let stored: (i64, i64) = sqlx::query_as("SELECT (SELECT revision FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2),(SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id=$1::uuid AND operation_id=$3)")
        .bind(context.tenant.to_string()).bind(id).bind(operation).fetch_one(&context.operator).await?;
    assert_eq!(stored, (1, 1));
    let replay = access::store::change_rule(
        &context.audit,
        &proof,
        id,
        change.clone(),
        &context.request(&proof)?,
    )
    .await?;
    assert_eq!(
        serde_json::to_value(replay)?,
        serde_json::to_value(receipt)?
    );
    assert_eq!(
        context
            .audit_count("mdm.business", &operation.to_string())
            .await?,
        1
    );
    let mut conflicting = change;
    conflicting.value = None;
    assert!(matches!(
        access::store::change_rule(
            &context.audit,
            &proof,
            id,
            conflicting,
            &context.request(&proof)?
        )
        .await,
        Err(access::Error::Conflict)
    ));
    context.disable_audit().await?;
    let failed_id = Uuid::new_v4();
    let failed_operation = Uuid::new_v4();
    let failed = access::store::change_rule(
        &context.audit,
        &proof,
        failed_id,
        Change {
            operation_id: failed_operation,
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
        },
        &context.request(&proof)?,
    )
    .await;
    assert!(
        failed.is_err(),
        "the audited change must fail after SQL permission withdrawal"
    );
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2),(SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id=$1::uuid AND operation_id=$3)")
        .bind(context.tenant.to_string()).bind(failed_id).bind(failed_operation).fetch_one(&context.operator).await?;
    assert_eq!(counts, (0, 0));
    assert_eq!(
        context
            .audit_count("mdm.business", &failed_operation.to_string())
            .await?,
        0
    );
    context.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: product/source binding precedes purpose checks and current Identity facts fence reads"]
async fn embedded_source_is_bound_before_purpose_and_revocation_blocks_reads() -> Result<()> {
    use access::context::{AuthorizedPrincipal, Principal};
    use rss_mdm_install_support::StorageProfile;
    let c = Context::open("shared", &[]).await?;
    let result = async {
        let account = c.account(&[Permission::InventoryRead]).await?;
        let da = c.access().for_product(StorageProfile::Da);
        let access::credential::RequestCredential::Cookie(secret) = account.credential()? else {
            unreachable!()
        };
        let authenticated = c
            .authority
            .inspect_session(
                c.tenant,
                secret,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(3),
                ),
            )
            .await?;
        let bound = AuthorizedPrincipal::from_identity(&da, Principal::new(authenticated)?)?;
        assert_eq!(bound.profile(), StorageProfile::Da);
        assert_eq!(bound.authority_profile(), StorageProfile::Mdm);
        da.require_tenant_purpose(&bound, false).await?;
        assert!(
            bound.authorization().is_err(),
            "identity-only binding must not load grants"
        );
        let bound = bound.load_authorization(&da).await?;
        let request = c.read_auth(std::sync::Arc::new(bound));
        let fresh = request.revalidate().await?;
        request.current_binding(request.proof.authorization()?, fresh.as_ref())?;
        assert!(
            request
                .current_binding(request.proof.authorization()?, None)
                .is_err()
        );
        let access::credential::RequestCredential::Cookie(secret) = account.credential()? else {
            unreachable!()
        };
        let revoked = c
            .authority
            .inspect_session(c.tenant, secret, request.remaining()?)
            .await?;
        c.authority
            .revoke_current_session(
                revoked,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(3),
                ),
            )
            .await?;
        assert!(matches!(
            request.revalidate().await,
            Err(access::Error::Unauthorized)
        ));
        Ok(())
    }
    .await;
    c.close().await;
    result
}

#[tokio::test]
#[ignore = "T2: actual cookie authentication binds embedded DA authority before tenant purpose and optional grants"]
async fn embedded_da_http_binds_authority_before_purpose() -> Result<()> {
    use access::context::RequestAuth;
    use axum::{Extension, Router, routing::get};
    use rss_mdm_install_support::StorageProfile;
    use rss_mdm_management_http::authorization::http::{
        AuthenticationState, identity_only, protect,
    };
    use std::{sync::Arc, time::Duration};
    use tower::ServiceExt;
    let c = Context::open("shared", &[]).await?;
    let result = async {
        let origin = "https://query-test.invalid";
        let webauthn = rss_identity_postgres::WebauthnAuthority::connect(
            c.authority.clone(),
            "query-test.invalid".into(),
            origin.parse()?,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(6),
            ),
        )
        .await?;
        let state = Arc::new(AuthenticationState {
            identity: Arc::new(rss_mdm_management_http::identity::Identity {
                authority: c.authority.clone(),
                webauthn,
                http: rss_identity_http_axum::HttpConfig::new(origin, Duration::from_secs(8))?,
                tenant: c.tenant,
            }),
            access: Arc::new(c.access().for_product(StorageProfile::Da)),
            requests: Arc::new(tokio::sync::Semaphore::new(4)),
        });
        let protected = Router::new()
            .route(
                "/protected",
                get(|Extension(auth): Extension<RequestAuth>| async move {
                    assert_eq!(auth.proof.profile(), StorageProfile::Da);
                    assert_eq!(auth.proof.authority_profile(), StorageProfile::Mdm);
                    auth.proof
                        .require(
                            Permission::InventoryRead,
                            Some(&rss_mdm_agent_wire::DeviceId::new_v4()),
                        )
                        .map_err(rss_mdm_management_http::Error::from)?;
                    Ok::<_, rss_mdm_management_http::Error>(axum::http::StatusCode::OK)
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), protect));
        let identity = Router::new()
            .route(
                "/identity",
                get(|Extension(auth): Extension<RequestAuth>| async move {
                    assert!(auth.proof.authorization().is_err());
                    assert_eq!(auth.proof.authority_profile(), StorageProfile::Mdm);
                    axum::http::StatusCode::OK
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(state, identity_only));
        let app = protected
            .merge(identity)
            .layer(Extension(crate::clock::monotonic()));
        let allowed = c.account(&[Permission::InventoryRead]).await?;
        let denied = c.account(&[Permission::ResourceRead]).await?;
        for (account, path, expected) in [
            (&allowed, "/protected", 200),
            (&denied, "/protected", 403),
            (&denied, "/identity", 200),
        ] {
            let access::credential::RequestCredential::Cookie(secret) = account.credential()?
            else {
                unreachable!()
            };
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .header("host", "query-test.invalid")
                        .header("origin", origin)
                        .header(
                            "cookie",
                            format!("__Host-identity-session={}", secret.expose()),
                        )
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            assert_eq!(response.status().as_u16(), expected, "{path}");
        }
        // The real authentication owner can reject before the handler. Its response must
        // survive the same generated endpoint contract consumed by browsers.
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/protected")
                    .header("host", "query-test.invalid")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body, serde_json::json!({"code":"invalid_credential"}));
        let contract = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let endpoint = contract["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["method"] == "GET" && e["path"] == "/api/v1/device-views/{kind}/{id}")
            .unwrap();
        let responses = endpoint["responses"].as_array().unwrap();
        assert!(
            responses
                .iter()
                .filter(|r| r["status"] == 401)
                .any(|response| {
                    let id = response["body"]["schema"]["schemaId"].as_str().unwrap();
                    jsonschema::validator_for(&contract["schemas"][id])
                        .unwrap()
                        .is_valid(&body)
                })
        );
        assert!(
            !responses
                .iter()
                .filter(|r| r["status"] == 403)
                .any(|response| {
                    let id = response["body"]["schema"]["schemaId"].as_str().unwrap();
                    jsonschema::validator_for(&contract["schemas"][id])
                        .unwrap()
                        .is_valid(&body)
                })
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    c.close().await;
    result
}
