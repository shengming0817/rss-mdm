//! Product ingress and durable authority over real HTTP handlers and PostgreSQL.
#![allow(
    clippy::cognitive_complexity,
    reason = "distinct authentication and lifecycle denial assertions"
)]
use super::*;
use crate::audit_test_support::audit_count;
use rss_mdm_authorization_service::{
    OperationAuthority, Permission,
    context::AuthorizedPrincipal,
    credential::{ApiKeySecret, RequestCredential},
};

async fn fixture() -> Result<(authority::Authority, Router)> {
    use axum::middleware;
    use rss_mdm_management_http::{api_access, authorization::http, boundary};
    let authority = authority::Authority::open().await?;
    let management = Arc::new(api_access::Management {
        access: authority.authorization.clone(),
        audit: authority.audit.clone(),
    });
    let requests = Arc::new(tokio::sync::Semaphore::new(32));
    let network = Router::new()
        .nest(
            "/api/v1/tenant-administration",
            api_access::network_routes(management.clone()).into_axum(),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::new(http::AuthenticationState {
                identity: authority.identity.management_browser(),
                access: authority.authorization.clone(),
                requests: requests.clone(),
            }),
            http::protect_management,
        ))
        .layer(middleware::from_fn_with_state(
            (
                boundary::Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(32)),
                    host: "mdm.example.test".into(),
                    clock: monotonic(),
                    audit_store: authority.audit.clone(),
                    requests,
                    tenant: authority.identity.management_tenant.to_string(),
                },
                Arc::new(Vec::new()),
            ),
            boundary::admit,
        ))
        .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
    let bearer = authority
        .identity
        .bearer_routes()
        .route_layer(middleware::from_fn_with_state(
            Arc::new(api_access::BearerAdmission {
                access: authority.authorization.clone(),
                tenant: case_tenant().into(),
            }),
            api_access::admit_bearer,
        ));
    let authentication = rss_mdm_management_http::authentication_routes(
        rss_mdm_http_contract::Router::from_identity_router(
            authority.identity.routes().merge(bearer),
        ),
        boundary::Envelope {
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
            host: "mdm.example.test".into(),
            clock: monotonic(),
            audit_store: authority.audit.clone(),
            requests: Arc::new(tokio::sync::Semaphore::new(32)),
            tenant: case_tenant().into(),
        },
    )
    .into_axum();
    let router = authority
        .protect(Router::new().nest("/api/v1", api_access::key_routes(management).into_axum()))?
        .merge(network)
        .merge(authentication)
        .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
    Ok((authority, router))
}

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    input: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match input {
        Some(input) => {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&input)?)
        }
        None => Body::empty(),
    };
    let response = tokio::spawn(router.clone().oneshot(request.body(body)?)).await??;
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED
        && headers
            .iter()
            .any(|(name, _)| matches!(*name, "authorization" | "x-api-key"))
    {
        ensure!(response.headers().contains_key("www-authenticate"));
    }
    ensure!(response.headers()["cache-control"] == "no-store");
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}
fn manager() -> Result<Browser> {
    let config = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let secret = rss_identity_core::session::SessionSecret::parse(
        crate::config::secret(&config.parent().unwrap().join("source-session"))?.to_string(),
    )?;
    Ok(Browser {
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            secret.expose().into(),
        )]),
        csrf: Some(secret.csrf()),
        ..Browser::default()
    })
}
async fn policy(
    browser: &mut Browser,
    router: &Router,
    revision: u64,
    networks: Value,
) -> Result<()> {
    let response = browser.call(router, Method::PUT, "/api/v1/tenant-administration/api-access/network-policy", Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"networks":networks}))).await?;
    ensure!(
        response.0 == StatusCode::OK,
        "network policy: {}",
        response.0
    );
    ensure!(response.1["revision"] == revision + 1);
    Ok(())
}
async fn valid(store: &sqlx::PgPool, grant: &OperationAuthority) -> Result<bool> {
    let mut tx = store.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let valid = grant.valid(&mut tx, Permission::InventoryRead, now).await?;
    tx.rollback().await?;
    Ok(valid)
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: real HTTP, credentials and PostgreSQL"]
async fn programmatic_keys_tokens_and_online_network_policy() -> Result<()> {
    let (mut authority, mut router) = fixture().await?;
    let mut admin = authority.browser("admin")?;
    let store = authority.authorization.clone();
    let pool = authority.pool.clone();
    let tenant = authority.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    authority
        .resources
        .resource(SourceResource(runtime.clone()));
    let inventory = crate::planning::test_support::inventory_runtime(tenant).await;
    authority
        .resources
        .resource(InventoryFixtureResource(inventory.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        authority
            .audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
        inventory,
        audit,
        runtime,
        tenant,
        Arc::new(crate::clock::SystemClock),
        &key,
        Arc::new(crate::automation::inventory_tasks::InventoryTasks),
    ));
    router = router.merge(
        authority.protect(
            Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::assets::routes()
                    .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                        assets,
                    }))
                    .into_axum(),
            ),
        )?,
    );
    router = router.merge(authority.protect(authority.enrollment())?);
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        pg(&format!("INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{}','{}')", case_tenant(), case::name("device-1")))?;
        let mut manager = manager()?;
        let network_path = "/api/v1/tenant-administration/api-access/network-policy";
        let (status, initial) = manager.call(&router, Method::GET, network_path, None).await?;
        ensure!(status == StatusCode::OK && initial["networks"] == json!([]) && initial["revision"] == 0);
        ensure!(admin.call(&router, Method::GET, network_path, None).await?.0 == StatusCode::UNAUTHORIZED);
        let login_path = format!("/api/v1/identity/tenants/{}/bearer/login", case_tenant());
        let login = json!({"login":case::login("admin"),"password":PASSWORD});
        ensure!(call(&router, Method::POST, &login_path, &[], Some(login.clone())).await?.0 == StatusCode::FORBIDDEN);

        ensure!(audit_count(|r| r.action()=="authentication" && r.status()==403 && r.result()=="denied").await? > 0);
        let id = Uuid::new_v4();
        let metadata = json!({"name":"automation","enabled":true,"expiresAt":null,"grants":[{"operation":"inventory_read","scope":{"kind":"all_devices"}}]});
        let operation = Uuid::new_v4();
        let create = json!({"id":id,"operationId":operation,"metadata":metadata});
        let (status, issued) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create.clone())).await?;
        ensure!(status == StatusCode::OK, "key creation: {status}");
        let secret = issued["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing first secret"))?.to_owned();
        ensure!(secret.len() == 101);
        let (_, replay) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create)).await?;
        ensure!(replay["secret"].is_null() && replay["receipt"] == issued["receipt"]);
        let key_path = format!("/api/v1/api-keys/{id}");
        let (_, read) = admin.call(&router, Method::GET, &key_path, None).await?;
        ensure!(!read.to_string().contains(&secret) && read["id"] == id.to_string());
        let inventory = format!("{}/inventory", case_device());
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::FORBIDDEN);
        policy(&mut manager, &router, 0, json!(["127.0.0.1/32"])).await?;
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, "/api/v1/api-keys", &[("x-api-key", &secret)], None).await?.0 == StatusCode::FORBIDDEN);
        let (status, token) = call(&router, Method::POST, &login_path, &[], Some(login.clone())).await?;
        ensure!(status == StatusCode::OK, "bearer login: {status}");
        let bearer = format!("Bearer {}", token["accessToken"].as_str().ok_or_else(|| anyhow::anyhow!("missing bearer"))?);
        ensure!(call(&router, Method::GET, &inventory, &[("authorization", &bearer)], None).await?.0 == StatusCode::OK);
        for (method,path) in [(Method::GET,"/api/v1/self-enrollments"),(Method::POST,"/api/v1/self-enrollments"),(Method::GET,"/api/v1/registration-quotas/me")] {
            ensure!(call(&router,method,path,&[("authorization",&bearer)],Some(json!({}))).await?.0==StatusCode::FORBIDDEN);
        }
        for headers in [vec![("authorization", bearer.as_str()), ("x-api-key", secret.as_str())], vec![("x-api-key", secret.as_str()), ("x-api-key", secret.as_str())], vec![("authorization", bearer.as_str()), ("authorization", bearer.as_str())], vec![("x-api-key", secret.as_str()), ("cookie", "__Host-identity-session=broken")]] {
            ensure!(call(&router, Method::GET, &inventory, &headers, None).await?.0 == StatusCode::BAD_REQUEST);
        }
        let digest = pg(&format!("SELECT encode(secret_digest,'hex') FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{id}'", case_tenant()))?;
        ensure!(digest.trim().len() == 64 && !digest.contains(&secret));

        let access = store.clone();
        let parsed = ApiKeySecret::parse(secret.clone())?;
        let proof = AuthorizedPrincipal::from_identity(access.authenticate_key(case_tenant(), &parsed).await?).load_authorization(&access).await?;
        let grant = OperationAuthority::all_devices(proof.authorization()?, &proof, Permission::InventoryRead)?;
        ensure!(valid(&pool, &grant).await?);
        let (status, rotation) = admin.call(&router, Method::POST, &format!("{key_path}/rotate"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
        ensure!(status == StatusCode::OK);
        let rotated = rotation["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing rotated secret"))?.to_owned();
        ensure!(rotated != secret && valid(&pool, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &secret)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::OK);
        let (identity, identity_resources) = crate::test_support::identity::identity(case_tenant()).await?;
        identity_resources.finish(async {
            let sessions = rss_mdm_authorization_service::session::SessionAuthority::new(identity.authority.clone(), identity.tenant);
            ensure!(sessions.authenticate(&access, RequestCredential::ApiKey(parsed)).await.is_err());
            Ok(())
        }).await?;
        let mut named = metadata.clone(); named["name"] = json!("renamed");
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"metadata":named}))).await?.0 == StatusCode::OK);
        ensure!(valid(&pool, &grant).await?);
        let mut disabled = named.clone(); disabled["enabled"] = json!(false);
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"metadata":disabled}))).await?.0 == StatusCode::OK);
        ensure!(!valid(&pool, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(admin.call(&router, Method::PUT, &key_path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":4,"metadata":named}))).await?.0 == StatusCode::OK);
        ensure!(!valid(&pool, &grant).await?);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::OK);
        policy(&mut manager, &router, 1, json!(["192.0.2.0/24"])).await?;
        for (name, credential) in [("authorization", bearer.as_str()), ("x-api-key", rotated.as_str())] {
            ensure!(call(&router, Method::GET, &inventory, &[(name, credential), ("x-forwarded-for", "192.0.2.1")], None).await?.0 == StatusCode::FORBIDDEN);
        }
        ensure!(call(&router, Method::POST, &login_path, &[("x-forwarded-for", "192.0.2.1")], Some(login)).await?.0 == StatusCode::FORBIDDEN);
        policy(&mut manager, &router, 2, json!(["127.0.0.1"])).await?;
        let logout = format!("/api/v1/identity/tenants/{}/bearer/logout", case_tenant());
        ensure!(call(&router, Method::POST, &logout, &[("authorization", &bearer)], None).await?.0 == StatusCode::NO_CONTENT);
        ensure!(call(&router, Method::GET, &inventory, &[("authorization", &bearer)], None).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(admin.call(&router, Method::POST, &format!("{key_path}/revoke"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":5}))).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key", &rotated)], None).await?.0 == StatusCode::UNAUTHORIZED);
        policy(&mut manager, &router, 3, json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: real key scope, lifecycle and transaction settlement"]
async fn key_scope_expiry_creator_independence_and_uncertain_issuance() -> Result<()> {
    let (mut authority, mut router) = fixture().await?;
    let mut admin = authority.browser("admin")?;
    let audit_store = authority.audit.clone();
    let store = authority.authorization.clone();
    let tenant = authority.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    authority
        .resources
        .resource(SourceResource(runtime.clone()));
    let inventory = crate::planning::test_support::inventory_runtime(tenant).await;
    authority
        .resources
        .resource(InventoryFixtureResource(inventory.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        authority
            .audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(
        inventory,
        audit,
        runtime,
        tenant,
        Arc::new(crate::clock::SystemClock),
        &key,
        Arc::new(crate::automation::inventory_tasks::InventoryTasks),
    ));
    router = router.merge(
        authority.protect(
            Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::assets::routes()
                    .with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState {
                        assets,
                    }))
                    .into_axum(),
            ),
        )?,
    );
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        pg(&format!("INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{}','{}')", case_tenant(), case::name("device-1")))?;
        let mut manager = manager()?;
        policy(&mut manager, &router, 0, json!(["127.0.0.1"])).await?;
        let scoped = json!({"name":"scoped","enabled":true,"expiresAt":null,"grants":[{"operation":"inventory_read","scope":{"kind":"device","id":case::name("device-1")}}]});
        let id = Uuid::new_v4();
        let create = json!({"id":id,"operationId":Uuid::new_v4(),"metadata":scoped});
        audit_store.inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck);
        let (status, unknown) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create.clone())).await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE && unknown.get("secret").is_none());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim() == "1");
        let (status, replay) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(create)).await?;
        ensure!(status == StatusCode::OK && replay["secret"].is_null());
        let path = format!("/api/v1/api-keys/{id}");
        let (status, rotation) = admin.call(&router, Method::POST, &format!("{path}/rotate"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
        ensure!(status == StatusCode::OK);
        let secret = rotation["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing rotated secret"))?.to_owned();
        let inventory = format!("{}/inventory",case_device());
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key",&secret)], None).await?.0 == StatusCode::OK);
        ensure!(call(&router, Method::GET, "/api/v1/devices/outside-key-scope/inventory", &[("x-api-key",&secret)], None).await?.0 == StatusCode::FORBIDDEN);
        ensure!(store.clone().authenticate_key(&Uuid::new_v4().to_string(), &ApiKeySecret::parse(secret.clone())?).await.is_err());
        for permission in ["identity_accounts_manage","identity_providers_manage","authorization_write","tenant_create"] {
            let mut input = scoped.clone(); input["grants"]=json!([{"operation":permission,"scope":{"kind":"tenant"}}]);
            ensure!(admin.call(&router, Method::PUT, &path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"metadata":input}))).await?.0 == StatusCode::BAD_REQUEST);
        }
        // Real rollback after the key write: no metadata, operation receipt or secret escapes.
        let failed_id = Uuid::new_v4();
        pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
        let failed = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(json!({"id":failed_id,"operationId":Uuid::new_v4(),"metadata":scoped}))).await;
        pg("GRANT INSERT(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) ON mdm_audit.receipts TO mdm_access")?;
        let (status, result) = failed?;
        ensure!(!status.is_success() && result.get("secret").is_none());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.api_keys WHERE tenant_id='{}' AND id='{failed_id}'",case_tenant()))?.trim() == "0");
        // Expiry uses current persisted metadata, not a credential cache.
        pg(&format!("UPDATE mdm_access.api_keys SET metadata=jsonb_set(metadata,'{{expiresAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-1)) WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        ensure!(call(&router, Method::GET, &inventory, &[("x-api-key",&secret)], None).await?.0 == StatusCode::UNAUTHORIZED);
        pg(&format!("UPDATE mdm_access.api_keys SET metadata=jsonb_set(metadata,'{{expiresAt}}','null') WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        let login_path=format!("/api/v1/identity/tenants/{}/bearer/login",case_tenant());
        let (status, token)=call(&router,Method::POST,&login_path,&[],Some(json!({"login":case::login("admin"),"password":PASSWORD}))).await?;
        ensure!(status==StatusCode::OK);
        let bearer=format!("Bearer {}",token["accessToken"].as_str().ok_or_else(||anyhow::anyhow!("missing bearer"))?);
        // Creator is audit metadata only; disabling it rejects its token but leaves tenant Key usable.
        let account_path=format!("/api/v1/identity/tenants/{}/accounts/{}/enabled",case_tenant(),case_admin());
        ensure!(admin.call(&router,Method::POST,&account_path,Some(json!({"enabled":false}))).await?.0==StatusCode::OK);
        ensure!(call(&router,Method::GET,&inventory,&[("authorization",&bearer)],None).await?.0==StatusCode::UNAUTHORIZED);
        ensure!(call(&router,Method::GET,&inventory,&[("x-api-key",&secret)],None).await?.0==StatusCode::OK);
        let receipts=pg(&format!("SELECT result FROM mdm_access.authorization_operations WHERE tenant_id='{}'",case_tenant()))?;
        ensure!(!receipts.contains(&secret));
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: programmatic business writes and managed enrollment"]
async fn business_writes_bind_key_actor_and_managed_enrollment() -> Result<()> {
    let (mut authority, mut router) = fixture().await?;
    let mut admin = authority.browser("admin")?;
    let tenant = authority.identity.tenant;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    authority
        .resources
        .resource(SourceResource(runtime.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        authority
            .audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let clock = Arc::new(crate::clock::SystemClock);
    let sessions = Arc::new(
        rss_mdm_authorization_service::session::SessionAuthority::new(
            authority.identity.authority.clone(),
            tenant,
        ),
    );
    let content = None;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
            authority.identity.authority.clone(),
            tenant,
        ),
        authorization: authority.authorization.clone(),
        runtime: runtime.clone(),
        audit_store: audit.clone(),
        tenant,
        content,
        clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let catalog = crate::flow::catalog(audit, runtime, tenant, clock).await?;
    let timeline = Arc::new(rss_mdm_timeline_service::Timeline::new(
        authority.pool.clone(),
        authority.audit.clone(),
        tenant,
        &secret("timeline-cursor"),
    )?);
    timeline.initialize().await?;
    let routes = rss_mdm_management_http::resource_catalog::http::routes()
        .with_state(Arc::new(
            rss_mdm_management_http::resource_catalog::http::HttpState {
                catalog,
                content: content_access,
            },
        ))
        .merge(rss_mdm_management_http::timeline::routes().with_state(timeline));
    router = router.merge(
        authority.protect(
            Router::new()
                .nest("/api/v1", routes.into_axum())
                .merge(authority.enrollment()),
        )?,
    );
    let (execution, _, _) = crate::test_support::command::command_service(
        authority.audit.clone(),
        sessions.clone(),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    authority
        .resources
        .resource(rss_mdm_execution_service::Resource(execution.clone()));
    let apple = Arc::new(rss_mdm_apple_channel::HttpState {
        platform_sso: None,
        platform_objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
            authority.audit.clone(),
        )),
        material_roots: Arc::new(vec![]),
        account_authority: rss_mdm_apple_channel::account_enrollment::authority(),
        authentication: rss_mdm_apple_channel::account_enrollment::Authentication {
            authority: authority.identity.authority.clone(),
            http: authority.identity.browser().http.clone(),
            origin: config.product_origin.clone(),
        },
        mount: crate::device::ChannelMount::new(
            tenant,
            rss_mdm_inventory::ReportSource::MdmApple,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: authority.audit.clone(),
        access: Arc::new(rss_mdm_apple_channel::Store::from_pool(
            authority.pool.clone(),
            authority.registration.clone(),
            authority.authorization.clone(),
        )),
        apple: None,
        clock: Arc::new(crate::clock::InventoryClock(Arc::new(
            crate::clock::SystemClock,
        ))),
        execution,
        protection: config.native_protector()?,
        credentials: authority.credentials.clone(),
        devices: Arc::new(crate::device::DeviceService::new(
            authority.registration.clone(),
            case_tenant().into(),
            authority.audit.clone(),
        )),
        identity: sessions,
        requests: Arc::new(tokio::sync::Semaphore::new(32)),
    });
    router = router.merge(
        authority.protect(
            rss_mdm_apple_channel::management_routes(apple)
                .into_axum()
                .layer(axum::middleware::from_fn(
                    crate::api::apple_management_settlement,
                )),
        )?,
    );

    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let mut manager = manager()?;
        policy(&mut manager, &router, 0, json!(["127.0.0.1"])).await?;
        let id = Uuid::new_v4();
        let metadata = json!({"name":"automation-writer","enabled":true,"expiresAt":null,"grants":[
            {"operation":"registration_configuration_read","scope":{"kind":"tenant"}},
            {"operation":"registration_configuration_write","scope":{"kind":"tenant"}},
            {"operation":"audit_read","scope":{"kind":"tenant"}},
            {"operation":"resource_write","scope":{"kind":"tenant"}},
            {"operation":"resource_read","scope":{"kind":"tenant"}},
            {"operation":"enrollment","scope":{"kind":"all_devices"}},
            {"operation":"inventory_read","scope":{"kind":"all_devices"}}
        ]});
        let (status, created) = admin.call(&router, Method::POST, "/api/v1/api-keys", Some(json!({"id":id,"operationId":Uuid::new_v4(),"metadata":metadata}))).await?;
        ensure!(status == StatusCode::OK);
        let secret = created["secret"].as_str().ok_or_else(|| anyhow::anyhow!("missing key"))?;
        for path in ["/api/v1/registration-quotas/defaults","/api/v1/audit-events","/api/v1/apple/organizations"] {
            ensure!(call(&router,Method::GET,path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK,"business read: {path}");
        }
        let organization=Uuid::new_v4();
        let ade_path=format!("/api/v1/apple/organizations/{organization}/ade");
        let ade_operation=Uuid::new_v4().to_string();
        let configured=call(&router,Method::PUT,&format!("{ade_path}/configuration"),&[("x-api-key",secret),("idempotency-key",&ade_operation)],Some(json!({"expectedRevision":0,"enabled":false,"serverUuid":organization,"orgId":"programmatic-test","rotateKey":false}))).await?;
        ensure!(configured.0==StatusCode::OK,"ADE configuration: {}",configured.0);
        ensure!(call(&router,Method::GET,&ade_path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let usage_path=format!("/api/v1/registration-quotas/users/{INSTANCE}/{}/usage",case_admin());
        ensure!(call(&router,Method::GET,&usage_path,&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let resource = Uuid::new_v4();
        let resource_path = format!("/api/v1/resources/{resource}");
        let operation = Uuid::new_v4();
        let body = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"create","kind":"script"}});
        let written = call(&router, Method::POST, &resource_path, &[("x-api-key",secret)], Some(body.clone())).await?;
        ensure!(written.0 == StatusCode::OK, "resource write: {}", written.0);
        ensure!(call(&router, Method::POST, &resource_path, &[("x-api-key",secret)], Some(body)).await? == written);
        ensure!(call(&router, Method::GET, &resource_path, &[("x-api-key",secret)], None).await?.0 == StatusCode::OK);
        let actor = format!("api-key:{id}");
        ensure!(audit_count(|r| r.actor()==Some(actor.as_str()) && r.event.facts().actor().kind().as_str()=="api_key" && r.operation()==Some(operation.to_string().as_str()) && r.result()=="success").await? > 0);
        let enrollment_op = Uuid::new_v4().to_string();
        let enrollment = call(&router, Method::POST, "/api/v1/enrollments", &[("x-api-key",secret),("idempotency-key",&enrollment_op)], Some(json!({"deviceId":case::name("device-1"),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?;
        ensure!(enrollment.0 == StatusCode::OK, "managed enrollment: {}", enrollment.0);
        let enrollment_id=enrollment.1["enrollmentId"].as_str().ok_or_else(|| anyhow::anyhow!("missing enrollment"))?;
        ensure!(call(&router,Method::GET,&format!("/api/v1/enrollments/{enrollment_id}"),&[("x-api-key",secret)],None).await?.0==StatusCode::OK);
        let key_path=format!("/api/v1/api-keys/{id}");
        let mut reduced=metadata.clone(); reduced["grants"]=json!([{"operation":"inventory_read","scope":{"kind":"all_devices"}}]);
        ensure!(admin.call(&router,Method::PUT,&key_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"metadata":reduced}))).await?.0==StatusCode::OK);
        let resume_op=Uuid::new_v4().to_string();
        ensure!(call(&router,Method::POST,&format!("/api/v1/enrollments/{enrollment_id}/resume"),&[("x-api-key",secret),("idempotency-key",&resume_op)],Some(json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}))).await?.0==StatusCode::FORBIDDEN);
        ensure!(call(&router,Method::GET,&resource_path,&[("x-api-key",secret)],None).await?.0==StatusCode::FORBIDDEN);
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=authorization.programmatic: original API key rechecked after streamed body"]
async fn streamed_content_rejects_rotated_key_before_binding() -> Result<()> {
    use futures::SinkExt;
    use sha2::{Digest, Sha256};
    let (mut authority, mut router) = fixture().await?;
    let mut admin = authority.browser("admin")?;
    let tenant = authority.identity.tenant;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    authority
        .resources
        .resource(SourceResource(runtime.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(
        authority
            .audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let clock = Arc::new(crate::clock::SystemClock);
    let content =
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(store) = &content {
        authority
            .resources
            .resource(crate::execution_assembly::ContentResource(store.clone()));
    }
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
            authority.identity.authority.clone(),
            tenant,
        ),
        authorization: authority.authorization.clone(),
        runtime: runtime.clone(),
        audit_store: audit.clone(),
        tenant,
        content,
        clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    router = router.merge(
        authority.protect(
            Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::content::http::routes()
                    .with_state(content_access)
                    .into_axum(),
            ),
        )?,
    );

    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let mut manager = manager()?;
        policy(&mut manager,&router,0,json!(["127.0.0.1"])).await?;
        let id=Uuid::new_v4();
        let metadata=json!({"name":"stream-writer","enabled":true,"expiresAt":null,"grants":[{"operation":"resource_write","scope":{"kind":"tenant"}},{"operation":"resource_read","scope":{"kind":"tenant"}}]});
        let (status,issued)=admin.call(&router,Method::POST,"/api/v1/api-keys",Some(json!({"id":id,"operationId":Uuid::new_v4(),"metadata":metadata}))).await?;
        ensure!(status==StatusCode::OK);
        let secret=issued["secret"].as_str().ok_or_else(||anyhow::anyhow!("missing key"))?;
        let resource=Uuid::new_v4();
        let path=format!("/api/v1/resources/{resource}");
        let bytes=b"#!/bin/sh\nprintf '{}'\n";
        let digest:[u8;32]=Sha256::digest(bytes).into();
        let script=json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{},"required":[],"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
        use rss_mdm_resource::{Architecture, Artifact, Declaration, Digest, Id, Kind, Platform, Variant, Version};
        let version = Version::new(tenant, Id::new(resource.to_string())?, Id::new("v1")?, Kind::Script,
            vec![Variant::new(Platform::MacOS, Architecture::Aarch64, Id::new("default")?, Declaration::Script {
                artifact: Artifact::new(Id::new("script")?, bytes.len() as u64, Digest::from_bytes(digest))?,
                definition: serde_json::from_value(script)?,
            })])?;
        runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
            rss_mdm_resource_postgres::fixture::draft_version_in(tx, version, rss_contract::Timepoint::try_from(1_i64).unwrap()).await
        })).await.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("resource rollback unconfirmed")), |_| Err(anyhow::anyhow!("resource commit unconfirmed")), |e| Err(anyhow::anyhow!(e)))?;
        let operation=Uuid::new_v4();
        let upload_path=|op|format!("{path}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={op}");
        let (mut sender,stream)=futures::channel::mpsc::channel::<Result<Vec<u8>,std::io::Error>>(1);
        let request=Request::builder().method(Method::POST).uri(upload_path(operation)).header("host","mdm.example.test").header("x-api-key",secret).header("content-type","application/octet-stream").body(Body::from_stream(stream))?;
        let running=tokio::spawn(router.clone().oneshot(request));
        sender.send(Ok(bytes[..1].to_vec())).await?;
        let observer=sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(crate::device::test_support::options("postgres")?).await?;
        let claimed=tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND document->'value'->'upload'->>'id'=$2 AND epoch IS NOT NULL").bind(case_tenant()).bind(operation.to_string()).fetch_one(&observer).await?;
                if count==1 { return Ok::<_,anyhow::Error>(()); }
                tokio::task::yield_now().await;
            }
        }).await;
        observer.close().await;
        let rotated:Result<String>=async {
            claimed??;
            let (status,rotation)=admin.call(&router,Method::POST,&format!("/api/v1/api-keys/{id}/rotate"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))).await?;
            ensure!(status==StatusCode::OK);
            let rotated=rotation["secret"].as_str().ok_or_else(||anyhow::anyhow!("missing rotated key"))?.to_owned();
            sender.send(Ok(bytes[1..].to_vec())).await?;
            Ok(rotated)
        }.await;
        drop(sender);
        let response=running.await??;
        let rotated=rotated?;
        ensure!(response.status()==StatusCode::UNAUTHORIZED,"rotated upload: {}",response.status());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'",case_tenant()))?.trim()=="0");
        ensure!(audit_count(|r|r.operation()==Some(operation.to_string().as_str()) && r.status()==201 && r.result()=="success").await?==0);
        let replacement=Uuid::new_v4();
        let response=router.clone().oneshot(Request::builder().method(Method::POST).uri(upload_path(replacement)).header("host","mdm.example.test").header("x-api-key",rotated).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?).await?;
        ensure!(response.status()==StatusCode::CREATED,"new key upload: {}",response.status());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{replacement}'",case_tenant()))?.trim()=="1");
        policy(&mut manager,&router,1,json!([])).await?;
        Ok(())
    }).await
}
