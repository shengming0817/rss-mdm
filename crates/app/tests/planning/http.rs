#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::test_support::planning_http::*;
use crate::test_support::{
    http::Browser, http::await_task, http::change_device_grants, http::change_management_grants,
    http::prepared_subject, http::seed_management_grants,
};
use crate::test_support::{process::*, runtime::*, *};
#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_collection_routes_reuse_current_policy() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            let tenant = fixture.identity.tenant;
            let runtime = crate::planning::test_support::runtime(tenant).await;
            let mut app_resources = Resources::default();
            app_resources.resource(SourceResource(runtime.clone()));
            let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
            let clock = Arc::new(crate::clock::SystemClock);
            let budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
            let audit = Arc::new(
                fixture
                    .audit
                    .on_runtime(runtime.clone(), tenant, &budget.control())
                    .await?,
            );
            let planning = Arc::new(
                crate::planning::Planning::new(
                    audit.clone(),
                    runtime.clone(),
                    tenant,
                    clock.clone(),
                    &key,
                    Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
                        audit.clone(),
                    )),
                )
                .await?,
            );
            let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
            let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(
                rss_mdm_management_http::planning::http::HttpState {
                    planning: planning.clone(),
                    groups,
                },
            ));
            let content = None;
            let catalog =
                crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
            let content_access = Arc::new(rss_mdm_content_service::service::Access {
                sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                    fixture.identity.authority.clone(),
                    tenant,
                ),
                authorization: fixture.authorization.clone(),
                runtime: runtime.clone(),
                audit_store: audit.clone(),
                tenant,
                content: content.clone(),
                clock: Arc::new(crate::clock::ContentClock(clock.clone())),
                catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
            });
            let routes = routes.merge(
                rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(
                    rss_mdm_management_http::resource_catalog::http::HttpState {
                        catalog: catalog.clone(),
                        content: content_access.clone(),
                    },
                )),
            );
            let router = fixture.router(
                rss_mdm_http_contract::Router::new()
                    .nest("/api/v1", routes)
                    .merge(fixture.authorization()),
            )?;

            app_resources
                .finish(async {
                    let mut browser = fixture.browser("other")?;
                    let subject = prepared_subject(&browser)?;
                    seed_management_grants(
                        &subject,
                        json!(["group_read", "scope_read", "policy_read", "resource_read"]),
                    )
                    .await?;
                    for path in ["/api/v1/groups", "/api/v1/scopes", "/api/v1/resources"] {
                        let (status, page) = browser.call(&router, Method::GET, path, None).await?;
                        ensure!(
                            status == StatusCode::OK,
                            "missing collection {path}: {status} {page}"
                        );
                        ensure!(page["items"].is_array() && page["nextCursor"].is_null());
                        ensure!(
                            browser
                                .call(&router, Method::GET, &format!("{path}?limit=0"), None)
                                .await?
                                .0
                                == StatusCode::BAD_REQUEST
                        );
                        ensure!(
                            browser
                                .call(&router, Method::GET, &format!("{path}?limit=1001"), None)
                                .await?
                                .0
                                == StatusCode::BAD_REQUEST
                        );
                    }
                    change_management_grants(&subject, json!([])).await?;
                    for path in ["/api/v1/groups", "/api/v1/scopes", "/api/v1/resources"] {
                        ensure!(
                            browser.call(&router, Method::GET, path, None).await?.0
                                == StatusCode::FORBIDDEN
                        );
                    }
                    Ok(())
                })
                .await
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_pending_directory_and_permission_changes() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let inventory = crate::inventory_runtime::InventoryRuntime::fixture(config.runtime_database.options()?, Arc::new(rss_mdm_inventory_service::Store::from_pool(fixture.pool.clone())), tenant, monotonic(), fixture.audit.clone()).await?;
    app_resources.resource(InventoryFixtureResource(inventory.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(inventory, audit, runtime, tenant, Arc::new(crate::clock::SystemClock), &key, Arc::new(crate::automation::inventory_tasks::InventoryTasks)));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: false, protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: None, signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(fixture.audit.clone())), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs, signed: false, content_available: false,
    }));
    let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(fixture.registration.clone(), tenant.to_string(), fixture.audit.clone()));
    let routes = rss_mdm_management_http::enrollment::directory::routes().with_state(Arc::new(rss_mdm_management_http::enrollment::directory::HttpState {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, devices, assets: assets.clone(), queries, windows: true, apple: false,
    }));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.enrollment()).merge(fixture.authorization()))?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let device = case::name("pending-console");
    change_device_grants(&mut browser,
        device,
        &["enrollment", "inventory_read"],
    )
    .await?;
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, enrollment) = browser.call(&router, Method::POST, "/api/v1/enrollments", Some(json!({"deviceId":device,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?;
    ensure!(
        status == StatusCode::OK,
        "enrollment: {status} {enrollment}"
    );
    let (status, page) = browser
        .call(&router, Method::GET, "/api/v1/devices?limit=1", None)
        .await?;
    ensure!(
        status == StatusCode::OK,
        "pending directory: {status} {page}"
    );
    ensure!(page["items"][0]["id"] == device && page["items"][0]["status"] == "pending");
    let (statistics_status,statistics)=browser.call(&router,Method::GET,"/api/v1/devices/statistics",None).await?;
    ensure!(statistics_status==StatusCode::OK && statistics["statistics"]["total"]==1);
    ensure!(page["items"][0]["inventoryAvailable"] == false && page.get("statistics").is_none());
    let detail = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/devices/{device}"),
            None,
        )
        .await?;
    ensure!(detail.0 == StatusCode::OK && detail.1["id"] == device);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.devices WHERE tenant_id='{}' AND id='{device}'",
            case_tenant()
        ))?
        .trim()
            == "0",
        "directory inserted pending device authority"
    );
    change_device_grants(&mut browser, device, &["enrollment"]).await?;
    for id in [device, case::name("hidden-console")] {
        ensure!(
            browser
                .call(&router, Method::GET, &format!("/api/v1/devices/{id}"), None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
    }
    ensure!(
        browser
            .call(&router, Method::GET, "/api/v1/devices", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
    }).await

    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_directory_pages_registered_revoked_and_pending() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let inventory = crate::inventory_runtime::InventoryRuntime::fixture(config.runtime_database.options()?, Arc::new(rss_mdm_inventory_service::Store::from_pool(fixture.pool.clone())), tenant, monotonic(), fixture.audit.clone()).await?;
    app_resources.resource(InventoryFixtureResource(inventory.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(inventory, audit, runtime, tenant, Arc::new(crate::clock::SystemClock), &key, Arc::new(crate::automation::inventory_tasks::InventoryTasks)));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: false, protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: None, signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(fixture.audit.clone())), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs, signed: false, content_available: false,
    }));
    let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(fixture.registration.clone(), tenant.to_string(), fixture.audit.clone()));
    let routes = rss_mdm_management_http::enrollment::directory::routes().with_state(Arc::new(rss_mdm_management_http::enrollment::directory::HttpState {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, devices, assets: assets.clone(), queries, windows: true, apple: false,
    }));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.enrollment()).merge(fixture.authorization()))?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = prepared_subject(&browser)?;
    identity::seed_grants(
        case_tenant(),
        &subject,
        identity::device_grants(None, &["inventory_read", "enrollment", "credentials"])?,
    )
    .await?;
    let pending = case::name("a-pending");
    let revoked = case::name("b-revoked");
    let registered = case::name("c-registered");
    let password_digest = crate::enrollment::Password::new("A".repeat(43))?.digest(case_tenant(), pending)?;
    let pending_grant = Uuid::new_v4();
    let pending_request = Uuid::new_v4();
    let revoked_grant = Uuid::new_v4();
    let revoked_request = Uuid::new_v4();
    let registration = Uuid::new_v4();
    pg(&format!("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{tenant}','{pending_grant}','fixture','{instance}','{pending}','enrollment','available',clock_timestamp()+interval '60 seconds'),('{tenant}','{revoked_grant}','fixture','{instance}','{revoked}','enrollment','consumed',clock_timestamp()+interval '60 seconds'); INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile,state,expected_generation,password_digest,password_version,expires_at,issuance_operation,credential_ref) VALUES('{tenant}','{pending_request}','{pending_grant}','mdm.windows','Device','pending',0,'{password_digest}',1,clock_timestamp()+interval '60 seconds',gen_random_uuid(),gen_random_uuid()),('{tenant}','{revoked_request}','{revoked_grant}','mdm.windows','Device','cancelled',0,NULL,0,NULL,NULL,NULL); INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{tenant}','{revoked}'); INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES('{tenant}','{registration}','{revoked}','mdm',1,'{revoked_request}','revoked','primary',gen_random_uuid()); INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES('{tenant}',gen_random_uuid(),'{registration}','mdm',repeat('1',64),'revoked')", tenant=case_tenant(), instance=INSTANCE))?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{}','{registered}')",
        case_tenant()
    ))?;
    pg_tenant(
        case::peer(),
        &format!(
            "INSERT INTO mdm_access.devices VALUES('{}','{}')",
            case::peer(),
            case::name("peer-hidden")
        ),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, hosted).await },
    ));
    browser.network = Some((
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()?,
        format!("http://{address}"),
    ));
    for descending in [false, true] {
        let sort=if descending{"-id"}else{"id"};
        let mut path = format!("/api/v1/devices?limit=1&sort={sort}");
        let mut ids = Vec::new();
        loop {
            let (status, page) = browser.call(&router, Method::GET, &path, None).await?;
            ensure!(status == StatusCode::OK, "directory page: {status} {page}");
            let(_,statistics)=browser.call(&router,Method::GET,"/api/v1/devices/statistics",None).await?;
            ensure!(
                statistics["statistics"]["total"] == 3
                    && statistics["statistics"]["pending"] == 1
                    && statistics["statistics"]["revoked"] == 1,
                "inconsistent or cross-tenant statistics: {page}"
            );
            for item in page["items"].as_array().unwrap() {
                ids.push(item["id"].as_str().unwrap().to_owned());
                ensure!(item["inventoryAvailable"] == false);
            }
            let Some(after) = page["nextCursor"].as_str() else {
                break;
            };
            path = format!("/api/v1/devices?limit=1&sort={sort}&cursor={after}");
            ensure!(ids.len() <= 3, "directory repeated page");
        }
        let mut expected = vec![pending, revoked, registered];
        if descending {
            expected.reverse();
        }
        ensure!(ids == expected, "directory order: {ids:?}");
    }
    let (_, detail) = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/devices/{revoked}"),
            None,
        )
        .await?;
    ensure!(detail["status"] == "revoked" && detail["channels"][0]["status"] == "revoked");
    ensure!(detail["capabilities"][0]["devicePrerequisite"]["reason"] == "not_registered");
    change_device_grants(&mut browser, pending, &["inventory_read"]).await?;
    let (_, page) = browser
        .call(&router, Method::GET, "/api/v1/devices?limit=1", None)
        .await?;
    let(_,statistics)=browser.call(&router,Method::GET,"/api/v1/devices/statistics",None).await?;
    ensure!(statistics["statistics"]["total"] == 1 && page["items"][0]["id"] == pending);
    for id in [revoked, case::name("absent")] {
        ensure!(
            browser
                .call(&router, Method::GET, &format!("/api/v1/devices/{id}"), None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
    }
    Ok(())
    }).await

    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_script_support_requires_signer_and_content() -> Result<()> {
    use crate::test_support::agent_execution::{Fixture, case_device_id};
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.authority.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let inventory = crate::inventory_runtime::InventoryRuntime::fixture(config.runtime_database.options()?, Arc::new(rss_mdm_inventory_service::Store::from_pool(fixture.authority.pool.clone())), tenant, monotonic(), fixture.authority.audit.clone()).await?;
    app_resources.resource(InventoryFixtureResource(inventory.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.authority.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(inventory, audit, runtime, tenant, Arc::new(crate::clock::SystemClock), &key, Arc::new(crate::automation::inventory_tasks::InventoryTasks)));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    app_resources.finish(async {
    let mut supported_router = None;
    for (signed, content) in [(true, true), (true, false), (false, true)] {
        let selected_content = if content { fixture.content.clone() } else { None };
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: false, protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: selected_content.clone(), signing_enabled: signed,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(fixture.authority.audit.clone())), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection: protection.clone() }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime.clone(), tenant, inputs, signed, content_available: selected_content.is_some(),
    }));
    let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(fixture.authority.registration.clone(), tenant.to_string(), fixture.authority.audit.clone()));
    let routes = rss_mdm_management_http::enrollment::directory::routes().with_state(Arc::new(rss_mdm_management_http::enrollment::directory::HttpState {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, devices, assets: assets.clone(), queries, windows: true, apple: false,
    }));
        let router = fixture.authority.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes))?;
        if signed && content { supported_router = Some(router.clone()); }
                        let (status, detail) = fixture
                            .author
                            .call(
                                &router,
                                Method::GET,
                                &format!("/api/v1/devices/{}", case_device_id()),
                                None,
                            )
                            .await?;
                        ensure!(
                            status == StatusCode::OK,
                            "capability detail signed={signed} content={content}: {status} {detail}"
                        );
                        let capability = detail["capabilities"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|v| v["action"] == "script")
                            .unwrap();
                        let supported = signed && content;
                        ensure!(
                            capability["productSupport"]["state"]
                                == if supported {
                                    "supported"
                                } else {
                                    "unsupported"
                                },
                            "script support signed={signed} content={content}: {capability}"
                        );
                        ensure!(
                            capability["productSupport"]["reason"]
                                == if supported {
                                    Value::Null
                                } else {
                                    json!("product_not_configured")
                                }
                        );
                        ensure!(
                            capability["devicePrerequisite"]["state"] == "ready"
                                && capability["permission"]["allowed"] == true,
                            "configuration merged device or permission facts: {capability}"
                        );
    }
            let grants = fixture
                .grants
                .iter()
                .filter(|grant| grant.operation != crate::authorization::Permission::ScriptExecute)
                .cloned()
                .collect();
            identity::change_grants(case_tenant(), &fixture.author_id, grants).await?;
            let (status, detail) = fixture
                .author
                .call(
                    supported_router.as_ref().expect("supported query"),
                    Method::GET,
                    &format!("/api/v1/devices/{}", case_device_id()),
                    None,
                )
                .await?;
            ensure!(status == StatusCode::OK);
            let capability = detail["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["action"] == "script")
                .unwrap();
            ensure!(
                capability["action"] == "script"
                    && capability["productSupport"]["state"] == "supported"
                    && capability["devicePrerequisite"]["state"] == "ready"
                    && capability["permission"]["allowed"] == false,
                "revocation merged capability facts: {capability}"
            );
    Ok(())
    }).await
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_metadata_filters_and_selectors() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(crate::planning::Planning::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone()))).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { planning: planning.clone(), groups }));
    let content = None;
    let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: content_access.clone() })));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: config.recovery_credentials.is_some(), protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: content.clone(), signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: planning.objects.clone(), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs: inputs.clone(), signed: false, content_available: content.is_some(),
    }));
    let policies = Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(&key, runtime.clone(), rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?, audit.clone(), tenant, Arc::new(rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?), inputs));
    let routes = routes.merge(rss_mdm_management_http::planning::policies::http::routes(queries, rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor")).with_state(policies));
    let routes = routes.merge(rss_mdm_management_http::workspace_routes());
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = prepared_subject(&browser)?;
    let mut grants = identity::device_grants(None, &["inventory_read", "device_unmanage"])?;
    for operation in ["group_read", "group_write", "scope_read", "scope_write",
        "resource_read", "resource_write", "policy_read", "policy_write"] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(operation))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::seed_grants(case_tenant(), &subject, grants).await?;
    let mut groups = [Uuid::new_v4(), Uuid::new_v4()];
    groups.sort();
    runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |c| Box::pin(async move {
            for (i, id) in groups.iter().enumerate() {
                sqlx::query("INSERT INTO mdm_group.groups(tenant_id,id,kind,presentation,revision,member_version,member_count,deleted,calculation_revision,asset_context) VALUES($1::uuid,$2,'static',$3,1,0,0,false,0,'endpoint')")
                    .bind(tenant.to_string()).bind(id).bind(json!({"name":format!("console-{i}"),"description":""})).execute(&mut *c).await?;
            }
            Ok(())
        })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    let (_, first) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/groups?limit=1&filter=kind==static",
            None,
        )
        .await?;
    ensure!(
        first["items"][0]["id"] == groups[0].to_string()
            && first["nextCursor"].is_string()
    );
    let (_, second) = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/groups?limit=1&filter=kind==static&cursor={}", first["nextCursor"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(second["items"][0]["id"] == groups[1].to_string() && second["nextCursor"].is_null());
    let (_, named) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/groups?filter=name=icontains=console-1&sort=-id",
            None,
        )
        .await?;
    ensure!(
        named["items"].as_array().unwrap().len() == 1
            && named["items"][0]["id"] == groups[1].to_string()
    );

    // Real SQL tie-breaking and projection-independent continuation for Scope and Policy.
    let mut scope_ids=[Uuid::new_v4(),Uuid::new_v4()];scope_ids.sort();
    let mut policy_ids=[Uuid::new_v4(),Uuid::new_v4()];policy_ids.sort();
    let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    for (scope,policy) in scope_ids.iter().zip(policy_ids.iter()) {
        crate::test_support::agent_execution::seed_scope(&planning, *scope, json!([])).await?;
        let change: rss_mdm_policy::Change = serde_json::from_value(json!({"action":"put","enabled":false,"definition":{"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}}))?;
        let changed = rss_mdm_policy::Policy::apply(*policy, None, 0, &change, Uuid::new_v4(), None)?;
        let frozen = rss_mdm_execution_service::frozen::Frozen::UnmanageDevice {
            schedule: match &changed.policy.definition.action { rss_mdm_policy::Action::UnmanageDevice { schedule, .. } => schedule.clone(), _ => unreachable!() }, run_lifetime_seconds: 300,
            actor: proof.actor(),
        };
        let publication = rss_mdm_policy_postgres::Publication { change, policy: changed.policy, frozen: Some(serde_json::to_value(frozen)?), author: json!({"subject":subject}), at: 1 };
        runtime.local_tx_with_context(tenant, crate::identity::deadline(), &publication, |p, tx| Box::pin(async move {
            rss_mdm_policy_postgres::fixture::published_in(tx, p).await
        })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    }
    for (family,ids) in [("scopes",scope_ids),("policies",policy_ids)] {
        let base=format!("/api/v1/{family}?filter=id=in=({},{});revision==1&sort=revision&fields=id&limit=1",ids[0],ids[1]);
        let (status,page)=browser.call(&router,Method::GET,&base,None).await?;
        ensure!(status==StatusCode::OK,"{family}: {page}");
        ensure!(page["items"]==json!([{"id":ids[0]}])&&page["nextCursor"].is_string());
        let cursor=page["nextCursor"].as_str().unwrap();
        let (status,last)=browser.call(&router,Method::GET,&format!("{base}&cursor={cursor}"),None).await?;
        ensure!(status==StatusCode::OK&&last["items"]==json!([{"id":ids[1]}])&&last["nextCursor"].is_null());
        ensure!(browser.call(&router,Method::GET,&format!("{}&cursor={cursor}",base.replace("fields=id","fields=revision")),None).await?.0==StatusCode::CONFLICT);
    }
    let resource = case::name("directory-script");
    runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
        rss_mdm_resource_postgres::fixture::resource_in(tx, rss_mdm_resource::Resource::new(tenant, rss_mdm_resource::Id::new(resource).expect("fixture id"), rss_mdm_resource::Kind::Script), 1)
                .await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    let (_, resources) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/resources?filter=kind==script;active==false",
            None,
        )
        .await?;
    ensure!(
        resources["items"][0]["id"] == resource
            && resources["items"][0]["kind"] == "script"
            && resources["items"][0]["activeVersion"].is_null()
    );
    for path in [
        "/api/v1/groups?kind=wrong",
        "/api/v1/resources?filter=kind==wrong",
        "/api/v1/policies?limit=0",
        "/api/v1/policies?action=wrong",
        "/api/v1/scopes?limit=1001",
    ] {
        ensure!(
            browser.call(&router, Method::GET, path, None).await?.0 == StatusCode::BAD_REQUEST,
            "accepted malformed query {path}"
        );
    }
    let (_, workspace) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/mdm-candidate/workspace",
            None,
        )
        .await?;
    ensure!(["devices", "policies", "software", "security", "operations"].iter().all(|id| workspace["modules"].as_array().unwrap().iter().any(|m| m["id"] == *id)), "required workspace modules missing: {workspace}");

    change_management_grants(&subject, json!([])).await?;
    let (_, workspace) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/mdm-candidate/workspace",
            None,
        )
        .await?;
    ensure!(
        workspace["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "policies")
            .unwrap()["available"]
            == false
    );
    ensure!(
        browser
            .call(
                &router,
                Method::GET,
                &format!("/api/v1/groups?filter=kind==static&cursor={}", first["nextCursor"].as_str().unwrap()),
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
    }).await

    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_scope_ready_tracks_current_admission() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
        let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(crate::planning::Planning::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone()))).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { planning: planning.clone(), groups }));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = prepared_subject(&browser)?;
    seed_management_grants(&subject, json!(["scope_read", "scope_write"])).await?;
    let scope = Uuid::new_v4();
    let path = format!("/api/v1/scopes/{scope}");
    let owner = start_automation(&fixture.base).await?;
    call(
        &mut browser,
        &router,
        &path,
        0,
        json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_ingress().await?;
    let fresh = browser
        .call(&router, Method::GET, "/api/v1/scopes?filter=ready==true", None)
        .await?;
    ensure!(
        fresh.0 == StatusCode::OK && fresh.1["items"][0]["id"] == scope.to_string(),
        "fresh scope: {fresh:?}"
    );
    stop_worker(owner).await?;
    let changed = browser.call(&router, Method::POST, &path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":{"targets":[],"limitations":[],"exclusions":[]}}}))).await?;
    ensure!(changed.0 == StatusCode::OK, "scope update: {changed:?}");
    ensure!(pg(&format!("SELECT resolution IS NOT NULL FROM mdm_planning.scopes WHERE tenant_id='{}' AND id='{scope}'", case_tenant()))?.trim() == "t", "fixture lost historical resolution");
    let fresh = browser
        .call(&router, Method::GET, "/api/v1/scopes?filter=ready==true", None)
        .await?;
    let stale = browser
        .call(&router, Method::GET, "/api/v1/scopes?filter=ready==false", None)
        .await?;
    ensure!(
        fresh.0 == StatusCode::OK && fresh.1["items"] == json!([]),
        "stale scope listed ready: {fresh:?}"
    );
    ensure!(
        stale.0 == StatusCode::OK && stale.1["items"][0]["id"] == scope.to_string(),
        "stale scope missing: {stale:?}"
    );
    let owner = start_automation(&fixture.base).await?;
    await_task(
        &mut browser,
        &router,
        &format!("{path}/tasks/{}", changed.1["task"].as_str().unwrap()),
    )
    .await?;
    await_ingress().await?;
    let fresh = browser
        .call(&router, Method::GET, "/api/v1/scopes?filter=ready==true", None)
        .await?;
    ensure!(
        fresh.0 == StatusCode::OK && fresh.1["items"][0]["id"] == scope.to_string(),
        "recalculated scope: {fresh:?}"
    );
    stop_worker(owner).await?;
    Ok(())
    }).await

    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn planning_routes_and_derived_result_authorization() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let devices = [case::name("device-1"), case::name("device-2")];
        for device in devices {
            pg(&format!("INSERT INTO mdm_access.devices VALUES('{}','{device}')", case_tenant()))?;
            inventory::seed_source(device, "mdm", "mdm.windows", "Model-A")?;
        }
        let automation = start_automation(&fixture.base).await?;
        await_ingress().await?;
            let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(crate::planning::Planning::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone()))).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { planning: planning.clone(), groups }));
    let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(store) = &content { app_resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
    let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: content_access.clone() })));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: config.recovery_credentials.is_some(), protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: content.clone(), signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: planning.objects.clone(), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs: inputs.clone(), signed: false, content_available: content.is_some(),
    }));
    let policies = Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(&key, runtime.clone(), rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?, audit.clone(), tenant, Arc::new(rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?), inputs));
    let routes = routes.merge(rss_mdm_management_http::planning::policies::http::routes(queries, rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor")).with_state(policies));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;

        app_resources.finish(async {
            let mut browser = fixture.browser("other")?;
            let member = prepared_subject(&browser)?;
            seed_management_grants(&member, json!(["group_read","group_write","group_recompute","scope_read","scope_write","policy_read","policy_write","resource_read","resource_write"])).await?;
            let group = uuid::Uuid::new_v4();
            let scope = uuid::Uuid::new_v4();
            let policy = uuid::Uuid::new_v4();
            let resource = uuid::Uuid::new_v4();
            let group_path = format!("/api/v1/groups/{group}");
            call(&mut browser,&router,&group_path,0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"authorized-results","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}}})).await?;
            let accepted = call(&mut browser, &router, &format!("{group_path}/previews"), 1, json!({})).await?;
            let scoped = call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":devices.map(|id|json!({"kind":"device","id":id})),"limitations":null,"exclusions":[]}})).await?;
            native_configuration_resource(&planning.runtime, planning.tenant, content.as_deref().expect("native content"), resource, "windows", "x86_64", windows_configuration()).await?;
            let mut grants = identity::device_grants(None, &["inventory_read", "configuration_write"])?;
            for permission in ["group_read","group_write","group_recompute","scope_read","scope_write","policy_read","policy_write","resource_read","resource_write"] {
                grants.push(crate::authorization::Grant { operation: serde_json::from_value(json!(permission))?, scope: crate::authorization::Scope::Tenant });
            }
            identity::change_grants(case_tenant(), &member, grants).await?;
            let policy_path = format!("/api/v1/policies/{policy}");
            call(&mut browser,&router,&policy_path,0,json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}}})).await?;
            let referenced_scope = format!("SELECT json_build_array(s.deleted,s.revision,p.definition->>'scope') FROM mdm_planning.scopes s JOIN mdm_policy.policies p ON p.tenant_id=s.tenant_id AND p.id='{policy}' WHERE s.tenant_id='{}' AND s.id='{scope}'", case_tenant());
            let before: Value = serde_json::from_str(pg(&referenced_scope)?.trim())?;
            ensure!(before == json!([false, 1, scope.to_string()]), "referenced scope fixture: {before}");
            let denied = browser.call(&router, Method::POST, &format!("/api/v1/scopes/{scope}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}}))).await?;
            ensure!(denied.0 == StatusCode::CONFLICT, "referenced scope deletion: {denied:?}");
            let after: Value = serde_json::from_str(pg(&referenced_scope)?.trim())?;
            ensure!(after == before, "rejected deletion changed scope or policy reference: {after}");
            derived_result_authorization(&mut browser,&router,&member,&group_path,accepted["task"].as_str().unwrap(),scope,scoped["task"].as_str().unwrap(),&policy_path).await?;
            Ok(())
        }).await?;
        crate::test_support::runtime::stop_worker(automation).await?;
        Ok(())
    }).await
}
#[allow(clippy::too_many_arguments)]
async fn derived_result_authorization(
    browser: &mut Browser,
    router: &Router,
    member: &str,
    group: &str,
    group_result: &str,
    scope: uuid::Uuid,
    scope_result: &str,
    policy: &str,
) -> Result<()> {
    let permissions = json!([
        "group_read",
        "group_write",
        "group_recompute",
        "scope_read",
        "scope_write",
        "policy_read",
        "policy_write",
        "resource_read",
        "resource_write"
    ]);
    let absent = uuid::Uuid::new_v4();
    for (route, code) in [
        (
            format!("/api/v1/policies/{absent}/assignments"),
            "policy_not_found",
        ),
        (
            format!("/api/v1/groups/{absent}/results/{group_result}/members"),
            "group_not_found",
        ),
        (
            format!("{group}/results/{absent}/members"),
            "group_not_found",
        ),
        (
            format!("/api/v1/scopes/{absent}/results/{scope_result}/members?channel=mdm"),
            "scope_not_found",
        ),
        (
            format!("/api/v1/scopes/{scope}/results/{absent}/members?channel=mdm"),
            "scope_not_found",
        ),
    ] {
        let response = browser.call(router, Method::GET, &route, None).await?;
        ensure!(
            response.0 == StatusCode::NOT_FOUND && response.1["code"] == code,
            "planning missing result {route}: {response:?}"
        );
    }
    let mut paths = vec![
        format!("{group}/tasks/{group_result}"),
        format!("/api/v1/scopes/{scope}/tasks/{scope_result}"),
        format!("{policy}/assignments"),
    ];
    paths.push(format!("{group}/results/{group_result}/members?limit=1"));
    paths.push(format!(
        "/api/v1/scopes/{scope}/results/{scope_result}/members?channel=mdm&limit=1"
    ));
    // Keep an actually issued cursor, then shrink the subject's device access.
    let (status, page) = Box::pin(browser.call(router, Method::GET, &paths[3], None)).await?;
    ensure!(status == StatusCode::OK, "authorized derived page: {page}");
    let cursor = page["nextCursor"].as_str().unwrap();
    paths.push(format!("{}&cursor={cursor}", paths[3]));
    for limited in [false, true] {
        let mut grants = permissions
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                Ok(crate::authorization::Grant {
                    operation: serde_json::from_value(p.clone())?,
                    scope: crate::authorization::Scope::Tenant,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if limited {
            grants.extend(crate::test_support::identity::device_grants(
                Some(crate::test_support::case::name("device-1")),
                &["inventory_read"],
            )?);
        }
        Box::pin(crate::test_support::identity::change_grants(
            case_tenant(),
            member,
            grants,
        ))
        .await?;
        for path in &paths {
            let (status, body) = Box::pin(browser.call(router, Method::GET, path, None)).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "derived page leaked after inventory grant shrink at {path}: {status} {body}"
            );
        }
    }
    Box::pin(change_management_grants(member, permissions)).await?;
    for path in &paths {
        let (status, body) = Box::pin(browser.call(router, Method::GET, path, None)).await?;
        ensure!(
            status == StatusCode::OK,
            "restored full inventory grant: {path} {status} {body}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn collection_blueprints_instantiate_replay_and_keep_tenant_versions() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let routes = rss_mdm_http_contract::Router::new();
    let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(store) = &content { app_resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
    let resource_catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: resource_catalog.clone(), content: content_access.clone() })));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;

    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = prepared_subject(&browser)?;
    seed_management_grants(&subject, json!(["resource_read", "resource_write"])).await?;
    let catalog = browser
        .call(&router, Method::GET, "/api/v1/collection-blueprints", None)
        .await?;
    ensure!(catalog.0 == StatusCode::OK);
    ensure!(
        catalog.1["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == "windows.software.win32")
    );
    let path = format!("/api/v1/resources/{}", uuid::Uuid::new_v4());
    let body = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"instantiate","blueprint":"macos.hardware","version":"1"}});
    // Fail after the resource commit, then resume the same operation with content enabled.
    let unavailable_content = rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant),
        authorization: fixture.authorization.clone(), runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: None,
        clock: Arc::new(crate::clock::ContentClock(clock.clone())), catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    };
    let unavailable = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: resource_catalog.clone(), content: Arc::new(unavailable_content) }))))?;
    let app_resources = Resources::default();
    app_resources.finish(async {
    let interrupted = settled_write(&mut browser, &unavailable, &path, body.clone()).await?;
    ensure!(
        !interrupted.0.is_success(),
        "missing content falsely completed instantiation"
    );
    let committed = browser.call(&router, Method::GET, &path, None).await?;
    ensure!(committed.0 == StatusCode::OK && committed.1["revision"] == 2);
    let first = settled_write(&mut browser, &router, &path, body.clone()).await?;
    ensure!(
        first.0 == StatusCode::OK,
        "blueprint instantiation: {first:?}"
    );
    ensure!(first.1["revision"] == 2 && first.1["origin"]["blueprint"] == "macos.hardware");
    ensure!(settled_write(&mut browser, &router, &path, body).await? == first);
    let mut variants = first.1["versions"][0]["variants"].clone();
    for variant in variants.as_array_mut().unwrap() {
        let definition = &mut variant["declaration"]["definition"];
        definition["mappings"]["device.hardware.apple.model_name"]["query"] = json!("ModelNumber");
        let parsed: rss_mdm_resource::NativeCollectionDefinition =
            serde_json::from_value(definition.clone())?;
        let bytes = parsed.canonical();
        variant["declaration"]["artifact"]["length"] = json!(bytes.len());
        variant["declaration"]["artifact"]["sha256"] =
            json!(rss_mdm_resource::Digest::of(&bytes).bytes());
    }
    call(&mut browser, &router, &path, 2, json!({"action":"version","kind":"native_collection","version":"tenant-v2","variants":variants})).await?;
    let current = browser.call(&router, Method::GET, &path, None).await?;
    ensure!(current.0 == StatusCode::OK && current.1["versions"].as_array().unwrap().len() == 2);
    ensure!(current.1["origin"] == first.1["origin"]);
    let candidate = format!("/api/v1/resources/{}", uuid::Uuid::new_v4());
    call(
        &mut browser,
        &router,
        &candidate,
        0,
        json!({"action":"instantiate","blueprint":"macos.hardware","version":"1"}),
    )
    .await?;
    ensure!(browser.call(&router, Method::GET, &path, None).await? == current);
    let directory = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/resources?filter=kind==native_collection",
            None,
        )
        .await?;
    ensure!(directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 2);
    {
        let id = "windows.agent.certificates_device_my";
        let target=format!("/api/v1/resources/{}",uuid::Uuid::new_v4());
        let input=json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"instantiate","blueprint":id,"version":"1"}});
        let created=settled_write(&mut browser,&router,&target,input.clone()).await?;
        ensure!(created.0==StatusCode::OK,"Agent blueprint: {created:?}");
        ensure!(settled_write(&mut browser,&router,&target,input).await?==created);
        let variants=created.1["versions"][0]["variants"].clone();
        call(&mut browser,&router,&target,2,json!({"action":"version","kind":"agent_collection","version":"tenant-copy","variants":variants})).await?;
        let customized=browser.call(&router,Method::GET,&target,None).await?;
        let another=format!("/api/v1/resources/{}",uuid::Uuid::new_v4());
        call(&mut browser,&router,&another,0,json!({"action":"instantiate","blueprint":id,"version":"1"})).await?;
        ensure!(browser.call(&router,Method::GET,&target,None).await?==customized);
    }
    change_management_grants(&subject, json!([])).await?;
    ensure!(
        browser
            .call(&router, Method::GET, "/api/v1/collection-blueprints", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
    }).await
    }).await

    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn reverse_memberships_revalidate_authority_after_request_snapshot() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let browser = fixture.browser("other")?;
            let subject = prepared_subject(&browser)?;
            let mut grants = identity::device_grants(None, &["inventory_read"])?;
            grants.push(crate::authorization::Grant {
                operation: crate::authorization::Permission::GroupRead,
                scope: crate::authorization::Scope::Tenant,
            });
            identity::seed_grants(case_tenant(), &subject, grants).await?;
            let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
            proof.manage(crate::authorization::Permission::GroupRead)?;
            proof.require_all_devices(crate::authorization::Permission::InventoryRead)?;
            let planning =
                crate::planning::test_support::planning(crate::planning::test_support::tenant())
                    .await;
            let groups = rss_mdm_inventory_service::groups::Groups {
                reconcile_messaging: planning.reconcile_messaging.clone(),
                objects: planning.objects.clone(),
                tenant: planning.tenant,
                groups: planning.groups.clone(),
                cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[9; 32]),
                audit_store: planning.audit_store.clone(),
                runtime: planning.runtime.clone(),
                clock: Arc::new(crate::clock::InventoryClock(Arc::new(
                    crate::clock::SystemClock,
                ))),
            };
            identity::change_grants(case_tenant(), &subject, vec![]).await?;
            // The same proof still contains both old grants. The transaction must reject before existence reads.
            let audit = rss_mdm_audit_integration::RequestAudit::new(
                case_tenant().into(),
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            proof.bind_audit(&audit)?;
            let result = groups
                .memberships(
                    &proof,
                    "not-present",
                    &rss_mdm_inventory_service::groups::memberships::SCHEMA
                        .parse("limit=1")
                        .unwrap()
                        .0,
                    &audit,
                )
                .await;
            audit.finalize(None);
            planning.runtime.close().await;
            ensure!(
                matches!(result, Err(rss_mdm_inventory_service::Error::Forbidden)),
                "stale request authority: {result:?}"
            );
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn nested_groups_sources_references_and_authorized_pages() -> Result<()> {
    use anyhow::Context;
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let devices=[case::name("nested-a"),case::name("nested-b")];
        for (device,model) in devices.iter().zip(["Model-A","Model-B"]) {inventory::seed_source(device,"mdm","mdm.windows",model)?;}
        let worker=start_automation(&fixture.base).await?;
        await_ingress().await?;
            let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(crate::planning::Planning::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone()))).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { planning: planning.clone(), groups }));
    let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(store) = &content { app_resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
    let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: content_access.clone() })));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: config.recovery_credentials.is_some(), protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: content.clone(), signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: planning.objects.clone(), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs: inputs.clone(), signed: false, content_available: content.is_some(),
    }));
    let policies = Arc::new(rss_mdm_flow_service::planning::policies::Policies::new(&key, runtime.clone(), rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?, audit.clone(), tenant, Arc::new(rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?), inputs));
    let routes = routes.merge(rss_mdm_management_http::planning::policies::http::routes(queries, rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor")).with_state(policies));
    let routes = routes.merge(rss_mdm_management_http::compliance::http::routes().with_state(crate::planning::test_support::compliance(&planning).await));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;

        app_resources.finish(async {
            let mut browser=fixture.browser("other")?;
            let subject=prepared_subject(&browser)?;
            let mut grants=identity::device_grants(None,&["inventory_read","configuration_write"])?;
            for name in ["group_read","group_write","group_recompute","scope_read","scope_write","compliance_rule_read","compliance_write","policy_read","policy_write","resource_read","resource_write"] {
                grants.push(crate::authorization::Grant {operation:serde_json::from_value(json!(name))?,scope:crate::authorization::Scope::Tenant});
            }
            identity::seed_grants(case_tenant(),&subject,grants.clone()).await?;
            let source=Uuid::new_v4();let nested=Uuid::new_v4();let grandparent=Uuid::new_v4();let scope=Uuid::new_v4();let compliance=Uuid::new_v4();
            let path=|id|format!("/api/v1/groups/{id}");
            let condition=|criteria:Value|json!({"selector":{"kind":"device"},"quantifier":"one","criteria":criteria});
            let reference=|id,op|json!({"kind":"group","groupId":id,"op":op});
            call(&mut browser,&router,&path(source),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"nested-source","description":""},"criteria":condition(json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}))})).await?;
            let without_read: Vec<_> = grants.iter().filter(|g| g.operation != crate::authorization::Permission::GroupRead).cloned().collect();
            identity::change_grants(case_tenant(),&subject,without_read).await?;
            let rejected=browser.call(&router,Method::POST,&path(nested),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","assetContext":"endpoint","presentation":{"name":"denied-reference","description":""},"criteria":condition(reference(source,"member_of"))}}))).await?;
            ensure!(rejected.0==StatusCode::FORBIDDEN,"group reference without GroupRead: {rejected:?}");
            identity::change_grants(case_tenant(),&subject,grants.clone()).await?;
            for (id,target) in [(nested,source),(grandparent,nested)] {
                call(&mut browser,&router,&path(id),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"nested-parent","description":""},"criteria":condition(reference(target,"member_of"))})).await?;
                let (_,read)=browser.call(&router,Method::GET,&path(id),None).await?;
                ensure!(read["group"]["memberCount"]==1,"nested result: {read}");
                ensure!(read["criteria"]["criteria"]["groupId"]==target.to_string());
            }
            let before_preview=browser.call(&router,Method::GET,&path(nested),None).await?.1["memberSet"].clone();
            let preview=call(&mut browser,&router,&format!("{}/previews",path(nested)),1,json!({})).await?;
            let result=preview["task"].as_str().context("preview task")?;
            let page=browser.call(&router,Method::GET,&format!("{}/results/{result}/members",path(nested)),None).await?;
            ensure!(page.0==StatusCode::OK && page.1["totalMembers"]==1 && page.1["current"]==false && page.1["sources"][0]["group"]==source.to_string(),"nested preview source evidence: {page:?}");
            ensure!(browser.call(&router,Method::GET,&path(nested),None).await?.1["memberSet"]==before_preview,"preview published membership");
            call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":grandparent}],"limitations":null,"exclusions":[]}})).await?;
            let definition=json!({"presentation":{"name":"disabled-reference","description":""},"severity":"high","enabled":false,"platform":"all","target":{"kind":"groups","ids":[source]},"criteria":condition(json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}))});
            let result=browser.call(&router,Method::PUT,&format!("/api/v1/compliance-rules/{compliance}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":definition}))).await?;
            ensure!(result.0==StatusCode::OK,"compliance setup: {result:?}");
            await_ingress().await?;
            let resource=Uuid::new_v4();let policy=Uuid::new_v4();
            native_configuration_resource(&planning.runtime, planning.tenant, content.as_deref().expect("native content"),resource,"windows","x86_64",windows_configuration()).await?;
            call(&mut browser,&router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":false,"definition":{"scope":scope,"action":{"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}}})).await?;
            await_ingress().await?;
            let refs=format!("{}/references",path(source));
            let (status,first)=browser.call(&router,Method::GET,&format!("{refs}?limit=1"),None).await?;
            ensure!(status==StatusCode::OK&&first["items"].as_array().is_some_and(|i|i.len()==1),"reference page: {status} {first}");
            let token=first["nextCursor"].as_str().context("missing continuation")?.to_owned();
            let mut items=first["items"].as_array().unwrap().clone();let mut next=Some(token.clone());
            while let Some(cursor)=next {
                let (status,page)=browser.call(&router,Method::GET,&format!("{refs}?limit=1&cursor={cursor}"),None).await?;
                ensure!(status==StatusCode::OK,"page continuation: {status} {page}");
                items.extend(page["items"].as_array().context("missing items")?.iter().cloned());
                next=page["nextCursor"].as_str().map(str::to_owned);
            }
            ensure!(items.len()==5,"complete graph: {items:?}");
            ensure!(items.iter().any(|i|i["source"]["id"]==policy.to_string()&&i["relation"]=="indirect"&&i["lifecycleState"]=="disabled"));
            ensure!(items.iter().any(|i|i["source"]["id"]==scope.to_string()&&i["relation"]=="indirect"));
            ensure!(items.iter().any(|i|i["source"]["id"]==compliance.to_string()&&i["lifecycleState"]=="disabled"&&i["blocksDeletion"]==true));
            ensure!(browser.call(&router,Method::GET,&format!("{}/references?cursor={token}",path(nested)),None).await?.0==StatusCode::CONFLICT);
            let (status,select)=browser.call(&router,Method::GET,&format!("/api/v1/groups?referenceableFor={source}"),None).await?;
            ensure!(status==StatusCode::OK,"reference selector {status} {select}");
            ensure!(!select["items"].as_array().unwrap().iter().any(|g|g["id"]==source.to_string()));
            // Saved cycles and cross-context references are rejected transactionally.
            for (id,revision,input) in [(source,1,json!({"action":"rule","criteria":condition(reference(grandparent,"member_of"))})),(Uuid::new_v4(),0,json!({"action":"create","assetContext":"associated_device","presentation":{"name":"wrong-context","description":""},"criteria":condition(reference(source,"member_of"))}))] {
                let (accepted,job)=browser.call(&router,Method::POST,&path(id),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input}))).await?;
                ensure!(accepted==StatusCode::ACCEPTED);
                tokio::time::timeout(Duration::from_secs(30),async {loop {let state=browser.call(&router,Method::GET,job["statusUrl"].as_str().unwrap(),None).await?.1;if state["failure"]=="invalid_input" {break Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(20)).await;}}).await??;
            }
            ensure!(browser.call(&router,Method::POST,&path(source),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}}))).await?.0==StatusCode::CONFLICT);
            // An input definition edit invalidates continuation, even before a worker recomputes it.
            call(&mut browser,&router,&path(nested),1,json!({"action":"rule","criteria":condition(reference(source,"not_member_of"))})).await?;
            await_ingress().await?;
            ensure!(browser.call(&router,Method::GET,&format!("{refs}?limit=1&cursor={token}"),None).await?.0==StatusCode::CONFLICT);
            let (_,read)=browser.call(&router,Method::GET,&path(grandparent),None).await?;
            ensure!(read["group"]["memberCount"]==1,"negative propagated: {read}");
            let result=read["memberSet"].as_str().context("missing nested member set")?;
            let (_,members)=browser.call(&router,Method::GET,&format!("{}/results/{result}/members",path(grandparent)),None).await?;
            ensure!(members["page"]["items"]==json!([{"kind":"endpoint","id":devices[1]}]),"negative membership identity: {members}");
            let manual=Uuid::new_v4();let manual_negative=Uuid::new_v4();
            call(&mut browser,&router,&path(manual),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"manual-source","description":""},"criteria":null})).await?;
            call(&mut browser,&router,&path(manual),1,json!({"action":"members","add":[{"kind":"endpoint","id":devices[0]}],"remove":[]})).await?;
            call(&mut browser,&router,&path(manual_negative),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"negative-manual","description":""},"criteria":condition(reference(manual,"not_member_of"))})).await?;
            let (_,manual_read)=browser.call(&router,Method::GET,&path(manual_negative),None).await?;
            ensure!(manual_read["group"]["memberCount"]==1,"static source complement: {manual_read}");
            // No positive member diff: Unknown becomes NoMatch and must still wake a negated dependent.
            let unknown=Uuid::new_v4();let negative=Uuid::new_v4();
            call(&mut browser,&router,&path(unknown),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"unknown-source","description":""},"criteria":condition(json!({"kind":"predicate","field":"device.os.version","op":"eq","value":{"kind":"string","value":"never"}}))})).await?;
            call(&mut browser,&router,&path(negative),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"negative-unknown","description":""},"criteria":condition(reference(unknown,"not_member_of"))})).await?;
            let (_,before)=browser.call(&router,Method::GET,&path(negative),None).await?;ensure!(before["group"]["memberCount"]==0,"Unknown was negated: {before}");
            call(&mut browser,&router,&path(unknown),1,json!({"action":"rule","criteria":condition(json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"never"}}))})).await?;
            await_ingress().await?;
            let (_,after)=browser.call(&router,Method::GET,&path(negative),None).await?;ensure!(after["group"]["memberCount"]==2,"NoMatch did not propagate: {after}");
            let right=Uuid::new_v4();let diamond=Uuid::new_v4();
            call(&mut browser,&router,&path(right),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"diamond-right","description":""},"criteria":condition(reference(source,"member_of"))})).await?;
            call(&mut browser,&router,&path(diamond),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"diamond-top","description":""},"criteria":condition(json!({"kind":"and","children":[reference(nested,"member_of"),reference(right,"not_member_of")]}))})).await?;
            await_ingress().await?;
            let (_,diamond_refs)=browser.call(&router,Method::GET,&format!("{refs}?kind=group&relation=indirect"),None).await?;
            let diamond_entry=diamond_refs["items"].as_array().context("diamond items")?.iter().find(|i|i["source"]["id"]==diamond.to_string()).context("diamond reference missing")?;
            ensure!(diamond_entry["roles"]==json!(["member_of","not_member_of"]),"lost diamond role: {diamond_entry}");
            // Obtain a valid cursor after every graph mutation, then change only authority.
            let (status,fresh)=browser.call(&router,Method::GET,&format!("{refs}?limit=1"),None).await?;
            ensure!(status==StatusCode::OK);let live_token=fresh["nextCursor"].as_str().context("fresh cursor missing")?.to_owned();
            ensure!(browser.call(&router,Method::GET,&format!("{refs}?limit=1&cursor={live_token}"),None).await?.0==StatusCode::OK);
            // Adding an unrelated grant leaves visible entries unchanged: view binding alone cannot reject this token.
            change_management_grants(&subject,json!(["group_read","group_write","group_recompute","scope_read","scope_write","compliance_rule_read","compliance_write","policy_read","policy_write","resource_read","resource_write","inventory_fields_write"])).await?;
            ensure!(browser.call(&router,Method::GET,&format!("{refs}?limit=1&cursor={live_token}"),None).await?.0==StatusCode::CONFLICT);
            // Current authority is checked on each page; absent category grants hide identities.
            change_management_grants(&subject,json!(["group_read","group_write","group_recompute"])).await?;
            let (status,filtered)=browser.call(&router,Method::GET,&refs,None).await?;
            ensure!(status==StatusCode::OK&&filtered["items"].as_array().unwrap().len()==4&&filtered["deletionBlocked"]==true,"filtered references: {status} {filtered}");
            ensure!(browser.call(&router,Method::GET,&format!("{refs}?kind=compliance_rule"),None).await?.0==StatusCode::FORBIDDEN);
            ensure!(browser.call(&router,Method::GET,&format!("{refs}?cursor={live_token}"),None).await?.0==StatusCode::CONFLICT);
            ensure!(browser.call(&router,Method::GET,&format!("{}/references",path(Uuid::new_v4())),None).await?.0==StatusCode::NOT_FOUND);
            Ok(())
        }).await?;
        stop_worker(worker).await?;Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn resource_query_executes_filter_sort_projection_and_bound_continuations() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let routes = rss_mdm_http_contract::Router::new();
    let content = None;
    let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: content_access.clone() })));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.authorization()))?;
        app_resources.finish(async {
            let mut browser = fixture.browser("other")?;
            let subject = prepared_subject(&browser)?;
            seed_management_grants(&subject,json!(["resource_read","resource_write"])).await?;
            let ids=[case::name("query-a"),case::name("query-b"),case::name("query-c"),case::name("query-d"),case::name("query-e")];
            for (index,(id,kind)) in ids.iter().zip([rss_mdm_resource::Kind::Script,rss_mdm_resource::Kind::Software,rss_mdm_resource::Kind::Script,rss_mdm_resource::Kind::Configuration,rss_mdm_resource::Kind::Script]).enumerate() {
                let mut resource = rss_mdm_resource::Resource::new(tenant,rss_mdm_resource::Id::new(*id)?,kind);
                let mut presentation=json!({"name":id,"extension":{"kept":true}});
                if index==2 {presentation["changed"]=json!(true);}
                resource.set_presentation(presentation.as_object().unwrap().clone())?;
                runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
                    rss_mdm_resource_postgres::fixture::resource_in(tx,resource,if index==2 {3}else{2}).await
                })).await.fold(Ok, Err, Err, Err, Err, Err)?;
            }
            // A foreign tenant's same-ID header must never enter this tenant's page.
            pg(&format!("WITH peer AS (SELECT convert_to(jsonb_set(convert_from(document,'UTF8')::jsonb,'{{1}}',to_jsonb('{}'::text))::text,'UTF8') AS document FROM mdm_resource.aggregates WHERE tenant_id='{}' AND id='{}') INSERT INTO mdm_resource.aggregates(tenant_id,id,revision,document,digest) SELECT '{}','{}',99,document,sha256(document) FROM peer",case::peer(),case_tenant(),ids[0],case::peer(),ids[0]))?;
            let tenant=rss_request_context::TenantId::parse(case_tenant())?;
            let active=case::name("query-active");
            let blueprint=rss_mdm_resource::blueprints::get("windows.identity","1").unwrap();
            let version=blueprint.instantiate(tenant,rss_mdm_resource::Id::new(active)?)?;
            runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(tx,version,rss_contract::Timepoint::try_from(10_i64).unwrap()).await
            })).await.fold(Ok, Err, Err, Err, Err, Err)?;
            let mut candidates=ids.to_vec();candidates.push(active);
            let filter=format!("id=in=({});active==false",candidates.join(","));
            let uri=|filter:&str,sort:&str,fields:&str,limit:&str,cursor:Option<&str>| {
                let mut query=url::form_urlencoded::Serializer::new(String::new());
                query.extend_pairs([("filter",filter),("sort",sort),("fields",fields),("limit",limit)]);
                if let Some(cursor)=cursor{query.append_pair("cursor",cursor);}
                format!("/api/v1/resources?{}",query.finish())
            };
            let active_filter=format!("id=in=({});active==true",candidates.join(","));
            let only_active=browser.call(&router,Method::GET,&uri(&active_filter,"id","id,activeVersion","100",None),None).await?;
            ensure!(only_active.0==StatusCode::OK && only_active.1["items"].as_array().unwrap().len()==1
                && only_active.1["items"][0]["id"]==active && only_active.1["items"][0]["activeVersion"]==blueprint.label(),
                "active predicate was not selective: {only_active:?}");
            let sort="kind,-revision";
            let fields="id,revision,kind,presentation";
            let first=browser.call(&router,Method::GET,&uri(&filter,sort,fields,"2",None),None).await?;
            ensure!(first.0==StatusCode::OK,"query: {first:?}");
            ensure!(first.1["items"][0]["id"]==ids[3] && first.1["items"][1]["id"]==ids[2],"global multi-key order: {}",first.1);
            ensure!(first.1["items"][0]["presentation"]["extension"]["kept"]==true);
            ensure!(first.1["items"][0].as_object().unwrap().len()==4);
            let token=first.1["nextCursor"].as_str().unwrap().to_owned();
            ensure!(token!=ids[2],"cursor exposed the former ID-only continuation");
            let second=browser.call(&router,Method::GET,&uri(&filter,sort,fields,"1",Some(&token)),None).await?;
            ensure!(second.0==StatusCode::OK && second.1["items"][0]["id"]==ids[0],"equal sort values need ID tie-break: {second:?}");
            let third=browser.call(&router,Method::GET,&uri(&filter,sort,fields,"2",second.1["nextCursor"].as_str()),None).await?;
            ensure!(third.0==StatusCode::OK && third.1["items"][0]["id"]==ids[4] && third.1["items"][1]["id"]==ids[1] && third.1["nextCursor"].is_null(),"terminal page: {third:?}");
            let scripts=format!("id=in=({});kind==script;revision=ge=2",ids.join(","));
            let projected=browser.call(&router,Method::GET,&uri(&scripts,"-id","presentation","1",None),None).await?;
            ensure!(projected.0==StatusCode::OK && projected.1["items"][0].as_object().unwrap().len()==1 && projected.1["items"][0]["presentation"]["name"]==ids[4]);
            let projected_next=browser.call(&router,Method::GET,&uri(&scripts,"-id","presentation","10",projected.1["nextCursor"].as_str()),None).await?;
            ensure!(projected_next.0==StatusCode::OK && projected_next.1["items"].as_array().unwrap().len()==2 && projected_next.1["items"][0]["presentation"]["name"]==ids[2] && projected_next.1["items"][1]["presentation"]["name"]==ids[0] && projected_next.1["nextCursor"].is_null(),"projection removed seek data: {projected_next:?}");
            let empty=browser.call(&router,Method::GET,&uri("revision=lt=0","id","id","1",None),None).await?;
            ensure!(empty.0==StatusCode::OK && empty.1["items"]==json!([]) && empty.1["nextCursor"].is_null());
            for query in [uri(&filter,"-id",fields,"2",Some(&token)),uri(&filter,sort,"id","2",Some(&token)),uri(&scripts,sort,fields,"2",Some(&token))] {
                let rejected=browser.call(&router,Method::GET,&query,None).await?;
                ensure!(rejected.0==StatusCode::CONFLICT && rejected.1["code"]=="resource_cursor_invalidated","context accepted or wrong error: {rejected:?}");
            }
            for raw in ["sort=active","fields=","filter=kind==bogus","filter=id==%27x%27%20OR%201=1","limit=1&limit=2","filter=id==%FF","filter=id==a*","after=x","filter=active=gt=false"] {
                ensure!(browser.call(&router,Method::GET,&format!("/api/v1/resources?{raw}"),None).await?.0==StatusCode::BAD_REQUEST,"invalid query accepted: {raw}");
            }
            change_management_grants(&subject,json!(["resource_read","resource_write","scope_read"])).await?;
            ensure!(browser.call(&router,Method::GET,&uri(&filter,sort,fields,"2",Some(&token)),None).await?.0==StatusCode::CONFLICT,"old authorization binding accepted");
            let stale=crate::device::test_support::admin(case_tenant(),"other-a").await?;
            stale.manage(crate::authorization::Permission::ResourceRead)?;
            let catalog=crate::flow::catalog(fixture.audit.clone(),runtime.clone(),tenant,
                Arc::new(crate::clock::SystemClock)).await?;
            change_management_grants(&subject,json!([])).await?;
            ensure!(browser.call(&router,Method::GET,&uri(&filter,sort,fields,"2",Some(&token)),None).await?.0==StatusCode::FORBIDDEN,"cursor granted authority");
            let audit=rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(),"management_read", rss_mdm_audit_integration::AuditIntent::Routine);
            stale.bind_audit(&audit)?;
            let result=catalog.directory(&stale,&rss_mdm_resource::directory::Query::parse("limit=1")?,&audit).await;
            audit.finalize(None);
            ensure!(matches!(result,Err(rss_mdm_flow_service::Error::Forbidden)),"cached authorization survived revocation");
            Ok(())
        }).await
    }).await
}

#[tokio::test]
#[ignore = "MODULE=planning.http: current dataset inventory presence matches real asset reads"]
async fn console_inventory_presence_uses_current_dataset_authority() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
            let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
    let inventory = crate::inventory_runtime::InventoryRuntime::fixture(config.runtime_database.options()?, Arc::new(rss_mdm_inventory_service::Store::from_pool(fixture.pool.clone())), tenant, monotonic(), fixture.audit.clone()).await?;
    app_resources.resource(InventoryFixtureResource(inventory.clone()));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let assets = Arc::new(rss_mdm_inventory_service::assets::AssetService::new(inventory, audit, runtime, tenant, Arc::new(crate::clock::SystemClock), &key, Arc::new(crate::automation::inventory_tasks::InventoryTasks)));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: false, protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: None, signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_flow_service::planning::execution_source::ExecutionSource { objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(fixture.audit.clone())), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs, signed: false, content_available: false,
    }));
    let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(fixture.registration.clone(), tenant.to_string(), fixture.audit.clone()));
    let routes = rss_mdm_management_http::enrollment::directory::routes().with_state(Arc::new(rss_mdm_management_http::enrollment::directory::HttpState {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, devices, assets: assets.clone(), queries, windows: true, apple: false,
    }));
    let routes = routes.merge(rss_mdm_management_http::assets::routes().with_state(Arc::new(rss_mdm_management_http::assets::http::HttpState { assets })));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes).merge(fixture.enrollment()).merge(fixture.authorization()))?;

        app_resources.finish(async {
            let mut browser = fixture.browser("other")?;
            let device = case::name("dataset-presence");
            change_device_grants(&mut browser, device, &["inventory_read"]).await?;
            let (registration, epoch) = crate::test_support::inventory::seed_source(device, "agent", "agent.native", "old")?;
            pg(&format!("DELETE FROM mdm.inventory WHERE tenant_id='{}' AND registration='{registration}'", case_tenant()))?;
            let path = format!("/api/v1/devices/{device}");
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == false);
            let definition = crate::test_support::inventory::definition("presence-real-dataset", "agent.native", &[rss_mdm_inventory::builtin::MODEL]);
            crate::test_support::inventory::register_definition(&definition)?;
            let scope = crate::device::scope_dataset(rss_request_context::TenantId::parse(case_tenant())?, registration, "agent.native", epoch, definition.dataset())?.encode()?;
            let user_scope = rss_mdm_inventory::CollectionScope::MacosApplications {
                root: rss_mdm_inventory::ApplicationRoot::User, uid: Some(501),
            };
            let user_definition = rss_mdm_inventory::CollectionDefinition::new(
                "presence-user-dataset", "v1", rss_mdm_inventory::Source::AgentNative,
                vec![rss_mdm_inventory::CollectionField {
                    definition: definition.fields().next().unwrap().clone(), scope: user_scope.clone(),
                }],
            )?;
            crate::test_support::inventory::register_definition(&user_definition)?;
            let user_coordinate = crate::device::scope_dataset(rss_request_context::TenantId::parse(case_tenant())?, registration, "agent.native", epoch, user_definition.dataset())?.encode()?;
            let user_coverage = serde_json::to_string(&user_definition.coverage()?)?;
            let namespace = user_scope.canonical()?;
            pg(&format!("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,field_scope,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES('{}','mdm.observation.v1','inventory-projection-v1','{user_coordinate}','{user_coverage}','device.model','{namespace}','{{\"kind\":\"string\",\"value\":\"user-model\"}}','user-presence-test',1,2,'known','{registration}','agent.native','{epoch}',1)", case_tenant()))?;
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == false);
            let query = url::form_urlencoded::Serializer::new(String::new()).append_pair("scope", &namespace).finish();
            let user_inventory = browser.call(&router,Method::GET,&format!("{path}/inventory?{query}"),None).await?;
            ensure!(user_inventory.0 == StatusCode::OK && user_inventory.1["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == "user-model", "user inventory: {user_inventory:?}");
            let coverage = serde_json::to_string(&definition.coverage()?)?;
            pg(&format!("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,field_scope,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence) VALUES('{}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','device.model','{{\"kind\":\"device\"}}','{{\"kind\":\"string\",\"value\":\"current-model\"}}','presence-test',1,2,'known','{registration}','agent.native','{epoch}',1)", case_tenant()))?;
            let inventory = browser.call(&router,Method::GET,&format!("{path}/inventory"),None).await?;
            ensure!(inventory.0 == StatusCode::OK && inventory.1["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == "current-model", "inventory: {inventory:?}");
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == true);
            let page = browser.call(&router,Method::GET,"/api/v1/devices",None).await?;
            ensure!(page.1["items"][0]["inventoryAvailable"] == true, "directory: {page:?}");
            // Retained facts from a previous epoch are not current inventory.
            pg(&format!("UPDATE mdm_access.report_sources SET epoch=gen_random_uuid() WHERE tenant_id='{}' AND registration='{registration}'", case_tenant()))?;
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == false);
            pg(&format!("UPDATE mdm_access.report_sources SET epoch='{epoch}' WHERE tenant_id='{}' AND registration='{registration}'", case_tenant()))?;
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == true);
            pg(&format!("UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id='{}' AND registration='{registration}'", case_tenant()))?;
            ensure!(browser.call(&router,Method::GET,&path,None).await?.1["inventoryAvailable"] == false);
            Ok(())
        }).await
    }).await
}
