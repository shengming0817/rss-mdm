#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::test_support::planning_http::*;
use crate::test_support::*;
#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_collection_routes_reuse_current_policy() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            let (router, app_resources) = app(&fixture.base).await?;
            app_resources
                .finish(async {
                    let mut browser = fixture.browser("other")?;
                    let subject = browser_subject(&browser, &router).await?;
                    set_management_grants(
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
                    set_management_grants(&subject, json!([])).await?;
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
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let device = case::name("pending-console");
    set_device_grants(
        &mut browser,
        &router,
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
    ensure!(page["items"][0]["inventoryAvailable"] == false && page["statistics"]["total"] == 1);
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
    set_device_grants(&mut browser, &router, device, &["enrollment"]).await?;
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
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    identity::set_grants(
        case_tenant(),
        &subject,
        identity::device_grants(None, &["inventory_read", "enrollment", "credentials"])?,
    )
    .await?;
    let pending = case::name("a-pending");
    let revoked = case::name("b-revoked");
    let registered = case::name("c-registered");
    browser.operation = Some(Uuid::new_v4());
    ensure!(browser.call(&router,Method::POST,"/api/v1/enrollments",Some(json!({"deviceId":pending,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?.0==StatusCode::OK);
    let principal = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let service = rss_mdm_registration_service::DeviceService::new(
        fixture.access.registration(),
        case_tenant().into(),
        fixture.audit.clone(),
    );
    let credential = rss_mdm_registration_service::ChannelMount::new(
        rss_request_context::TenantId::parse(case_tenant())?,
        rss_mdm_inventory::ReportSource::MdmWindows,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .credential(crate::test_support::secret("console-agent"))?;
    let (_, receipt) =
        crate::device::test_support::bind(&service, &principal, &credential, revoked, 0).await?;
    service
        .revoke(&principal, revoked, receipt.registration, Uuid::new_v4())
        .await?;
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
        let mut path = format!("/api/v1/devices?limit=1&descending={descending}");
        let mut ids = Vec::new();
        loop {
            let (status, page) = browser.call(&router, Method::GET, &path, None).await?;
            ensure!(status == StatusCode::OK, "directory page: {status} {page}");
            ensure!(
                page["statistics"]["total"] == 3
                    && page["statistics"]["pending"] == 1
                    && page["statistics"]["revoked"] == 1,
                "inconsistent or cross-tenant statistics: {page}"
            );
            for item in page["items"].as_array().unwrap() {
                ids.push(item["id"].as_str().unwrap().to_owned());
                ensure!(item["inventoryAvailable"] == false);
            }
            let Some(after) = page["nextCursor"].as_str() else {
                break;
            };
            path = format!("/api/v1/devices?limit=1&descending={descending}&after={after}");
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
    set_device_grants(&mut browser, &router, pending, &["inventory_read"]).await?;
    let (_, page) = browser
        .call(&router, Method::GET, "/api/v1/devices?limit=1", None)
        .await?;
    ensure!(page["statistics"]["total"] == 1 && page["items"][0]["id"] == pending);
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
    resources
        .finish(async {
            fixture.register().await?;
            for (signed, content) in [(true, true), (true, false), (false, true)] {
                let mut config = fixture.base.clone();
                if !signed {
                    config["task_signing"] = Value::Null;
                    config["agent_pki"] = json!({"mode":"disabled"});
                }
                if !content {
                    config["content"] = Value::Null;
                }
                let (router, app_resources) = app(&config).await?;
                app_resources
                    .finish(async {
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
                        Ok(())
                    })
                    .await?;
            }
            let grants = fixture
                .grants
                .iter()
                .filter(|grant| grant.operation != crate::authorization::Permission::ScriptExecute)
                .cloned()
                .collect();
            identity::set_grants(case_tenant(), &fixture.author_id, grants).await?;
            let (status, detail) = fixture
                .author
                .call(
                    &fixture.router,
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
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_metadata_filters_and_selectors() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(
        &subject,
        json!([
            "group_read",
            "group_write",
            "scope_read",
            "scope_write",
            "resource_read",
            "resource_write",
            "policy_read"
        ]),
    )
    .await?;
    let mut groups = [Uuid::new_v4(), Uuid::new_v4()];
    groups.sort();
    for (i, id) in groups.iter().enumerate() {
        call(&mut browser,&router,&format!("/api/v1/groups/{id}"),0,json!({"action":"create","assetContext":"endpoint","name":format!("console-{i}"),"description":"","criteria":null})).await?;
    }
    let (_, first) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/groups?limit=1&kind=static",
            None,
        )
        .await?;
    ensure!(
        first["items"][0]["id"] == groups[0].to_string()
            && first["nextCursor"] == groups[0].to_string()
    );
    let (_, second) = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/groups?limit=1&after={}", groups[0]),
            None,
        )
        .await?;
    ensure!(second["items"][0]["id"] == groups[1].to_string() && second["nextCursor"].is_null());
    let (_, named) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/groups?name=console-1&descending=true",
            None,
        )
        .await?;
    ensure!(
        named["items"].as_array().unwrap().len() == 1
            && named["items"][0]["id"] == groups[1].to_string()
    );
    let resource = case::name("directory-script");
    call(
        &mut browser,
        &router,
        &format!("/api/v1/resources/{resource}"),
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    let (_, resources) = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/resources?kind=script&active=false",
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
        "/api/v1/resources?kind=wrong",
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
    ensure!(
        workspace["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["source"] == "real")
    );
    set_management_grants(&subject, json!([])).await?;
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
                &format!("/api/v1/groups?after={}", groups[0]),
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
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(&subject, json!(["scope_read", "scope_write"])).await?;
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
        .call(&router, Method::GET, "/api/v1/scopes?ready=true", None)
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
        .call(&router, Method::GET, "/api/v1/scopes?ready=true", None)
        .await?;
    let stale = browser
        .call(&router, Method::GET, "/api/v1/scopes?ready=false", None)
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
        .call(&router, Method::GET, "/api/v1/scopes?ready=true", None)
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
        let (router, app_resources) = app(&fixture.base).await?;
        app_resources.finish(async {
            let mut browser = fixture.browser("other")?;
            let member = browser_subject(&browser, &router).await?;
            set_management_grants(&member, json!(["group_read","group_write","group_recompute","scope_read","scope_write","policy_read","policy_write","resource_read","resource_write"])).await?;
            let group = uuid::Uuid::new_v4();
            let scope = uuid::Uuid::new_v4();
            let policy = uuid::Uuid::new_v4();
            let resource = uuid::Uuid::new_v4();
            let group_path = format!("/api/v1/groups/{group}");
            call(&mut browser,&router,&group_path,0,json!({"action":"create","assetContext":"endpoint","name":"authorized-results","description":"","criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}}})).await?;
            let accepted = call(&mut browser, &router, &format!("{group_path}/previews"), 1, json!({})).await?;
            let scoped = call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":devices.map(|id|json!({"kind":"device","id":id})),"limitations":null,"exclusions":[]}})).await?;
            native_configuration_resource(&mut browser, &router, resource, "windows", "x86_64", windows_configuration()).await?;
            let mut grants = identity::device_grants(None, &["inventory_read", "configuration_write"])?;
            for permission in ["group_read","group_write","group_recompute","scope_read","scope_write","policy_read","policy_write","resource_read","resource_write"] {
                grants.push(crate::authorization::Grant { operation: serde_json::from_value(json!(permission))?, scope: crate::authorization::Scope::Tenant });
            }
            identity::set_grants(case_tenant(), &member, grants).await?;
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
        crate::test_support::stop_worker(automation).await?;
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
        Box::pin(crate::test_support::identity::set_grants(
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
    Box::pin(set_management_grants(member, permissions)).await?;
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
    let (router, app_resources) = app(&fixture.base).await?;
    app_resources.finish(async {
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(&subject, json!(["resource_read", "resource_write"])).await?;
    let catalog = browser
        .call(&router, Method::GET, "/api/v1/collection-blueprints", None)
        .await?;
    ensure!(catalog.0 == StatusCode::OK && catalog.1["categories"].as_array().unwrap().len() == 6);
    ensure!(
        catalog.1["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == "windows.software.win32")
    );
    let path = format!("/api/v1/resources/{}", uuid::Uuid::new_v4());
    let body = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"instantiate","blueprint":"macos.hardware","version":"2"}});
    // Fail after the resource commit, then resume the same operation with content enabled.
    let mut without_content = fixture.base.clone();
    without_content["content"] = serde_json::Value::Null;
    let (unavailable, app_resources) = app(&without_content).await?;
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
        json!({"action":"instantiate","blueprint":"macos.hardware","version":"2"}),
    )
    .await?;
    ensure!(browser.call(&router, Method::GET, &path, None).await? == current);
    let directory = browser
        .call(
            &router,
            Method::GET,
            "/api/v1/resources?kind=native_collection",
            None,
        )
        .await?;
    ensure!(directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 2);
    for id in ["windows.agent.certificates_device_my","macos.agent.certificates_system"] {
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
    set_management_grants(&subject, json!([])).await?;
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
            let (router, app_resources) = app(&fixture.base).await?;
            app_resources
                .finish(async {
                    let browser = fixture.browser("other")?;
                    let subject = browser_subject(&browser, &router).await?;
                    let mut grants = identity::device_grants(None, &["inventory_read"])?;
                    grants.push(crate::authorization::Grant {
                        operation: crate::authorization::Permission::GroupRead,
                        scope: crate::authorization::Scope::Tenant,
                    });
                    identity::set_grants(case_tenant(), &subject, grants).await?;
                    let proof =
                        crate::device::test_support::admin(case_tenant(), "other-a").await?;
                    proof.manage(crate::authorization::Permission::GroupRead)?;
                    proof.require_all_devices(crate::authorization::Permission::InventoryRead)?;
                    let planning = crate::planning::test_support::planning(
                        crate::planning::test_support::tenant(),
                    )
                    .await;
                    let groups = rss_mdm_inventory_service::groups::Groups {
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
                    identity::set_grants(case_tenant(), &subject, vec![]).await?;
                    // The same proof still contains both old grants. The transaction must reject before existence reads.
                    let audit = rss_mdm_audit_integration::RequestAudit::new(
                        case_tenant().into(),
                        "management_read",
                    );
                    proof.bind_audit(&audit)?;
                    let result = groups
                        .memberships(
                            &proof,
                            "not-present",
                            &rss_mdm_inventory_service::groups::memberships::Query {
                                limit: 1,
                                cursor: None,
                            },
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
        })
        .await
}
