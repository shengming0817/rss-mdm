#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::test_support::planning_http::*;
use crate::test_support::*;
#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_collection_routes_reuse_current_policy() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let reader = authority::reader(&fixture.base).await?;
    let router = app(&fixture.base, reader).await?;
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(
        &subject,
        json!(["group_read", "scope_read", "policy_read", "resource_read"]),
    )
    .await?;
    for path in ["/api/v2/groups", "/api/v2/scopes", "/api/v4/resources"] {
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
    for path in ["/api/v2/groups", "/api/v2/scopes", "/api/v4/resources"] {
        ensure!(browser.call(&router, Method::GET, path, None).await?.0 == StatusCode::FORBIDDEN);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_pending_directory_and_permission_changes() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = app(&fixture.base, authority::reader(&fixture.base).await?).await?;
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
    let (status, enrollment) = browser.call(&router, Method::POST, "/api/v3/enrollments", Some(json!({"deviceId":device,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"agent.builtin"}))).await?;
    ensure!(
        status == StatusCode::OK,
        "enrollment: {status} {enrollment}"
    );
    let (status, page) = browser
        .call(&router, Method::GET, "/api/v3/devices?limit=1", None)
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
            &format!("/api/v3/devices/{device}"),
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
                .call(&router, Method::GET, &format!("/api/v3/devices/{id}"), None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
    }
    ensure!(
        browser
            .call(&router, Method::GET, "/api/v3/devices", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_directory_pages_registered_revoked_and_pending() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = app(&fixture.base, authority::reader(&fixture.base).await?).await?;
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
    ensure!(browser.call(&router,Method::POST,"/api/v3/enrollments",Some(json!({"deviceId":pending,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"agent.builtin"}))).await?.0==StatusCode::OK);
    let principal = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    let service = rss_mdm_registration_service::DeviceService::new(
        fixture.access.registration(),
        case_tenant().into(),
        fixture.audit.clone(),
    );
    let credential = rss_mdm_registration_service::ChannelMount::new(
        rss_request_context::TenantId::parse(case_tenant())?,
        rss_mdm_inventory::ReportSource::AgentBuiltin,
    )
    .credential(crate::test_support::secret("console-agent"));
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
        let mut path = format!("/api/v3/devices?limit=1&descending={descending}");
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
            path = format!("/api/v3/devices?limit=1&descending={descending}&after={after}");
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
            &format!("/api/v3/devices/{revoked}"),
            None,
        )
        .await?;
    ensure!(detail["status"] == "revoked" && detail["channels"][0]["status"] == "revoked");
    ensure!(detail["capabilities"][0]["devicePrerequisite"]["reason"] == "not_registered");
    set_device_grants(&mut browser, &router, pending, &["inventory_read"]).await?;
    let (_, page) = browser
        .call(&router, Method::GET, "/api/v3/devices?limit=1", None)
        .await?;
    ensure!(page["statistics"]["total"] == 1 && page["items"][0]["id"] == pending);
    for id in [revoked, case::name("absent")] {
        ensure!(
            browser
                .call(&router, Method::GET, &format!("/api/v3/devices/{id}"), None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_script_support_requires_signer_and_content() -> Result<()> {
    use crate::test_support::agent_execution::{Fixture, case_device_id};
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    for (signed, content) in [(true, false), (false, true), (false, false), (true, true)] {
        let mut config = fixture.base.clone();
        if !signed {
            config["task_signing"] = Value::Null;
        }
        if !content {
            config["content"] = Value::Null;
        }
        let router = app(&config, authority::reader(&config).await?).await?;
        let (status, detail) = fixture
            .author
            .call(
                &router,
                Method::GET,
                &format!("/api/v3/devices/{}", case_device_id()),
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
    identity::set_grants(case_tenant(), &fixture.author_id, grants).await?;
    let (status, detail) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v3/devices/{}", case_device_id()),
            None,
        )
        .await?;
    ensure!(status == StatusCode::OK);
    let capability = &detail["capabilities"][0];
    ensure!(
        capability["action"] == "script"
            && capability["productSupport"]["state"] == "supported"
            && capability["devicePrerequisite"]["state"] == "ready"
            && capability["permission"]["allowed"] == false,
        "revocation merged capability facts: {capability}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_metadata_filters_and_selectors() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = app(&fixture.base, authority::reader(&fixture.base).await?).await?;
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
        call(&mut browser,&router,&format!("/api/v2/groups/{id}"),0,json!({"action":"create","name":format!("console-{i}"),"description":"","criteria":null})).await?;
    }
    let (_, first) = browser
        .call(
            &router,
            Method::GET,
            "/api/v2/groups?limit=1&kind=static",
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
            &format!("/api/v2/groups?limit=1&after={}", groups[0]),
            None,
        )
        .await?;
    ensure!(second["items"][0]["id"] == groups[1].to_string() && second["nextCursor"].is_null());
    let (_, named) = browser
        .call(
            &router,
            Method::GET,
            "/api/v2/groups?name=console-1&descending=true",
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
        &format!("/api/v4/resources/{resource}"),
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    let (_, resources) = browser
        .call(
            &router,
            Method::GET,
            "/api/v4/resources?kind=script&active=false",
            None,
        )
        .await?;
    ensure!(
        resources["items"][0]["id"] == resource
            && resources["items"][0]["kind"] == "script"
            && resources["items"][0]["activeVersion"].is_null()
    );
    for path in [
        "/api/v2/groups?kind=wrong",
        "/api/v4/resources?kind=wrong",
        "/api/v3/policies?limit=0",
        "/api/v3/policies?action=wrong",
        "/api/v2/scopes?limit=1001",
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
            "/api/mdm-candidate/v1/workspace",
            None,
        )
        .await?;
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
            "/api/mdm-candidate/v1/workspace",
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
                &format!("/api/v2/groups?after={}", groups[0]),
                None
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.http"]
async fn console_scope_ready_tracks_current_admission() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let router = app(&fixture.base, authority::reader(&fixture.base).await?).await?;
    let mut browser = fixture.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(&subject, json!(["scope_read", "scope_write"])).await?;
    let scope = Uuid::new_v4();
    let path = format!("/api/v2/scopes/{scope}");
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
        .call(&router, Method::GET, "/api/v2/scopes?ready=true", None)
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
        .call(&router, Method::GET, "/api/v2/scopes?ready=true", None)
        .await?;
    let stale = browser
        .call(&router, Method::GET, "/api/v2/scopes?ready=false", None)
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
        .call(&router, Method::GET, "/api/v2/scopes?ready=true", None)
        .await?;
    ensure!(
        fresh.0 == StatusCode::OK && fresh.1["items"][0]["id"] == scope.to_string(),
        "recalculated scope: {fresh:?}"
    );
    stop_worker(owner).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=planning.http"]
async fn planning_routes_and_derived_result_authorization() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let reader = authority::reader(&fixture.base).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','{DEVICE_ONE}')",
        TENANT = case_tenant(),
        DEVICE_ONE = case::name("device-1")
    ))?;
    inventory::seed_source(
        crate::test_support::case::name("device-1"),
        "mdm",
        "mdm.windows",
        "Model-A",
    )?;
    let base = &fixture.base;
    let session = &fixture.browser("other")?;
    let automation = start_automation(base).await?;
    await_ingress().await?;
    let initial = app(base, reader.clone()).await?;
    let member = browser_subject(session, &initial).await?;
    set_management_grants(
        &member,
        json!([
            "group_read",
            "group_write",
            "group_recompute",
            "scope_read",
            "scope_write",
            "policy_read",
            "policy_write",
            "resource_read",
            "resource_write"
        ]),
    )
    .await?;
    let router = initial;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
    let _server = Server(task);
    let mut browser = Browser {
        network: Some((
            Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(12))
                .build()?,
            format!("http://{address}"),
        )),
        ..session.clone()
    };
    let original_csrf = browser.csrf.take();
    for token in [None, Some("incorrect-token".to_owned())] {
        browser.csrf = token;
        let blocked = uuid::Uuid::new_v4();
        let response=browser.call(&router,Method::POST,&format!("/api/v2/groups/{blocked}"),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"csrf-must-not-write","description":"","criteria":null}}))).await?;
        ensure!(
            response.0 == StatusCode::FORBIDDEN,
            "planning write accepted absent/incorrect csrf token: {}",
            response.0
        );
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_group.groups WHERE id='{blocked}'"
            ))?
            .trim()
                == "0"
        );
    }
    browser.csrf = original_csrf;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let policy = uuid::Uuid::new_v4();
    let resource = uuid::Uuid::new_v4();
    let group_path = format!("/api/v2/groups/{group}");
    call(&mut browser,&router,&group_path,0,json!({"action":"create","name":"managed","description":"","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}})).await?;
    let (_, current) = browser
        .call(&router, Method::GET, &group_path, None)
        .await?;
    let revision = current["group"]["revision"].as_u64().unwrap();
    let accepted = call(
        &mut browser,
        &router,
        &format!("{group_path}/previews"),
        revision,
        json!({}),
    )
    .await?;
    let result_path = format!(
        "{group_path}/results/{}/members",
        accepted["task"].as_str().unwrap()
    );
    let (status, preview) = browser
        .call(&router, Method::GET, &result_path, None)
        .await?;
    ensure!(
        status == StatusCode::OK
            && preview["page"]["items"] == json!([crate::test_support::case::name("device-1")]),
        "trusted inventory mapping: {preview}"
    );
    pg(
        "UPDATE mdm.inventory SET value='{\"kind\":\"string\",\"value\":\"Model-B\"}' WHERE field='device.model'",
    )?;
    await_ingress().await?;
    // Immutable previews retain their fixed input even after a fact writer advances it.
    ensure!(
        browser
            .call(&router, Method::GET, &result_path, None)
            .await?
            .1
            == preview
    );
    let (_, current) = browser
        .call(&router, Method::GET, &group_path, None)
        .await?;
    let changed = call(
        &mut browser,
        &router,
        &format!("{group_path}/previews"),
        current["group"]["revision"].as_u64().unwrap(),
        json!({}),
    )
    .await?;
    let (_, members) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "{group_path}/results/{}/members",
                changed["task"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        members["page"]["items"] == json!([]),
        "new watermark did not observe the changed fact: {members}"
    );
    pg(
        "UPDATE mdm.inventory SET value='{\"kind\":\"string\",\"value\":\"Model-A\"}' WHERE field='device.model'",
    )?;
    await_ingress().await?;
    // The old synchronous endpoint and snapshot request shape are gone.
    ensure!(
        browser
            .call(
                &router,
                Method::GET,
                &format!("{group_path}/preview?expectedRevision=1"),
                None
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    let stale = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"recompute","snapshot":"obsolete"}});
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(stale))
            .await?
            .0
            .is_client_error()
    );
    let second = format!("scope-second-{}", uuid::Uuid::new_v4());
    let third = format!("scope-third-{}", uuid::Uuid::new_v4());
    for device in [&second, &third] {
        seed_management_device(device)?;
    }
    await_ingress().await?;
    let target_group = uuid::Uuid::new_v4();
    let limit_group = uuid::Uuid::new_v4();
    for (id, members) in [
        (
            target_group,
            json!([crate::test_support::case::name("device-1"), second, third]),
        ),
        (
            limit_group,
            json!([crate::test_support::case::name("device-1"), second]),
        ),
    ] {
        let path = format!("/api/v2/groups/{id}");
        call(
            &mut browser,
            &router,
            &path,
            0,
            json!({"action":"create","name":"set-algebra","description":"","criteria":null}),
        )
        .await?;
        call(
            &mut browser,
            &router,
            &path,
            1,
            json!({"action":"members","add":members,"remove":[]}),
        )
        .await?;
    }
    let scope_receipt = call(&mut browser,&router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":target_group}],"limitations":[{"kind":"group","id":limit_group}],"exclusions":[{"kind":"device","id":second}]}})).await?;
    native_configuration_resource(
        &mut browser,
        &router,
        resource,
        "windows",
        "x86_64",
        windows_configuration(),
    )
    .await?;
    let resource_path = format!("/api/v4/resources/{resource}");
    let policy_path = format!("/api/v3/policies/{policy}");
    let definition = json!({"scope":scope,"action": {"resource": {"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}});
    let mut assigned = definition.clone();
    let empty_scope = uuid::Uuid::new_v4();
    let empty = call(
        &mut browser,
        &router,
        &format!("/api/v2/scopes/{empty_scope}"),
        0,
        json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}),
    )
    .await?;
    await_task(
        &mut browser,
        &router,
        &format!(
            "/api/v2/scopes/{empty_scope}/tasks/{}",
            empty["task"].as_str().unwrap()
        ),
    )
    .await?;
    assigned["scope"] = json!(empty_scope);
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &["inventory_read", "configuration_write"],
    )?;
    for p in [
        "group_read",
        "group_write",
        "group_recompute",
        "scope_read",
        "scope_write",
        "policy_read",
        "policy_write",
        "resource_read",
        "resource_write",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(p))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(case_tenant(), &member, grants).await?;
    call(
        &mut browser,
        &router,
        &policy_path,
        0,
        json!({"action":"put","enabled":true,"definition":assigned}),
    )
    .await?;
    let referenced=browser.call(&router,Method::POST,&format!("/api/v2/scopes/{empty_scope}"),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}}))).await?;
    ensure!(
        referenced.0 == StatusCode::CONFLICT,
        "referenced Scope was deleted: {referenced:?}"
    );
    Box::pin(derived_result_authorization(
        &mut browser,
        &router,
        &member,
        &group_path,
        accepted["task"].as_str().unwrap(),
        scope,
        scope_receipt["task"].as_str().unwrap(),
        &policy_path,
    ))
    .await?;
    let (_, decisions) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/scopes/{scope}/results/{}/decisions",
                scope_receipt["task"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    let explanations = decisions["page"]["items"].as_array().unwrap();
    ensure!(explanations.iter().any(|e| {
        e["device"] == second
            && e["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("explicit_exclusion"))
    }));
    ensure!(explanations.iter().any(|e| {
        e["device"] == third
            && e["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("missing_limitation_match"))
    }));
    let state = browser
        .call(&router, Method::GET, &policy_path, None)
        .await?
        .1;
    ensure!(state["revision"] == 1 && state["enabled"] == true);
    // Revocation is persistent and visible to every existing router/session.
    set_management_grants(&member, json!([])).await?;
    let restricted = app(base, reader.clone()).await?;
    let mut denied = session.clone();
    for path in [&group_path, &policy_path, &resource_path] {
        ensure!(
            denied.call(&restricted, Method::GET, path, None).await?.0 == StatusCode::FORBIDDEN
        );
    }
    set_management_grants(&member, json!(["group_write"])).await?;
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime")?;
    let failed=browser.call(&router,Method::POST,&format!("/api/v2/groups/{}",uuid::Uuid::new_v4()),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"must-rollback","description":"","criteria":null}}))).await?;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime")?;
    ensure!(
        failed.0 == StatusCode::INTERNAL_SERVER_ERROR && failed.1["code"] == "audit_contract_error"
    );
    ensure!(pg("SELECT count(*) FROM mdm_group.groups WHERE name='must-rollback'")?.trim() == "0");
    crate::test_support::stop_worker(automation).await?;
    reader.close().await;
    Ok(())
}
fn seed_management_device(device: &str) -> Result<()> {
    let grant = uuid::Uuid::new_v4();
    let request = uuid::Uuid::new_v4();
    let registration = uuid::Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '200 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active'); INSERT INTO mdm_access.credentials VALUES('{TENANT}',gen_random_uuid(),'{registration}','mdm',md5('{registration}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{TENANT}','{registration}','mdm.windows','77777777-7777-4777-8777-777777777777',true);",
        TENANT = case_tenant()
    ))?;
    Ok(())
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
            format!("/api/v2/groups/{absent}/results/{group_result}/members"),
            "group_not_found",
        ),
        (
            format!("{group}/results/{absent}/members"),
            "group_not_found",
        ),
        (
            format!("/api/v2/scopes/{absent}/results/{scope_result}/members"),
            "scope_not_found",
        ),
        (
            format!("/api/v2/scopes/{scope}/results/{absent}/members"),
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
        format!("/api/v2/scopes/{scope}/tasks/{scope_result}"),
        format!("{policy}/devices"),
    ];
    for kind in ["members", "changes", "decisions"] {
        paths.push(format!("{group}/results/{group_result}/{kind}?limit=1"));
    }
    for kind in ["members", "decisions"] {
        paths.push(format!(
            "/api/v2/scopes/{scope}/results/{scope_result}/{kind}?limit=1"
        ));
    }
    // Keep an actually issued cursor, then shrink the subject's device access.
    let (status, page) = Box::pin(browser.call(router, Method::GET, &paths[3], None)).await?;
    ensure!(status == StatusCode::OK, "authorized derived page: {page}");
    let cursor = page["nextCursor"].as_str().unwrap();
    paths.push(format!("{}&cursor={cursor}", paths[3]));
    let criteria = json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}});
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
        let before = pg(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_automation.automation_jobs))",
        )?;
        for (path, revision, input) in [
            (
                format!("/api/v2/groups/{}", uuid::Uuid::new_v4()),
                0,
                json!({"action":"create","name":"denied-dynamic","description":"","criteria":criteria}),
            ),
            (
                group.to_owned(),
                0,
                json!({"action":"rule","criteria":criteria}),
            ),
        ] {
            let (status,body)=browser.call(router,Method::POST,&path,Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}))).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "derived writer accepted absent/full-inventory gap: {status} {body}"
            );
        }
        for path in &paths {
            let (status, body) = Box::pin(browser.call(router, Method::GET, path, None)).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "derived page leaked after inventory grant shrink at {path}: {status} {body}"
            );
        }
        ensure!(
            pg(
                "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_automation.automation_jobs))"
            )? == before,
            "denied dynamic write enqueued work"
        );
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
