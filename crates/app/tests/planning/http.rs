#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::test_support::planning_http::*;
use crate::test_support::*;
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
    pg("UPDATE mdm.inventory SET value='Model-B' WHERE field='device.model'")?;
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
    pg("UPDATE mdm.inventory SET value='Model-A' WHERE field='device.model'")?;
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
    let resource_path = format!("/api/v3/resources/{resource}");
    call(
        &mut browser,
        &router,
        &resource_path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    call(
        &mut browser,
        &router,
        &resource_path,
        1,
        json!({"action":"firewall_version","version":"v1","enabled":true}),
    )
    .await?;
    call(
        &mut browser,
        &router,
        &resource_path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let policy_path = format!("/api/v2/policies/{policy}");
    let definition = json!({"resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"domain-firewall"},"scope":scope,"behavior":{"kind":"configuration","exit":"retain"}});
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
    let mut grants =
        crate::test_support::identity::device_grants(None, &["inventory_read", "firewall_write"])?;
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
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '200 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active'); INSERT INTO mdm_access.credentials VALUES('{TENANT}',gen_random_uuid(),'{registration}','mdm',md5('{registration}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','mdm.windows','77777777-7777-4777-8777-777777777777','device-basics/2/model-os/typed-v2',true);",
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
