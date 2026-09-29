#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
async fn history_boundaries(
    b: &mut Browser,
    router: &Router,
    base: &Value,
    token: &str,
    rule_path: &str,
    task: &str,
    subject: &str,
) -> Result<()> {
    let history = "/api/v2/devices/compliance-a/compliance/history";
    for filter in ["from=0", "until=9999999999"] {
        ensure!(
            b.call(
                router,
                Method::GET,
                &format!("{history}?cursor={token}&{filter}"),
                None
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    let mut other = Browser::default();
    ensure!(other.login(router, "other").await? == StatusCode::OK);
    let other_subject = browser_subject(&other, router).await?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        &other_subject,
        crate::test_support::identity::device_grants(None, &["compliance_read"])?,
    )
    .await?;
    ensure!(other.call(router, Method::GET, history, None).await?.0 == StatusCode::OK);
    ensure!(
        other
            .call(
                router,
                Method::GET,
                &format!("{history}?cursor={token}"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    for device in [None, Some("compliance-a")] {
        let mut limited = vec![crate::authorization::Grant {
            operation: crate::authorization::Permission::ComplianceRuleRead,
            scope: crate::authorization::Scope::Tenant,
        }];
        if let Some(device) = device {
            limited.extend(crate::test_support::identity::device_grants(
                Some(device),
                &["compliance_read"],
            )?);
        }
        crate::test_support::identity::set_grants(case_tenant(), subject, limited).await?;
        ensure!(b.call(router, Method::GET, rule_path, None).await?.0 == StatusCode::OK);
        ensure!(
            b.call(
                router,
                Method::GET,
                &format!("{rule_path}/tasks/{task}"),
                None
            )
            .await?
            .0 == StatusCode::FORBIDDEN
        );
    }
    grants(subject, None).await?;
    let tenant = case::peer();
    let config = crate::test_support::identity::config(tenant)?;
    let access = database(base).await?;
    let audit = access.audit_store(&config.audit).await?;
    let (other_router, _, _) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit,
    )
    .await?;
    let other_router = other_router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    pg_tenant(
        tenant,
        &format!("INSERT INTO mdm_access.devices VALUES('{tenant}','compliance-a')"),
    )?;
    crate::test_support::identity::set_grants(
        tenant,
        case::context()["admins"][tenant].as_str().unwrap(),
        crate::test_support::identity::device_grants(None, &["compliance_read"])?,
    )
    .await?;
    let mut cross = Browser::default();
    ensure!(
        cross
            .call(
                &other_router,
                Method::POST,
                &format!("/api/v2/tenants/{tenant}/login"),
                Some(json!({"login":case::login("admin"),"password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        cross
            .call(&other_router, Method::GET, history, None)
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        cross
            .call(
                &other_router,
                Method::GET,
                &format!("{history}?cursor={token}"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.http: real HTTP and durable worker contract"]
async fn http_history_cursors_authorization_and_disable() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    let subject = &fixture.subject;
    let initial = status(&mut browser, router, "compliance-a", "unknown").await?;
    ensure!(initial["reason"] == "no_rules");
    let (_, path, written) = fixture.rule().await?;
    let (s, _) = browser
        .call(
            router,
            Method::PUT,
            &path,
            Some(request(0, definition(json!({"kind":"all"})))),
        )
        .await?;
    ensure!(s == StatusCode::CONFLICT);
    ensure!(
        status(&mut browser, router, "compliance-a", "pending").await?["rules"][0]["current"]
            .is_null()
    );
    let queued = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(queued["phase"] == "queued" && queued["processed"] == 0);
    let list = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/compliance-rules",
        None,
    )
    .await?;
    ensure!(list.get("nextCursor").is_some() && list["items"][0].get("currentRun").is_none());
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "unknown").await?;
    assign(&mut browser, router, "compliance-a", 0, false).await?;
    let old =
        status(&mut browser, router, "compliance-a", "compliant").await?["rules"][0]["current"]
            .clone();
    assign(&mut browser, router, "compliance-a", 1, true).await?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    let history = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/devices/compliance-a/compliance/history",
        None,
    )
    .await?;
    ensure!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["status"] == "compliant" && v["factWatermark"] == old["factWatermark"]),
        "history was rewritten"
    );
    let original = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/versions/1"),
        None,
    )
    .await?;
    ensure!(original["definition"]["target"]["kind"] == "all");
    let first = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v2/devices/compliance-a/compliance/history?limit=1",
        None,
    )
    .await?;
    let next = first["nextCursor"].as_str().unwrap();
    let second = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("/api/v2/devices/compliance-a/compliance/history?limit=1&cursor={next}"),
        None,
    )
    .await?;
    ensure!(first["items"][0]["task"] != second["items"][0]["task"]);
    let (s, _) = browser
        .call(
            router,
            Method::GET,
            &format!("/api/v2/devices/compliance-b/compliance/history?cursor={next}"),
            None,
        )
        .await?;
    ensure!(
        s == StatusCode::BAD_REQUEST,
        "history cursor was reused for a different device"
    );
    history_boundaries(
        &mut browser,
        router,
        base,
        next,
        &path,
        written["task"].as_str().unwrap(),
        subject,
    )
    .await?;
    // Device-scoped authorization applies equally to history and current results.
    grants(subject, Some("compliance-a")).await?;
    for suffix in ["compliance", "compliance/history"] {
        let (s, _) = browser
            .call(
                router,
                Method::GET,
                &format!("/api/v2/devices/compliance-b/{suffix}"),
                None,
            )
            .await?;
        ensure!(s == StatusCode::FORBIDDEN);
    }
    let (s, _) = browser.call(router, Method::GET, &path, None).await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            router,
            Method::POST,
            &format!("{path}/recompute"),
            Some(request(2, json!({}))),
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            router,
            Method::GET,
            &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    grants(subject, None).await?;
    // Disabling removes the rule from the aggregate but preserves all previous evidence.
    let mut def = definition(json!({"kind":"all"}));
    def["enabled"] = json!(false);
    ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(1, def)),
    )
    .await?;
    ensure!(status(&mut browser, router, "compliance-a", "unknown").await?["reason"] == "no_rules");
    ensure!(
        !ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v2/devices/compliance-a/compliance/history",
            None
        )
        .await?["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    ensure!(audit_count(|r| r.action() == "compliance_read")? > 0);
    crate::test_support::stop_worker(automation).await?;
    fixture.close().await;
    Ok(())
}
