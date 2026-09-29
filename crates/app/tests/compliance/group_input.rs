use super::*;
async fn waiting_group_does_not_spin(b: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    let group = Uuid::new_v4();
    let gp = format!("/api/v2/groups/{group}");
    let created=ok(b,router,Method::POST,&gp,Some(request(0,json!({"action":"create","name":"held group","description":"","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}})))).await?;
    let group_task = created["task"].as_str().unwrap();
    // Hold only the external group input. No claim was created while the worker was stopped.
    pg(&format!(
        "UPDATE mdm_automation.automation_jobs SET forwarded=true WHERE id='{group_task}'"
    ))?;
    let rule = Uuid::new_v4();
    let path = format!("/api/v2/compliance-rules/{rule}");
    let waiting = ok(
        b,
        router,
        Method::PUT,
        &path,
        Some(request(
            0,
            definition(json!({"kind":"groups","ids":[group]})),
        )),
    )
    .await?;
    let task = waiting["task"].as_str().unwrap();
    let worker = start_automation(base).await?;
    let finished = task_phase(b, router, &format!("{path}/tasks/{task}"), "superseded").await?;
    ensure!(
        finished["diagnostic"]["reason"] == "group_input_pending" && finished["processed"] == 0
    );
    let independent = Uuid::new_v4();
    let independent_path = format!("/api/v2/compliance-rules/{independent}");
    let run = ok(
        b,
        router,
        Method::PUT,
        &independent_path,
        Some(request(0, definition(json!({"kind":"all"})))),
    )
    .await?;
    task_phase(
        b,
        router,
        &format!("{independent_path}/tasks/{}", run["task"].as_str().unwrap()),
        "published",
    )
    .await?;
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_superseded")? == 1
    );
    pg(&format!(
        "UPDATE mdm_automation.automation_jobs SET forwarded=false WHERE id='{group_task}'"
    ))?;
    status(b, router, "compliance-a", "compliant").await?;
    let next = pg(&format!(
        "SELECT desired::text FROM mdm_compliance.rules WHERE id='{rule}'"
    ))?;
    ensure!(next.trim() != task);
    crate::test_support::stop_worker(worker).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.group_input: real HTTP and durable worker contract"]
async fn group_applicability_membership_versions_and_stale_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    let (_, path, _) = fixture.rule().await?;
    assign(&mut browser, router, "compliance-a", 0, true).await?;
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    let group = Uuid::new_v4();
    let gp = format!("/api/v2/groups/{group}");
    let group_rule = json!({"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}});
    crate::test_support::http::ok(&mut browser,router,Method::POST,&gp,Some(request(0,json!({"action":"create","name":"compliance target","description":"","criteria":group_rule})))).await?;
    let def = definition(json!({"kind":"groups","ids":[group]}));
    ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(1, def.clone())),
    )
    .await?;
    let unknown = status(&mut browser, router, "compliance-a", "unknown").await?;
    ensure!(unknown["rules"][0]["current"]["reason"] == "group_unknown");
    for (revision, floor, expected) in [
        (0, 1, "not_applicable"),
        (1, 4, "non_compliant"),
        (2, 1, "not_applicable"),
    ] {
        ok(
            &mut browser,
            router,
            Method::PUT,
            "/api/v2/devices/compliance-a/manual-fields/custom.office_floor",
            Some(request(
                revision,
                json!({"action":"set","value":{"kind":"integer","value":floor}}),
            )),
        )
        .await?;
        status(&mut browser, router, "compliance-a", expected).await?;
    }
    // Unknown -> false leaves membership empty but must change applicability evidence.
    ok(
        &mut browser,
        router,
        Method::PUT,
        "/api/v2/devices/compliance-b/manual-fields/custom.office_floor",
        Some(request(
            0,
            json!({"action":"set","value":{"kind":"integer","value":1}}),
        )),
    )
    .await?;
    status(&mut browser, router, "compliance-b", "not_applicable").await?;
    let g = crate::test_support::http::ok(&mut browser, router, Method::GET, &gp, None).await?;
    let (s, _) = browser
        .call(
            router,
            Method::POST,
            &gp,
            Some(request(
                g["group"]["revision"].as_u64().unwrap(),
                json!({"action":"delete"}),
            )),
        )
        .await?;
    ensure!(s == StatusCode::CONFLICT, "referenced group was deleted");
    crate::test_support::stop_worker(automation).await?;
    assign(&mut browser, router, "compliance-a", 1, false).await?;
    // Group-only race: frozen membership must not survive a later group definition.
    let grouped = definition(json!({"kind":"groups","ids":[group]}));
    let stale_group = ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(2, grouped)),
    )
    .await?;
    let g = crate::test_support::http::ok(&mut browser, router, Method::GET, &gp, None).await?;
    let (accepted, _) = browser.call(router,Method::POST,&gp,Some(request(g["group"]["revision"].as_u64().unwrap(),json!({"action":"rule","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}})))).await?;
    ensure!(accepted == StatusCode::OK);
    let restarted = start_automation(base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, router, "compliance-a", "compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 3);
    let evidence = &latest["rules"][0]["current"]["applicability"]["groups"][0];
    ensure!(evidence["decision"] == "match" && evidence["memberSet"].is_string());
    let old = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{}", stale_group["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(old["phase"] == "superseded");
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            if pg(&format!("SELECT d.consumed=c.revision FROM mdm_planning.asset_dispatch d JOIN mdm.asset_clock c USING(tenant_id) WHERE d.tenant_id='{TENANT}'", TENANT = case_tenant()))?.trim()=="t" {return Ok::<_,anyhow::Error>(())}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    crate::test_support::stop_worker(restarted).await?;
    fixture.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.group_input: real HTTP and durable worker contract"]
async fn pending_group_input_does_not_spin_or_starve_other_rules() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    assign(&mut browser, router, "compliance-a", 0, false).await?;
    ok(
        &mut browser,
        router,
        Method::PUT,
        "/api/v2/devices/compliance-a/manual-fields/custom.office_floor",
        Some(request(
            0,
            json!({"action":"set","value":{"kind":"integer","value":1}}),
        )),
    )
    .await?;
    waiting_group_does_not_spin(&mut browser, router, base).await?;
    fixture.close().await;
    Ok(())
}
