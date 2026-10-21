use super::*;
async fn waiting_group_does_not_spin(b: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    // Drain setup writes before creating the held input: their legitimate dispatch must
    // not race with the task-count assertion that detects work without new input.
    let setup = start_automation(base).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let caught_up = pg(&format!(
                "SELECT d.consumed=c.revision FROM mdm_planning.asset_dispatch d JOIN mdm.asset_clock c USING(tenant_id) WHERE d.tenant_id='{}'",
                case_tenant()
            ))?;
            if caught_up.trim() == "t" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    crate::test_support::stop_worker(setup).await?;
    let group = Uuid::new_v4();
    let gp = format!("/api/v1/groups/{group}");
    let created=ok(b,router,Method::POST,&gp,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"held group","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}}})))).await?;
    let group_task = created["task"].as_str().unwrap();
    // Hold only the external group input. No claim was created while the worker was stopped.
    pg(&format!(
        "UPDATE mdm_automation.automation_jobs SET forwarded=true WHERE id='{group_task}'"
    ))?;
    let rule = Uuid::new_v4();
    let path = format!("/api/v1/compliance-rules/{rule}");
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
    let held = pg(&format!(
        "SELECT jsonb_build_array(desired,(SELECT count(*) FROM mdm_automation.automation_jobs WHERE target='{rule}' AND tenant_id='{}')) FROM mdm_compliance.rules WHERE id='{rule}'",
        case_tenant()
    ))?;
    let independent = Uuid::new_v4();
    let independent_path = format!("/api/v1/compliance-rules/{independent}");
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
    ensure!(
        pg(&format!(
            "SELECT jsonb_build_array(desired,(SELECT count(*) FROM mdm_automation.automation_jobs WHERE target='{rule}' AND tenant_id='{}')) FROM mdm_compliance.rules WHERE id='{rule}'",
            case_tenant()
        ))? == held,
        "pending input spun new work"
    );
    pg(&format!(
        "UPDATE mdm_automation.automation_jobs SET forwarded=false WHERE id='{group_task}'"
    ))?;
    status(b, router, "compliance-a", "compliant").await?;
    let next = pg(&format!(
        "SELECT desired::text FROM mdm_compliance.rules WHERE id='{rule}'"
    ))?;
    ensure!(next.trim() != task);
    task_phase(
        b,
        router,
        &format!("{path}/tasks/{}", next.trim()),
        "published",
    )
    .await?;
    ensure!(
        pg(&format!(
            "SELECT current_run::text FROM mdm_compliance.rules WHERE id='{rule}'"
        ))?
        .trim()
            == next.trim()
    );
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
    let gp = format!("/api/v1/groups/{group}");
    let group_rule = json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}}});
    crate::test_support::http::ok(&mut browser,router,Method::POST,&gp,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"compliance target","description":""},"criteria":group_rule})))).await?;
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
            "/api/v1/devices/compliance-a/manual-fields/custom.office_floor",
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
        "/api/v1/devices/compliance-b/manual-fields/custom.office_floor",
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
    let (accepted, _) = browser.call(router,Method::POST,&gp,Some(request(g["group"]["revision"].as_u64().unwrap(),json!({"action":"rule","criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}}})))).await?;
    ensure!(accepted == StatusCode::OK);
    let restarted = start_automation(base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, router, "compliance-a", "compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 3);
    let evidence = &latest["rules"][0]["current"]["applicability"]["groups"][0];
    let member_set = pg(&format!(
        "SELECT member_set::text FROM mdm_group.groups WHERE tenant_id='{}' AND id='{group}'",
        case_tenant()
    ))?;
    Uuid::parse_str(member_set.trim())?;
    ensure!(evidence["decision"] == "match" && evidence["memberSet"] == member_set.trim());
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
        "/api/v1/devices/compliance-a/manual-fields/custom.office_floor",
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
