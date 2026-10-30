use super::*;
use crate::audit_test_support::audit_count;
use sqlx::Connection;
async fn waiting_group_does_not_spin(b: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    // Drain setup writes before creating the held input: their legitimate dispatch must
    // not race with the task-count assertion that detects work without new input.
    let setup = start_automation(base).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let caught_up = pg(&format!(
                "SELECT NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=d.tenant_id AND NOT mdm.asset_visible(d.from_cut,e.revision)) FROM mdm_compliance.dispatch d WHERE d.tenant_id='{}'",
                case_tenant()
            ))?;
            if caught_up.trim() == "t" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    crate::test_support::runtime::stop_worker(setup).await?;
    let group = Uuid::new_v4();
    let planning = crate::planning::test_support::planning(rss_request_context::TenantId::parse(
        case_tenant(),
    )?)
    .await;
    let created=crate::planning::test_support::seed_group(&planning,&rss_mdm_inventory_service::groups::Command::Group {id:group,change:Box::new(crate::planning::test_support::group_operation(0,serde_json::from_value(json!({"action":"create","assetContext":"endpoint","presentation":{"name":"held group","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}}}))?))}).await?;
    let group_task = created["task"].as_str().unwrap();
    // Hold only the external group input. No claim was created while the worker was stopped.
    pg(&format!(
        "UPDATE rss_reconcile.targets SET next_run=clock_timestamp()+interval '1 hour' WHERE reconciler='mdm.groups' AND entity='task:{group_task}'"
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
        "SELECT jsonb_build_array(desired,(SELECT count(*) FROM mdm_compliance.runs WHERE rule_id='{rule}' AND tenant_id='{}')) FROM mdm_compliance.rules WHERE id='{rule}'",
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
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_superseded")
            .await?
            == 1
    );
    ensure!(
        pg(&format!(
            "SELECT jsonb_build_array(desired,(SELECT count(*) FROM mdm_compliance.runs WHERE rule_id='{rule}' AND tenant_id='{}')) FROM mdm_compliance.rules WHERE id='{rule}'",
            case_tenant()
        ))? == held,
        "pending input spun new work"
    );
    pg(&format!(
        "UPDATE rss_reconcile.targets SET next_run=clock_timestamp() WHERE reconciler='mdm.groups' AND entity='task:{group_task}'"
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
    crate::test_support::runtime::stop_worker(worker).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.group_input: real HTTP and durable worker contract"]
async fn group_applicability_membership_versions_and_stale_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v1/compliance-rules/{id}");
    let initial_definition: rss_mdm_inventory_service::compliance::Definition =
        serde_json::from_value(definition(json!({"kind":"all"})))?;
    ensure!(
        rss_mdm_compliance_postgres::put(
            &mut tx,
            tenant,
            &rss_mdm_compliance_postgres::Rule {
                id,
                revision: 1,
                enabled: true,
                desired: None,
                current_run: None,
                definition: initial_definition,
            },
            &["custom.is_loaner".into()],
            &[]
        )
        .await?
    );
    let field = rss_mdm_inventory::builtin::IS_LOANER;
    let value = rss_mdm_inventory::Scalar::Boolean(true);
    let evidence = rss_mdm_inventory::Evidence {
        scope: rss_mdm_inventory::CollectionScope::Device,
        source: rss_mdm_inventory::Source::Manual,
        dataset: None,
        registration: None,
        registration_generation: None,
        epoch: None,
        snapshot_id: Uuid::new_v4().to_string(),
        observed_at: 1,
        received_at: 2,
        actor: Some(case_admin().into()),
    };
    ensure!(
        rss_mdm_inventory_postgres::assign_in(
            &mut tx,
            tenant,
            "compliance-a",
            field,
            0,
            &rss_mdm_inventory::State::Known(value),
            &evidence
        )
        .await?
            == Some(1)
    );
    tx.commit().await?;
    owner.close().await?;
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    let group = Uuid::new_v4();
    let gp = format!("/api/v1/groups/{group}");
    let group_rule = json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}}});
    crate::test_support::planning_http::call(&mut browser,router,&gp,0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"compliance target","description":""},"criteria":group_rule})).await?;
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
    crate::test_support::runtime::stop_worker(automation).await?;
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
    ensure!(accepted == StatusCode::ACCEPTED);
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
    ensure!(
        old["phase"] == "published" || old["phase"] == "superseded",
        "old definition remains valid until async publication: {old}"
    );
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            if pg(&format!("SELECT NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=d.tenant_id AND NOT mdm.asset_visible(d.from_cut,e.revision)) FROM mdm_compliance.dispatch d WHERE d.tenant_id='{TENANT}'", TENANT = case_tenant()))?.trim()=="t" {return Ok::<_,anyhow::Error>(())}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    crate::test_support::runtime::stop_worker(restarted).await?;
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
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    for (field, value) in [
        (
            rss_mdm_inventory::builtin::IS_LOANER,
            rss_mdm_inventory::Scalar::Boolean(false),
        ),
        (
            rss_mdm_inventory::builtin::OFFICE_FLOOR,
            rss_mdm_inventory::Scalar::Integer(1),
        ),
    ] {
        let evidence = rss_mdm_inventory::Evidence {
            scope: rss_mdm_inventory::CollectionScope::Device,
            source: rss_mdm_inventory::Source::Manual,
            dataset: None,
            registration: None,
            registration_generation: None,
            epoch: None,
            snapshot_id: Uuid::new_v4().to_string(),
            observed_at: 1,
            received_at: 2,
            actor: Some(case_admin().into()),
        };
        ensure!(
            rss_mdm_inventory_postgres::assign_in(
                &mut tx,
                tenant,
                "compliance-a",
                field,
                0,
                &rss_mdm_inventory::State::Known(value),
                &evidence
            )
            .await?
                == Some(1)
        );
    }
    tx.commit().await?;
    owner.close().await?;
    waiting_group_does_not_spin(&mut browser, router, base).await?;
    fixture.close().await;
    Ok(())
}
