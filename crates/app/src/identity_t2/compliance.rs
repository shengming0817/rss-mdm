//! Authenticated production Router, durable worker and real TLS PostgreSQL.
use super::*;
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
fn definition(target: Value) -> Value {
    json!({"name":"loaner policy","severity":"high","enabled":true,"platform":"all","target":target,"criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}})
}
async fn ok(b: &mut Browser, r: &Router, m: Method, p: &str, v: Option<Value>) -> Result<Value> {
    let (s, v) = b.call(r, m, p, v).await?;
    ensure!(s == StatusCode::OK, "{p}: {s} {v}");
    Ok(v)
}
async fn status(b: &mut Browser, r: &Router, device: &str, expected: &str) -> Result<Value> {
    // Allow one production 30-second claim lease to expire after an unknown commit.
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let v = ok(
                b,
                r,
                Method::GET,
                &format!("/api/v2/devices/{device}/compliance"),
                None,
            )
            .await?;
            if v["status"] == expected {
                return Ok::<_, anyhow::Error>(v);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| {
        let jobs=pg("SELECT json_agg(json_build_object('kind',kind,'completed',completed,'failure',failure,'cursor',cursor,'forwarded',forwarded,'watermark',input->'input'->'watermark')) FROM mdm_automation.automation_jobs");
        let reconcile=pg("SELECT json_agg(json_build_object('entity',entity,'result',result,'wake',wake_version,'failures',failures,'lease',lease_until,'next',next_run)) FROM rss_reconcile.targets");
        let heads=pg("SELECT json_agg(row_to_json(r)) FROM mdm_compliance.rules r");
        let changes=pg("SELECT json_agg(json_build_object('revision',revision,'forwarded',forwarded)) FROM mdm.asset_changes");
        let checkpoint=pg("SELECT json_agg(row_to_json(d)) FROM mdm_planning.asset_dispatch d");
        let locks=pg("SELECT json_agg(json_build_object('wait',wait_event,'state',state,'query',left(query,160))) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'");
        anyhow::anyhow!("compliance {device} did not converge to {expected}; jobs={jobs:?}; waits={locks:?}; reconcile={reconcile:?}; checkpoint={checkpoint:?}; heads={heads:?}; changes={changes:?}")
    })?
}
async fn assign(
    b: &mut Browser,
    r: &Router,
    device: &str,
    revision: u64,
    value: bool,
) -> Result<Value> {
    ok(
        b,
        r,
        Method::PUT,
        &format!("/api/v2/devices/{device}/manual-fields/custom.is_loaner"),
        Some(request(
            revision,
            json!({"action":"set","value":{"kind":"boolean","value":value}}),
        )),
    )
    .await
}
async fn grants(subject: &str, device: Option<&str>) -> Result<()> {
    let mut grants = crate::identity_fixture::device_grants(
        device,
        &["compliance_read", "inventory_read", "inventory_assign"],
    )?;
    if device.is_none() {
        for operation in [
            crate::authorization::Permission::ComplianceRuleRead,
            crate::authorization::Permission::ComplianceWrite,
            crate::authorization::Permission::ComplianceRecompute,
            crate::authorization::Permission::GroupRead,
            crate::authorization::Permission::GroupWrite,
            crate::authorization::Permission::GroupRecompute,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
    }
    crate::identity_fixture::set_grants(TENANT, subject, grants).await
}
async fn admission_drift() -> Result<()> {
    let admission = include_str!("../../../compliance-postgres/src/admission.sql");
    let valid = |change: &str| {
        pg(&format!(
            "{change}; SET LOCAL ROLE mdm_flow_runtime; {admission}"
        ))
    };
    ensure!(valid("SELECT 1")?.lines().last() == Some("t"));
    for change in [
        "GRANT SELECT ON mdm_compliance.results TO mdm_api",
        "GRANT UPDATE(desired) ON mdm_compliance.rules TO mdm_api",
        "GRANT SELECT ON mdm_compliance.results TO PUBLIC",
        "ALTER TABLE mdm_compliance.results DISABLE ROW LEVEL SECURITY",
    ] {
        // Each probe rolls back; one drifting authority must fail the whole admission.
        ensure!(pg(&format!("SAVEPOINT drift; {change}; SET LOCAL ROLE mdm_flow_runtime; {admission}; RESET ROLE; ROLLBACK TO drift"))?.lines().any(|v| v == "f"), "unrejected drift: {change}");
    }
    Ok(())
}
async fn collected_facts(b: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    use crate::inventory_runtime::tests::{report, start, wait_ready_projection};
    let device = "collected-compliance";
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}')"
    ))?;
    let (registration, _) = super::assets::seed_source(device, "mdm", "mdm.windows", "seed")?;
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator=repeat('79',32) WHERE registration='{registration}'"
    ))?;
    let access = database(base).await?;
    let service = crate::device::DeviceService::new(
        access.clone(),
        TENANT.into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let proof = crate::device::tests::proof(TENANT, rss_mdm_inventory::Channel::Mdm, 121);
    let config: Config = serde_json::from_value(base.clone())?;
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.clone(),
        rss_request_context::TenantId::parse(TENANT)?,
        monotonic(),
    )
    .await?;
    let owner = start(runtime.clone()).await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v2/compliance-rules/{id}");
    let mut def = definition(json!({"kind":"all"}));
    def["platform"] = json!("windows");
    def["criteria"] = json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Collected"}});
    ok(b, router, Method::PUT, &path, Some(request(0, def.clone()))).await?;
    for (model, expected) in [("Collected", "compliant"), ("Changed", "non_compliant")] {
        let run = report(&service, &access, &proof, [Some(model), Some("11")]).await?;
        wait_ready_projection(&runtime, &run).await?;
        let response = status(b, router, device, expected).await?;
        let current = &response["rules"][0]["current"];
        ensure!(current["applicability"]["platformDecision"] == "match");
        ensure!(current["evidence"][0]["sources"][0]["source"] == "mdm.windows");
    }
    def["enabled"] = json!(false);
    ok(b, router, Method::PUT, &path, Some(request(1, def))).await?;
    ensure!(owner.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "make t2-compliance: authenticated Router, real PG and production automation"]
async fn rules_facts_groups_history_and_authorization() -> Result<()> {
    admission_drift().await?;
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
    {
        use sqlx::Connection;
        let mut connection =
            sqlx::PgConnection::connect_with(&config.flow.storage.database.options()?).await?;
        rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection).await?;
        pg("GRANT EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) TO mdm_api")?;
        let rejected = rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection)
            .await
            .is_err();
        pg("REVOKE EXECUTE ON FUNCTION mdm.lock_asset_watermark(uuid) FROM mdm_api")?;
        ensure!(rejected, "watermark fence accepted an unrelated grantee");
        rss_mdm_inventory_postgres::verify_watermark_fence(&mut connection).await?;
        connection.close().await?;
    }
    let reader = Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    );
    let access = database(&base).await?;
    let audit = access.audit_store(&config.audit).await?;
    let (router, _, plan_runtime) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit,
    )
    .await?;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut browser = Browser::default();
    ensure!(browser.login(&router, "admin").await? == StatusCode::OK);
    let subject = browser_subject(&browser, &router).await?;
    grants(&subject, None).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','compliance-a'),('{TENANT}','compliance-b')"
    ))?;
    pg(&format!(
        "INSERT INTO mdm_access.devices SELECT '{TENANT}', 'page-'||lpad(n::text,2,'0') FROM generate_series(1,33) n"
    ))?;
    let (agent, _) = super::assets::seed_source("compliance-b", "agent", "agent.builtin", "seed")?;
    for source in ["agent.script", "agent.osquery"] {
        let epoch = Uuid::new_v4();
        pg(&format!(
            "INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{agent}','{source}','{epoch}','enterprise-task-v1',true)"
        ))?;
    }
    let initial = status(&mut browser, &router, "compliance-a", "unknown").await?;
    ensure!(initial["reason"] == "no_rules");
    let id = Uuid::new_v4();
    let path = format!("/api/v2/compliance-rules/{id}");
    let body = request(0, definition(json!({"kind":"all"})));
    plan_runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    let (s, _) = browser
        .call(&router, Method::PUT, &path, Some(body.clone()))
        .await?;
    ensure!(
        s == StatusCode::SERVICE_UNAVAILABLE,
        "lost commit ACK must remain unknown"
    );
    let written = ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(body.clone()),
    )
    .await?;
    ensure!(
        ok(&mut browser, &router, Method::PUT, &path, Some(body)).await? == written,
        "operation replay changed response"
    );
    let (s, _) = browser
        .call(
            &router,
            Method::PUT,
            &path,
            Some(request(0, definition(json!({"kind":"all"})))),
        )
        .await?;
    ensure!(s == StatusCode::CONFLICT);
    ensure!(
        status(&mut browser, &router, "compliance-a", "pending").await?["rules"][0]["current"]
            .is_null()
    );
    let queued = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(queued["phase"] == "queued" && queued["processed"] == 0);
    let list = ok(
        &mut browser,
        &router,
        Method::GET,
        "/api/v2/compliance-rules",
        None,
    )
    .await?;
    ensure!(list.get("nextCursor").is_some() && list["items"][0].get("currentRun").is_none());
    let automation = start_automation(&base).await?;
    let unknown = status(&mut browser, &router, "compliance-a", "unknown").await?;
    ensure!(unknown["rules"][0]["current"]["reason"] == "facts_unknown");
    assign(&mut browser, &router, "compliance-a", 0, false).await?;
    let passed = status(&mut browser, &router, "compliance-a", "compliant").await?;
    let old = passed["rules"][0]["current"].clone();
    ensure!(old["evidence"][0]["sources"][0]["snapshotId"].is_string());
    assign(&mut browser, &router, "compliance-a", 1, true).await?;
    let failed = status(&mut browser, &router, "compliance-a", "non_compliant").await?;
    ensure!(
        failed["rules"][0]["current"]["factWatermark"].as_i64() > old["factWatermark"].as_i64()
    );
    let history = ok(
        &mut browser,
        &router,
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
        &router,
        Method::GET,
        &format!("{path}/versions/1"),
        None,
    )
    .await?;
    ensure!(original["definition"]["target"]["kind"] == "all");
    let first = ok(
        &mut browser,
        &router,
        Method::GET,
        "/api/v2/devices/compliance-a/compliance/history?limit=1",
        None,
    )
    .await?;
    let next = first["nextCursor"].as_str().unwrap();
    let second = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("/api/v2/devices/compliance-a/compliance/history?limit=1&cursor={next}"),
        None,
    )
    .await?;
    ensure!(first["items"][0]["task"] != second["items"][0]["task"]);
    let (s, _) = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/devices/compliance-b/compliance/history?cursor={next}"),
            None,
        )
        .await?;
    ensure!(
        s == StatusCode::BAD_REQUEST,
        "history cursor was reused for a different device"
    );
    // Publication and its terminal audit must roll back together, including the final page.
    pg(
        "CREATE SEQUENCE public.compliance_publish_attempts; GRANT USAGE ON SEQUENCE public.compliance_publish_attempts TO mdm_flow_runtime; CREATE FUNCTION public.reject_compliance_publish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.compliance_publish_attempts'); RAISE EXCEPTION 'publication fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_compliance_publish AFTER UPDATE ON mdm_compliance.rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.current_run IS DISTINCT FROM OLD.current_run) EXECUTE FUNCTION public.reject_compliance_publish()",
    )?;
    let recompute = request(1, json!({}));
    let restarted_run = ok(
        &mut browser,
        &router,
        Method::POST,
        &format!("{path}/recompute"),
        Some(recompute.clone()),
    )
    .await?;
    ensure!(
        ok(
            &mut browser,
            &router,
            Method::POST,
            &format!("{path}/recompute"),
            Some(recompute.clone())
        )
        .await?
            == restarted_run
    );
    ensure!(
        audit_count(
            |r| r.source() == "mdm.business" && r.operation() == recompute["operationId"].as_str()
        )? == 1
    );
    let task = restarted_run["task"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if pg("SELECT is_called FROM public.compliance_publish_attempts")?.trim() == "t" {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.results WHERE task='{task}'"
        ))?
        .trim()
            == "32"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.rules WHERE current_run='{task}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")? == 0
    );
    pg(
        "DROP TRIGGER reject_compliance_publish ON mdm_compliance.rules; DROP FUNCTION public.reject_compliance_publish(); DROP SEQUENCE public.compliance_publish_attempts",
    )?;
    status(&mut browser, &router, "compliance-a", "non_compliant").await?;
    ensure!(
        audit_count(|r| r.operation() == Some(task) && r.action() == "automation_completed")? == 1
    );
    let group = Uuid::new_v4();
    let gp = format!("/api/v2/groups/{group}");
    let group_rule = json!({"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":3}});
    super::assets::ok(&mut browser,&router,Method::POST,&gp,Some(request(0,json!({"action":"create","name":"compliance target","description":"","criteria":group_rule})))).await?;
    let mut def = definition(json!({"kind":"groups","ids":[group]}));
    ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(request(1, def.clone())),
    )
    .await?;
    let unknown = status(&mut browser, &router, "compliance-a", "unknown").await?;
    ensure!(unknown["rules"][0]["current"]["reason"] == "group_unknown");
    for (revision, floor, expected) in [
        (0, 1, "not_applicable"),
        (1, 4, "non_compliant"),
        (2, 1, "not_applicable"),
    ] {
        ok(
            &mut browser,
            &router,
            Method::PUT,
            "/api/v2/devices/compliance-a/manual-fields/custom.office_floor",
            Some(request(
                revision,
                json!({"action":"set","value":{"kind":"integer","value":floor}}),
            )),
        )
        .await?;
        status(&mut browser, &router, "compliance-a", expected).await?;
    }
    // Unknown -> false leaves membership empty but must change applicability evidence.
    ok(
        &mut browser,
        &router,
        Method::PUT,
        "/api/v2/devices/compliance-b/manual-fields/custom.office_floor",
        Some(request(
            0,
            json!({"action":"set","value":{"kind":"integer","value":1}}),
        )),
    )
    .await?;
    status(&mut browser, &router, "compliance-b", "not_applicable").await?;
    let g = super::assets::ok(&mut browser, &router, Method::GET, &gp, None).await?;
    let (s, _) = browser
        .call(
            &router,
            Method::POST,
            &gp,
            Some(request(
                g["group"]["revision"].as_u64().unwrap(),
                json!({"action":"delete"}),
            )),
        )
        .await?;
    ensure!(s == StatusCode::CONFLICT, "referenced group was deleted");
    // Device-scoped authorization applies equally to history and current results.
    grants(&subject, Some("compliance-a")).await?;
    for suffix in ["compliance", "compliance/history"] {
        let (s, _) = browser
            .call(
                &router,
                Method::GET,
                &format!("/api/v2/devices/compliance-b/{suffix}"),
                None,
            )
            .await?;
        ensure!(s == StatusCode::FORBIDDEN);
    }
    let (s, _) = browser.call(&router, Method::GET, &path, None).await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            &router,
            Method::POST,
            &format!("{path}/recompute"),
            Some(request(2, json!({}))),
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            &router,
            Method::GET,
            &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    grants(&subject, None).await?;
    // Disabling removes the rule from the aggregate but preserves all previous evidence.
    def["enabled"] = json!(false);
    ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(request(2, def)),
    )
    .await?;
    ensure!(
        status(&mut browser, &router, "compliance-a", "unknown").await?["reason"] == "no_rules"
    );
    ensure!(
        !ok(
            &mut browser,
            &router,
            Method::GET,
            "/api/v2/devices/compliance-a/compliance/history",
            None
        )
        .await?["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    collected_facts(&mut browser, &router, &base).await?;
    // Database isolation and immutable history are enforced below HTTP.
    let rows = pg(
        "SET LOCAL ROLE mdm_flow_runtime; SET LOCAL rss.tenant_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; SELECT count(*) FROM mdm_compliance.results",
    )?;
    ensure!(rows.trim() == "0");
    ensure!(pg("SET LOCAL ROLE mdm_flow_runtime; DELETE FROM mdm_compliance.results").is_err());
    let before = pg("SELECT count(*) FROM mdm_compliance.versions")?;
    pg(&format!(
        "SAVEPOINT probe; INSERT INTO mdm_compliance.versions SELECT tenant_id,rule_id,100,definition FROM mdm_compliance.versions WHERE rule_id='{id}' AND revision=1; ROLLBACK TO probe"
    ))?;
    ensure!(pg("SELECT count(*) FROM mdm_compliance.versions")? == before);
    ensure!(automation.shutdown().join().await?.is_clean());
    // Rule-only race: unchanged facts cannot allow an older revision to publish.
    let restarted_definition = definition(json!({"kind":"all"}));
    let stale = ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(request(3, restarted_definition.clone())),
    )
    .await?;
    ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(request(4, restarted_definition.clone())),
    )
    .await?;
    let restarted = start_automation(&base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, &router, "compliance-a", "non_compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 5);
    let old_task = stale["task"].as_str().unwrap();
    let old = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("{path}/tasks/{old_task}"),
        None,
    )
    .await?;
    ensure!(
        old["completed"] == true && old["failure"] == "superseded",
        "stale run was published: {old}"
    );
    ensure!(restarted.shutdown().join().await?.is_clean());
    // Fact-only race: the rule revision remains unchanged across restart.
    let stale_fact = ok(
        &mut browser,
        &router,
        Method::POST,
        &format!("{path}/recompute"),
        Some(request(5, json!({}))),
    )
    .await?;
    assign(&mut browser, &router, "compliance-a", 2, false).await?;
    let restarted = start_automation(&base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, &router, "compliance-a", "compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 5);
    let old = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("{path}/tasks/{}", stale_fact["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(old["phase"] == "superseded");
    let current_task = pg(&format!(
        "SELECT current_run FROM mdm_compliance.rules WHERE id='{id}'"
    ))?;
    let progress = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("{path}/tasks/{}", current_task.trim()),
        None,
    )
    .await?;
    ensure!(progress["phase"] == "published" && progress["processed"].as_i64().unwrap() > 32);
    ensure!(restarted.shutdown().join().await?.is_clean());
    // A late transaction failure must roll back definition, receipt, enqueue and staged audit.
    pg(
        "CREATE FUNCTION public.reject_compliance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; CREATE CONSTRAINT TRIGGER reject_compliance AFTER UPDATE ON mdm_compliance.rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_compliance()",
    )?;
    let failed = request(5, restarted_definition.clone());
    let op = failed["operationId"].as_str().unwrap().to_owned();
    let (s, _) = browser
        .call(&router, Method::PUT, &path, Some(failed))
        .await?;
    pg(
        "DROP TRIGGER reject_compliance ON mdm_compliance.rules; DROP FUNCTION public.reject_compliance()",
    )?;
    ensure!(s == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(ok(&mut browser, &router, Method::GET, &path, None).await?["revision"] == 5);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_compliance.operations WHERE id='{op}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(op.as_str()))? == 0
    );
    // Group-only race: frozen membership must not survive a later group definition.
    let grouped = definition(json!({"kind":"groups","ids":[group]}));
    let stale_group = ok(
        &mut browser,
        &router,
        Method::PUT,
        &path,
        Some(request(5, grouped)),
    )
    .await?;
    let g = super::assets::ok(&mut browser, &router, Method::GET, &gp, None).await?;
    let (accepted, _) = browser.call(&router,Method::POST,&gp,Some(request(g["group"]["revision"].as_u64().unwrap(),json!({"action":"rule","criteria":{"kind":"predicate","field":"custom.office_floor","op":"ge","value":{"kind":"integer","value":0}}})))).await?;
    ensure!(accepted == StatusCode::OK);
    let restarted = start_automation(&base)
        .await
        .map_err(|e| anyhow::anyhow!("compliance worker restart: {e:?}"))?;
    let latest = status(&mut browser, &router, "compliance-a", "compliant").await?;
    ensure!(latest["rules"][0]["current"]["ruleVersion"] == 6);
    let evidence = &latest["rules"][0]["current"]["applicability"]["groups"][0];
    ensure!(evidence["decision"] == "match" && evidence["memberSet"].is_string());
    let old = ok(
        &mut browser,
        &router,
        Method::GET,
        &format!("{path}/tasks/{}", stale_group["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(old["phase"] == "superseded");
    ensure!(restarted.shutdown().join().await?.is_clean());
    ensure!(audit_count(|r| r.action() == "compliance_read")? > 0);
    reader.close().await;
    Ok(())
}
