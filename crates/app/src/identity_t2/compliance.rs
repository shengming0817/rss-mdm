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
    tokio::time::timeout(Duration::from_secs(30), async {
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
        let checkpoint=pg("SELECT json_agg(row_to_json(d)) FROM mdm_compliance.dispatch d");
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "make t2-compliance: authenticated Router, real PG and production automation"]
async fn rules_facts_groups_history_and_authorization() -> Result<()> {
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let config: Config = serde_json::from_value(base.clone())?;
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
    ensure!(unknown["rules"][0]["current"]["reason"] == "applicability_unknown");
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
    // Restart with an older frozen task and a newer fact: only the latter may publish.
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
    assign(&mut browser, &router, "compliance-a", 2, false).await?;
    let restarted = start_automation(&base).await?;
    let latest = status(&mut browser, &router, "compliance-a", "compliant").await?;
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
    reader.close().await;
    Ok(())
}
