use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn rollout_time_success_gates_and_stage_evidence() -> Result<()> {
    let mut fixture = Fixture::approved(Platform::MacOs).await?;
    let empty_scope =
        prepared_scope(&fixture.base, &mut fixture.author, &fixture.router, &[]).await?;
    let content = fixture.content.clone();
    let base = fixture.base;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let scope = fixture.scope;

    let future = Uuid::new_v4();
    let future_path = format!("/api/v1/policies/{future}");
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let future_definition = |opens_at: i64, minimum: Option<u8>| json!({"scope":scope,"action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":empty_scope,"opensAt":0},{"scope":scope,"opensAt":opens_at,"minimumVerifiedPercent":minimum}]}}});
    let future_policy = write(
        &mut author,
        &router,
        &future_path,
        0,
        json!({"action":"put","enabled":true,"definition":future_definition(now+3600,None)}),
    )
    .await?;
    let frozen_version = future_policy["versionId"].clone();
    let device_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{future}/assignments"),
            None,
        )
        .await?;
    ensure!(
        device_page.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "device page misstates execution eligibility: {device_page:?}"
    );
    let preview=author.call(&router,Method::POST,"/api/v1/policies/previews",Some(json!({"definition":future_definition(now+3600,None),"after":null,"scopeResult":null}))).await?;
    ensure!(
        preview.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "preview misstates execution eligibility: {preview:?}"
    );
    let draft_gate = future_definition(1, Some(80));
    let draft_gate = author
        .call(
            &router,
            Method::POST,
            "/api/v1/policies/previews",
            Some(json!({"definition":draft_gate})),
        )
        .await?;
    ensure!(
        draft_gate.0 == StatusCode::OK
            && draft_gate.1["items"][0]["taskAdmission"]["state"] == "success_gate",
        "draft gate must use actual denominator and zero historical success: {draft_gate:?}"
    );
    let pending = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{future}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        pending.0 == StatusCode::OK
            && pending.1["stages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["ready"] == false && s["totalTargets"] == 0),
        "online statistics should wait for recovery: {pending:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.software_stage_stats WHERE version='{}'",
            frozen_version.as_str().unwrap()
        ))?
        .trim()
            == "0",
        "online read computed statistics"
    );
    let stack = worker(&base, content).await?;
    let waiting = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        waiting.0 == StatusCode::OK && waiting.1["task"].is_null(),
        "time gate: {waiting:?}"
    );
    write(
        &mut author,
        &router,
        &future_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let edited = write(
        &mut author,
        &router,
        &future_path,
        2,
        json!({"action":"put","enabled":false,"definition":future_definition(1,Some(80))}),
    )
    .await?;
    ensure!(
        edited["versionId"] == frozen_version,
        "rollout edit changed software execution version: {edited}"
    );
    write(
        &mut author,
        &router,
        &future_path,
        3,
        json!({"action":"enable"}),
    )
    .await?;
    let gated = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        gated.0 == StatusCode::OK && gated.1["task"].is_null(),
        "optional success gate: {gated:?}"
    );
    let resumed = write(
        &mut author,
        &router,
        &future_path,
        4,
        json!({"action":"put","enabled":true,"definition":future_definition(1,None)}),
    )
    .await?;
    ensure!(resumed["versionId"] == frozen_version);
    let resumed_task = claim(&router).await?;
    ensure!(
        resumed_task["payload"]["task"]["steps"][1]["action"]["package"] == "Private.Controlled",
        "resume: {resumed_task}"
    );
    ensure!(
        event(&router, &resumed_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &resumed_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(
            &router,
            &resumed_task,
            result_event(&resumed_task, "install", Some(0), "present", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let reordered=write(&mut author,&router,&future_path,5,json!({"action":"put","enabled":true,
        "definition":{"scope":scope,
        "action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"runLifetimeSeconds":600,
        "rollout":{"stages":[{"scope":scope,"opensAt":0},{"scope":empty_scope,"opensAt":1}]}}}})).await?;
    ensure!(reordered["versionId"] == frozen_version);
    let reordered_status = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let status = author
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v1/policies/{future}/software/rollout"),
                    None,
                )
                .await?;
            if status.1["stages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["ready"] == true)
            {
                return Ok::<_, anyhow::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    ensure!(
        reordered_status.1["stages"][0]["verifiedSuccess"] == 1
            && reordered_status.1["stages"][1]["verifiedSuccess"] == 0,
        "stage edit reused another scope's evidence: {reordered_status:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn new_approval_changes_execution_version() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;

    let scope = fixture.scope;
    let authored = |intent: &str| authored(resource, scope, intent);
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v1/policies/{policy}");
    let published = write(
        &mut author,
        &router,
        &policy_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install")}),
    )
    .await?;
    ensure!(published["version"] == 1, "publish: {published}");
    write(
        &mut author,
        &router,
        &policy_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(
        &mut author,
        &router,
        &format!("/api/v1/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    write(
        &mut author,
        &router,
        &format!("/api/v1/software/resources/{resource}/versions/v1"),
        2,
        json!({"action":"enable"}),
    )
    .await?;

    let rebound = write(
        &mut author,
        &router,
        &policy_path,
        2,
        json!({"action":"put","enabled":false,"definition":authored("required_install")}),
    )
    .await?;
    ensure!(
        rebound["versionId"] != published["versionId"],
        "reapproval must create a new execution version: {rebound}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn rollout_statistics_checkpoint_excluded_pages_and_reject_stale_inputs() -> Result<()> {
    let mut f = Fixture::approved(Platform::MacOs).await?;
    let mut devices = Vec::new();
    for i in 0..20 {
        let device = format!(
            "{}-stats-{i:02}",
            crate::test_support::case::name("rollout")
        );
        crate::test_support::inventory::seed_source(&device, "agent", "agent.builtin", "stats")?;
        devices.push(device);
    }
    let refs: Vec<&str> = devices.iter().map(String::as_str).collect();
    let root = prepared_scope(&f.base, &mut f.author, &f.router, &refs).await?;
    let stage = Uuid::new_v4();
    let automation = start_automation(&f.base).await?;
    let created=write(&mut f.author,&f.router,&format!("/api/v1/scopes/{stage}"),0,json!({"action":"put","definition":{"targets":devices.iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>(),"limitations":null,"exclusions":devices[..16].iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>()}})).await?;
    await_task(
        &mut f.author,
        &f.router,
        &format!(
            "/api/v1/scopes/{stage}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    crate::test_support::stop_worker(automation).await?;
    let policy = Uuid::new_v4();
    let mut definition = authored(f.resource, root, "required_install");
    definition["action"]["rollout"] = json!({"stages":[{"scope":stage,"opensAt":0}]});
    let published = write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/policies/{policy}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    let version = published["versionId"].as_str().unwrap();
    f.execution.recover_action_fixture(policy).await?;
    let first:Value=serde_json::from_str(pg(&format!("SELECT jsonb_build_object('cursor',cursor,'ready',ready,'counts',counts) FROM mdm_commands.software_stage_stats WHERE version='{version}' AND stage=0"))?.trim())?;
    ensure!(
        first["ready"] == false
            && first["counts"]["scanned"] == 16
            && first["counts"]["total"] == 0,
        "excluded page did not checkpoint: {first}"
    );
    let pending = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        pending.0 == StatusCode::OK && pending.1["stages"][0]["ready"] == false,
        "partial statistics escaped online: {pending:?}"
    );
    let changed_registration = pg(&format!(
        "SELECT id FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}' AND channel='agent' AND state='active'",
        case_tenant(),
        devices[0]
    ))?;
    pg(&format!(
        "INSERT INTO mdm_agent.bindings SELECT b.tenant_id,'{}'::uuid,b.wire_version,b.capabilities,b.platform,b.architecture,b.execution_context FROM mdm_agent.bindings b JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(b.tenant_id,b.registration) WHERE r.tenant_id='{}' AND r.device='{}' LIMIT 1",
        changed_registration.trim(),
        case_tenant(),
        crate::test_support::software_execution::case_device()
    ))?;
    // A storage failure at the checkpoint must roll back this page, then permit recovery.
    let guard = format!("stats_fail_{}", policy.simple());
    pg(&format!(
        "CREATE FUNCTION public.{guard}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.version='{version}'::uuid AND (NEW.counts->>'scanned')::bigint>(OLD.counts->>'scanned')::bigint THEN RAISE EXCEPTION 'fixture storage fault'; END IF; RETURN NEW; END $$; REVOKE ALL ON FUNCTION public.{guard}() FROM PUBLIC; CREATE TRIGGER {guard} BEFORE UPDATE ON mdm_commands.software_stage_stats FOR EACH ROW EXECUTE FUNCTION public.{guard}();"
    ))?;
    let rejected = f.execution.recover_action_fixture(policy).await;
    pg(&format!(
        "DROP TRIGGER {guard} ON mdm_commands.software_stage_stats; DROP FUNCTION public.{guard}();"
    ))?;
    ensure!(rejected.is_err(), "checkpoint storage fault was accepted");
    let unchanged:Value=serde_json::from_str(pg(&format!("SELECT jsonb_build_object('cursor',cursor,'ready',ready,'counts',counts) FROM mdm_commands.software_stage_stats WHERE version='{version}' AND stage=0"))?.trim())?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.software_stats_members WHERE version='{version}' AND stage=0"))?.trim()=="0","rolled back contributions remained");
    ensure!(
        unchanged == first,
        "rolled back page advanced durable statistics"
    );
    f.execution.recover_action_fixture(policy).await?;
    ensure!(pg(&format!("SELECT counts->>'scanned' FROM mdm_commands.software_stage_stats WHERE version='{version}' AND stage=0"))?.trim()=="20","binding update restarted membership scan");
    f.execution.recover_action_fixture(policy).await?;
    let ready = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        ready.0 == StatusCode::OK
            && ready.1["stages"][0]["ready"] == true
            && ready.1["stages"][0]["totalTargets"] == 4
            && ready.1["stages"][0]["unsupportedCapability"] == 4,
        "resumed reduction miscounted fixed channel targets: {ready:?}"
    );
    let statistics_generation = pg(&format!(
        "SELECT generation FROM mdm_commands.software_stage_stats WHERE version='{version}' AND stage=0"
    ))?;
    let automation = start_automation(&f.base).await?;
    let recalculated=write(&mut f.author,&f.router,&format!("/api/v1/scopes/{stage}"),1,json!({"action":"put","definition":{"targets":devices.iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>(),"limitations":null,"exclusions":devices[..16].iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>()}})).await?;
    await_task(
        &mut f.author,
        &f.router,
        &format!(
            "/api/v1/scopes/{stage}/tasks/{}",
            recalculated["task"].as_str().unwrap()
        ),
    )
    .await?;
    crate::test_support::stop_worker(automation).await?;
    let unchanged = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        unchanged.1["stages"][0]["ready"] == true && unchanged.1["stages"][0]["totalTargets"] == 4,
        "equivalent channel set invalidated statistics: {unchanged:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT generation FROM mdm_commands.software_stage_stats WHERE version='{version}' AND stage=0"
        ))? == statistics_generation,
        "equivalent channel set rebuilt denominator"
    );
    write(&mut f.author,&f.router,&format!("/api/v1/scopes/{stage}"),2,json!({"action":"put","definition":{"targets":devices.iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>(),"limitations":null,"exclusions":devices.iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>()}})).await?;
    let stale = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        stale.0 == StatusCode::OK && stale.1["stages"][0]["ready"] == false,
        "stale Scope statistics remained ready: {stale:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE policy_version='{version}'"
        ))?
        .trim()
            == "0",
        "statistics created execution effects"
    );
    Ok(())
}
