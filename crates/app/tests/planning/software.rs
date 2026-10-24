use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::{http::*, process::*, runtime::*, *};
use anyhow::Context;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn rollout_time_success_gates_and_stage_evidence() -> Result<()> {
    let mut fixture = Fixture::with_profiles(
        Platform::MacOs,
        json!(["inventory.collect.v1", "software.pkg.system.v1"]),
        context(Platform::MacOs),
    )
    .await?;
    fixture.seed_root(json!([])).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let empty_scope = prepared_scope(&fixture.planning, &[]).await?;
    let first_device = case::name("rollout-first");
    let first_credential = crate::test_support::runtime::credential("rollout-first");
    crate::test_support::agent::seed_profile(&fixture.base, fixture.execution.clone(), &first_credential, first_device,
        json!({"capabilities":["inventory.collect.v1","software.pkg.system.v1"],"platform":"macos","architecture":"aarch64","executionContext":context(Platform::MacOs)})).await?;
    let first_scope = prepared_scope(&fixture.planning, &[first_device]).await?;
    let root_scope = prepared_scope(&fixture.planning, &[first_device, crate::test_support::software_execution::case_device()]).await?;
    let execution = fixture.execution.clone();
    let base = fixture.base;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let scope = fixture.scope;

    let future = Uuid::new_v4();
    let future_path = format!("/api/v1/policies/{future}");
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let future_definition = |opens_at: i64, minimum: Option<u8>| json!({"scope":root_scope,"action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":first_scope,"opensAt":0},{"scope":scope,"opensAt":opens_at,"minimumVerifiedPercent":minimum}]}}});
    let future_policy = write(
        &mut author,
        &router,
        &future_path,
        0,
        json!({"action":"put","enabled":true,"definition":future_definition(now+3600,None)}),
    )
    .await?;
    let frozen_version = future_policy["versionId"].clone();
    let deletion=author.call(&router,Method::POST,&format!("/api/v1/scopes/{first_scope}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"delete"}}))).await?;
    ensure!(deletion.0==StatusCode::CONFLICT,"rollout-only Scope reference allowed deletion: {deletion:?}");

    let device_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{future}/assignments"),
            None,
        )
        .await?;
    ensure!(
        device_page.1["items"].as_array().unwrap().iter().find(|item| item["object"]["id"] == crate::test_support::software_execution::case_device()).expect("later-stage target missing")["taskAdmission"]["state"] == "scheduled",
        "device page misstates execution eligibility: {device_page:?}"
    );
    let preview=author.call(&router,Method::POST,"/api/v1/policies/previews",Some(json!({"definition":future_definition(now+3600,None),"after":null,"scopeResult":null}))).await?;
    ensure!(
        preview.1["items"].as_array().unwrap().iter().find(|item| item["object"]["id"] == crate::test_support::software_execution::case_device()).expect("later-stage target missing")["taskAdmission"]["state"] == "scheduled",
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
            && draft_gate.1["items"].as_array().unwrap().iter().find(|item| item["object"]["id"] == crate::test_support::software_execution::case_device()).expect("later-stage target missing")["taskAdmission"]["state"] == "success_gate",
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
            && pending.1["stages"].as_array().unwrap().len() == 2
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
    let stack = worker(&base, execution).await?;
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
    let first_task = claim_with(&router, &first_credential, Platform::MacOs).await.context("first-stage offer")?;
    for kind in [json!({"kind":"received"}), json!({"kind":"start"}), result_event(&first_task, "install", Some(0), "present", false)?] {
        ensure!(event_with(&router, &first_credential, &first_task, kind).await?.0 == StatusCode::OK);
    }
    let progress = ready_rollout(&mut author, &router, future).await?;
    ensure!(progress.1["stages"][0]["verifiedSuccess"] == 1, "{progress:?}");
    let eligible = author.call(&router, Method::GET, &format!("/api/v1/policies/{future}/assignments"), None).await?;
    ensure!(eligible.0 == StatusCode::OK && eligible.1["items"].as_array().unwrap().iter().find(|item| item["object"]["id"] == crate::test_support::software_execution::case_device()).unwrap()["taskAdmission"]["state"] == "eligible", "completed first stage did not open the second: {eligible:?}; progress={progress:?}");
    let resumed_task = claim(&router).await.map_err(|e| anyhow::anyhow!("second-stage offer: {e:#}; runs={:?}", pg(&format!("SELECT jsonb_agg(jsonb_build_object('device',device,'state',state,'occurrence',occurrence)) FROM mdm_commands.action_runs WHERE tenant_id='{}'",case_tenant()))))?;
    ensure!(
        resumed_task["payload"]["task"]["steps"][0]["action"]["package"] == "Private.Controlled",
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
    let reordered=write(&mut author,&router,&future_path,4,json!({"action":"put","enabled":true,
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
            ensure!(
                status.0 == StatusCode::OK && status.1["stages"].as_array().unwrap().len() == 2
            );
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
    .await.context("reordered stage statistics")??;
    ensure!(
        reordered_status.1["stages"][0]["verifiedSuccess"] == 1
            && reordered_status.1["stages"][1]["verifiedSuccess"] == 0,
        "stage edit reused another scope's evidence: {reordered_status:?}"
    );
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn new_approval_changes_execution_version() -> Result<()> {
    let mut fixture = Fixture::with_profiles(
        Platform::MacOs,
        json!(["inventory.collect.v1", "software.pkg.system.v1"]),
        context(Platform::MacOs),
    )
    .await?;
    fixture.seed_root(json!([])).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
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
            let unchanged = write(
                &mut author,
                &router,
                &policy_path,
                1,
                json!({"action":"put","enabled":true,"definition":authored("required_install")}),
            )
            .await?;
            ensure!(unchanged["versionId"] == published["versionId"]);
            let frozen = pg(&format!(
                "SELECT frozen FROM mdm_policy.versions WHERE tenant_id='{}' AND id='{}'",
                case_tenant(),
                published["versionId"].as_str().unwrap()
            ))?;
            write(
                &mut author,
                &router,
                &policy_path,
                2,
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
                3,
                json!({"action":"put","enabled":false,"definition":authored("required_install")}),
            )
            .await?;
            ensure!(
                rebound["versionId"] != published["versionId"],
                "reapproval must create a new execution version: {rebound}"
            );
            ensure!(
                pg(&format!(
                    "SELECT frozen FROM mdm_policy.versions WHERE tenant_id='{}' AND id='{}'",
                    case_tenant(),
                    rebound["versionId"].as_str().unwrap()
                ))? != frozen
            );
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn rollout_statistics_checkpoint_excluded_pages_and_reject_stale_inputs() -> Result<()> {
    let mut f = Fixture::with_profiles(
        Platform::MacOs,
        json!(["inventory.collect.v1", "software.pkg.system.v1"]),
        context(Platform::MacOs),
    )
    .await?;
    f.seed_root(json!([])).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let prefix = case::name("rollout");
    let devices: Vec<_> = (0..20).map(|i| format!("{prefix}-stats-{i:02}")).collect();
    // Only registration/channel presence is consumed here; Inventory facts and enrollment are not under test.
    pg(&format!("BEGIN; CREATE TEMP TABLE rollout_devices AS SELECT '{prefix}-stats-'||lpad(n::text,2,'0') AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS registration,gen_random_uuid() AS credential,gen_random_uuid() AS epoch FROM generate_series(0,19) n; INSERT INTO mdm_access.devices SELECT '{tenant}',device FROM rollout_devices; INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) SELECT '{tenant}',grant_id,gen_random_uuid(),'download','fixture','{instance}',device,'macos',repeat('0',64),repeat('0',64),'consumed',clock_timestamp()+interval '24 hours' FROM rollout_devices; INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch) SELECT '{tenant}',registration,device,'agent',1,grant_id,'active','primary',epoch FROM rollout_devices; INSERT INTO mdm_access.credentials SELECT '{tenant}',credential,registration,'agent',md5(credential::text)||md5(registration::text),'active' FROM rollout_devices; INSERT INTO mdm_access.report_sources SELECT '{tenant}',registration,'agent.builtin',epoch,true FROM rollout_devices; COMMIT;", tenant=case_tenant(), instance=INSTANCE))?;
    let refs: Vec<&str> = devices.iter().map(String::as_str).collect();
    let root = prepared_scope(&f.planning, &refs).await?;
    let stage = Uuid::new_v4();
    let definition: crate::planning::ScopeDefinition = serde_json::from_value(json!({"targets":devices.iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>(),"limitations":null,"exclusions":devices[..16].iter().map(|d|json!({"kind":"device","id":d})).collect::<Vec<_>>()}))?;
    f.planning.runtime.local_tx_with_context(f.planning.tenant, crate::identity::deadline(), (f.planning.as_ref(), definition), |(planning, definition), tx| {
        let definition = definition.clone();
        Box::pin(async move { planning.seed_scope_in(tx, stage, definition).await.map_err(|e| rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(e.to_string()))) })
    }).await.fold(|_| (),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"),|e|panic!("{e:?}"));
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
    crate::test_support::runtime::stop_worker(automation).await?;
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
    }).await
}
