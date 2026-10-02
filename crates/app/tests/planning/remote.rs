use crate::test_support::agent_execution::*;
use crate::test_support::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.remote"]
async fn scope_snapshot_result_views_and_authorization() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    let base = &fixture.base;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let grants = fixture.grants;
    let member = browser_subject(author, router).await?;
    let mut grants = grants.clone();
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["enrollment", "operation_read", "operation_cancel"],
    )?);
    crate::test_support::identity::set_grants(case_tenant(), &member, grants.clone()).await?;
    let automation = start_automation(base).await?;
    let scope = Uuid::new_v4();
    let created=post(author,router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device_id()}],"limitations":null,"exclusions":[]}}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    let id = Uuid::new_v4();
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let input = json!({"operationId":id,"resource":policy_definition(resource,case_empty_scope())["action"]["resource"],"targets":{"kind":"scope","id":scope},"action":{"kind":"execute","parameters":{}},"deadline":now+600});
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    let accepted = post(author, router, "/api/v3/remote-operations", input.clone()).await?;
    ensure!(accepted == post(author, router, "/api/v3/remote-operations", input).await?);
    let directory = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/remote-operations?kind=script&resource={resource}"),
            None,
        )
        .await?;
    ensure!(
        directory.0 == StatusCode::OK
            && directory.1["items"][0]["id"] == id.to_string()
            && directory.1["statistics"]["total"] == 1,
        "remote directory: {directory:?}"
    );
    let changed=post(author,router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            changed["task"].as_str().unwrap()
        ),
    )
    .await?;
    let owner = worker(base).await?;
    let task=claim(router).await.map_err(|e|anyhow::anyhow!("remote snapshot claim: {e}; state {}",pg(&format!("SELECT jsonb_build_object('operation',(SELECT to_jsonb(o)-'frozen'-'author' FROM mdm_planning.remote_operations o WHERE id='{id}'),'targets',(SELECT jsonb_agg(t) FROM mdm_planning.remote_operation_targets t WHERE operation='{id}'),'runs',(SELECT jsonb_agg(jsonb_build_object('id',r.id,'state',r.state,'gateway',r.gateway_accepted)) FROM mdm_commands.action_runs r WHERE remote_operation='{id}'))" )).unwrap_or_default()))?;
    let task_id = task["payload"]["taskId"].as_str().unwrap();
    ensure!(
        pg(&format!(
            "SELECT remote_operation FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == id.to_string(),
        "remote snapshot changed with Scope"
    );
    task_event(router, &task, json!({"kind":"received"})).await?;
    task_event(router, &task, json!({"kind":"start"})).await?;
    task_event(router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    let summary = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/remote-operations/{id}"),
            None,
        )
        .await?;
    ensure!(
        summary.0 == StatusCode::OK && summary.1["items"][0]["result"]["exitCode"] == 0,
        "remote result summary missing: {summary:?}"
    );
    ensure!(
        summary.1["items"][0]["result"].get("output").is_none()
            && summary.1["items"][0]["result"]["diagnostics"]
                .get("stdout")
                .is_none(),
        "remote summary disclosed streams"
    );
    let detail = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/remote-operations/{id}/runs/{task_id}"),
            None,
        )
        .await?;
    ensure!(
        detail.0 == StatusCode::OK
            && detail.1["result"]["output"]["version"] == "1.2"
            && detail.1["result"]["diagnostics"]["stdout"] == "captured stdout",
        "remote run detail unavailable: {detail:?}"
    );
    let wrong = author
        .call(
            router,
            Method::GET,
            &format!(
                "/api/v3/remote-operations/{}/runs/{task_id}",
                Uuid::new_v4()
            ),
            None,
        )
        .await?;
    ensure!(
        wrong.0 == StatusCode::NOT_FOUND,
        "remote detail accepted the wrong parent: {wrong:?}"
    );
    let without_read = grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::OperationRead)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &member, without_read).await?;
    let denied = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/remote-operations/{id}/runs/{task_id}"),
            None,
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "remote detail bypassed OperationRead: {denied:?}"
    );
    ensure!(
        author
            .call(router, Method::GET, "/api/v3/remote-operations", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    crate::test_support::identity::set_grants(case_tenant(), &member, grants).await?;
    ensure!(
        summary.1["phase"] == "completed",
        "successful remote work still appears unfinished"
    );
    crate::test_support::stop_worker(owner).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}'",
            case_tenant()
        ))? == before
    );
    crate::test_support::stop_worker(automation).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.remote"]
async fn bulk_pages_restart_and_cancellation_are_durable() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    let base = &fixture.base;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let grants = fixture.grants;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let member = browser_subject(author, router).await?;
    let mut grants = grants.clone();
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["enrollment", "operation_read", "operation_cancel"],
    )?);
    crate::test_support::identity::set_grants(case_tenant(), &member, grants.clone()).await?;
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    let mut devices = crate::test_support::agent::bulk_task_agents(case_device_id(), 129)?;
    devices.extend((0..171).map(|n| format!("unregistered-{n:04}")));
    let bulk = Uuid::new_v4();
    post(author,router,"/api/v3/remote-operations",json!({"operationId":bulk,"resource":policy_definition(resource,case_empty_scope())["action"]["resource"],"targets":{"kind":"devices","devices":devices},"action":{"kind":"execute","parameters":{}},"deadline":now+600})).await?;
    let mut owner = worker(base).await?;
    checkpoint(bulk, false).await?;
    crate::test_support::stop_worker(owner).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_planning.remote_operation_targets WHERE operation='{bulk}'"
        ))?
        .trim()
        .parse::<usize>()?
            < 301
    );
    owner = worker(base).await?;
    checkpoint(bulk, true).await?;
    crate::test_support::stop_worker(owner).await?;
    ensure!(
        pg(&format!(
            "SELECT run_after IS NOT NULL FROM mdm_planning.remote_operations WHERE id='{bulk}'"
        ))?
        .trim()
            == "t"
    );
    owner = worker(base).await?;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if pg(&format!(
                "SELECT staged FROM mdm_planning.remote_operations WHERE id='{bulk}'"
            ))?
            .trim()
                == "t"
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_planning.remote_operation_targets WHERE operation='{bulk}'"
        ))?
        .trim()
            == "301"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_planning.remote_operation_targets WHERE operation='{bulk}' AND status='blocked'"))?.trim()=="171");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{}'",
            case_tenant()
        ))? == before
    );
    ensure!(pg(&format!("SELECT count(DISTINCT delivery_id) FROM mdm_planning.remote_operation_targets WHERE operation='{bulk}' AND status='accepted'"))?.trim()=="130");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE remote_operation='{bulk}'"
        ))?
        .trim()
            == "130"
    );
    let task = claim(router).await.map_err(|error| anyhow::anyhow!("bulk claim: {error}; {}",pg(&format!("SELECT jsonb_build_object('runs',(SELECT jsonb_agg(jsonb_build_object('id',id,'state',state,'gateway',gateway_accepted,'available',available_at,'deadline',deadline,'registration',registration)) FROM mdm_commands.action_runs WHERE remote_operation='{bulk}' AND device='{DEVICE_ID}'),'target',(SELECT to_jsonb(t) FROM mdm_planning.remote_operation_targets t WHERE operation='{bulk}' AND device='{DEVICE_ID}'))", DEVICE_ID = case_device_id())).unwrap_or_default()))?;
    let task_id = task["payload"]["taskId"].as_str().unwrap();
    ensure!(
        pg(&format!(
            "SELECT remote_operation FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == bulk.to_string()
    );
    crate::test_support::stop_worker(owner).await?;
    let cancelled = post(
        author,
        router,
        &format!("/api/v3/remote-operations/{bulk}/cancel"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    ensure!(cancelled["cancellationRequested"] == true);
    let progress = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/remote-operations/{bulk}"),
            None,
        )
        .await?;
    ensure!(
        progress.0 == StatusCode::OK && progress.1["phase"] == "cancelling",
        "cancel intent was reported as completion: {progress:?}"
    );
    let mut event = json!({"kind":"start"});
    ensure!(
        task_event_request(router, &task, Uuid::new_v4(), &mut event)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    owner = worker(base).await?;
    await_cancelled(author, router, bulk).await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs WHERE remote_operation='{bulk}' AND state->>'cancellation'='confirmed'"))?.trim()=="130");
    crate::test_support::stop_worker(owner).await?;
    Ok(())
}
async fn checkpoint(operation: Uuid, recovery: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60),async {loop {
        let progress:Value=serde_json::from_str(pg(&format!("SELECT jsonb_build_object('cursor',cursor,'runAfter',run_after,'staged',staged) FROM mdm_planning.remote_operations WHERE id='{operation}'"))?.trim())?;
        let key=if recovery {"runAfter"}else{"cursor"};
        if !progress[key].is_null() {
            ensure!(recovery || progress["staged"]==false,"worker skipped the checkpoint boundary: {progress}");return Ok::<_,anyhow::Error>(());
        }
        ensure!(recovery || progress["staged"]==false,"all pages finished before restart: {progress}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await?
}
async fn await_cancelled(author: &mut Browser, router: &Router, id: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let reply = author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v3/remote-operations/{id}"),
                    None,
                )
                .await?;
            if reply.0 == StatusCode::SERVICE_UNAVAILABLE {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            ensure!(reply.0 == StatusCode::OK, "remote progress: {reply:?}");
            if reply.1["phase"] == "completed" {
                ensure!(reply.1["cancellationRequested"] == true);
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(
                reply.1["phase"] == "cancelling",
                "premature or unexpected terminal phase: {reply:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
