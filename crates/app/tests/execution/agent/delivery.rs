use crate::test_support::agent_execution::*;
use crate::test_support::*;
use ring::signature::KeyPair;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn registration_capability_and_wire_gate() -> Result<()> {
    let fixture = Fixture::new().await?;
    let router = fixture.router;
    let mut author = fixture.author;
    author.operation = Some(Uuid::new_v4());
    let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let enrollment = post(
        &mut author,
        &router,
        "/api/v3/enrollments",
        json!({"deviceId":case_device_id(),"password":password,"source":"agent.builtin"}),
    )
    .await?;
    author.operation = None;
    let registration=agent_call(&router,Method::POST,"/api/agent/v5/registrations",None,Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":case_inventory_credential(),"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v5"]}))).await?;
    ensure!(
        registration.0 == StatusCode::CREATED
            && registration.1["capabilities"] == json!(["inventory.collect.v5"]),
        "registration: {registration:?}"
    );
    let taskless = agent_call(
        &router,
        Method::POST,
        "/api/agent/v5/tasks/claim",
        Some(case_inventory_credential()),
        Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"profiles":["posix_sh","bash","power_shell7","osquery"]})),
    )
    .await?;
    ensure!(
        taskless.0 == StatusCode::FORBIDDEN,
        "inventory-only registration entered task API: {taskless:?}"
    );
    author.operation = Some(Uuid::new_v4());
    let enrollment = post(
        &mut author,
        &router,
        "/api/v3/enrollments",
        json!({"deviceId":case_device_id(),"password":password,"source":"agent.builtin"}),
    )
    .await?;
    author.operation = None;
    let registration=agent_call(&router,Method::POST,"/api/agent/v5/registrations",None,Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":case_credential(),"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v5","task.execute.v5"]}))).await?;
    ensure!(
        registration.0 == StatusCode::CREATED
            && registration.1["capabilities"] == json!(["inventory.collect.v5", "task.execute.v5"]),
        "task registration: {registration:?}"
    );
    // Legacy URL and major cannot enter task intake.
    let old = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/agent/v2/tasks/claim")
                .header("host", "mdm.example.test")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(old.status() == StatusCode::NOT_FOUND);
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/agent/v5/tasks/claim",
            Some(case_credential()),
            Some(json!({"wireVersion":2,"operationId":Uuid::new_v4()}))
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn offer_start_result_replay_and_inventory_projection() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let registration = fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let base = fixture.base;
    let router = fixture.router;
    let execution = fixture.execution;
    let mut author = fixture.author;
    let key = fixture.key;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let policy_id = publish(&mut author, &router, id).await?;
    let first = claim_request(&router, Uuid::new_v4()).await?;
    ensure!(first.0 == StatusCode::OK, "lazy acceptance: {first:?}");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="1");
    tokio::time::timeout(Duration::from_secs(15),async {loop {
        if pg(&format!("SELECT gateway_accepted FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="t" {break Ok::<_,anyhow::Error>(());}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await??;
    if !first.1["task"].is_null() {
        pg(&format!(
            "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{delivery,leaseUntil}}','0') WHERE tenant_id='{}' AND id='{}'",
            case_tenant(),
            first.1["task"]["payload"]["taskId"].as_str().unwrap()
        ))?;
    }
    let claim_operation = Uuid::new_v4();
    execution.inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(
        claim_request(&router, claim_operation).await?.0 == StatusCode::SERVICE_UNAVAILABLE,
        "claim commit-pending fault was not surfaced"
    );
    let claim_response = claim_request(&router, claim_operation).await?;
    ensure!(claim_response.0 == StatusCode::OK && !claim_response.1["task"].is_null());
    ensure!(
        claim_response == claim_request(&router, claim_operation).await?,
        "claim retry receipt changed"
    );
    let task = claim_response.1["task"].clone();
    let signed: rss_mdm_agent_wire::SignedTask = serde_json::from_value(task.clone())?;
    let context = rss_mdm_agent_wire::TaskVerification {
        key_id: "t2",
        public_key: key.public_key().as_ref(),
        tenant_id: Uuid::parse_str(case_tenant())?,
        device_id: case_device_id(),
        platform: rss_mdm_agent_wire::TaskPlatform::Macos,
        architecture: rss_mdm_agent_wire::TaskArchitecture::Aarch64,
        registration_id: Uuid::parse_str(registration["registrationId"].as_str().unwrap())?,
        generation: registration["generation"].as_u64().unwrap(),
        task_id: signed.payload.task_id(),
        attempt_id: signed.payload.attempt_id(),
        permit: rss_mdm_agent_wire::TaskPermit::Offer,
        now,
    };
    signed.verify(&context)?;
    let attempt = signed.payload.attempt_id();
    let reserved = pg(&format!(
        "SELECT sequence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='pending' AND sealed_at IS NULL",
        case_tenant()
    ))?;
    ensure!(
        !reserved.trim().is_empty(),
        "collection was not frozen before Offer"
    );
    task_event(&router, &task, json!({"kind":"received"})).await?;
    let permit = task_event(&router, &task, json!({"kind":"start"})).await?;
    let ack: rss_mdm_agent_wire::TaskEventAck = serde_json::from_value(permit)?;
    ack.into_permit()
        .unwrap()
        .verify(&rss_mdm_agent_wire::TaskVerification {
            permit: rss_mdm_agent_wire::TaskPermit::Start,
            ..context
        })?;
    let result_operation = Uuid::new_v4();
    let mut result = json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}});
    execution.inject_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    ensure!(
        task_event_request(&router, &task, result_operation, &mut result)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE,
        "result commit-unknown fault was not surfaced"
    );
    let accepted = task_event_request(&router, &task, result_operation, &mut result).await?;
    ensure!(accepted.0 == StatusCode::OK);
    ensure!(
        accepted == task_event_request(&router, &task, result_operation, &mut result).await?,
        "result retry receipt changed"
    );
    let mut conflict = result.clone();
    conflict["output"]["version"] = json!("different");
    ensure!(
        task_event_request(&router, &task, result_operation, &mut conflict)
            .await?
            .0
            == StatusCode::CONFLICT,
        "result operation accepted conflicting payload"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_receipts WHERE id='{result_operation}'"
        ))?
        .trim()
            == "1"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND registration='{}' AND source='agent.script' AND delivery_pending", case_tenant(), registration["registrationId"].as_str().unwrap()))?.trim()=="1");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM rss_device_command.commands WHERE command_id='{}'",
            signed.payload.task_id()
        ))?
        .trim()
            == "0"
    );
    ensure!(
        pg(&format!(
            "SELECT sequence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='snapshot'",
            case_tenant()
        ))? == reserved,
        "result changed collection ordering"
    );
    let runtime = agent_runtime(&base).await?;
    let inventory = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if pg(
                &format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.script' AND state='known'", case_tenant(), registration["registrationId"].as_str().unwrap()),
            )?
            .trim()
                == "2"
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let (_, detail) = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/devices/{DEVICE_ID}/inventory",
                DEVICE_ID = case_device_id()
            ),
            None,
        )
        .await?;
    ensure!(
        detail["asset"]["device"]["fields"]["custom.corporate_agent.healthy"]["state"]["value"]["value"]
            == true,
        "detail: {detail}"
    );
    crate::test_support::stop_worker(inventory).await?;
    runtime.close_fixture().await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn chunked_results_require_complete_output_and_preserve_attempt_identity() -> Result<()> {
    use rss_mdm_agent_wire as wire;
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _, _) = fixture.resource_with_output_limit(524288).await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    publish(&mut fixture.author, &fixture.router, resource).await?;
    let task = claim(&fixture.router).await?;
    task_event(&fixture.router, &task, json!({"kind":"received"})).await?;
    task_event(&fixture.router, &task, json!({"kind":"start"})).await?;
    let result = wire::TaskResult::new(
        Some(0),
        wire::OutputQuality::Complete,
        json!({"version":"1.2","healthy":true,"padding":"x".repeat(400000)}),
        wire::TaskDiagnostics::new("".into(), "".into(), 1, 1, None)?,
    )?;
    let (reference, chunks) = wire::ChunkedTaskResult::split(result)?;
    ensure!(chunks.len() == 2);
    let mut final_event = serde_json::to_value(wire::TaskEvent::ChunkedResult(reference))?;
    ensure!(
        task_event_request(&fixture.router, &task, Uuid::new_v4(), &mut final_event)
            .await?
            .0
            == StatusCode::BAD_REQUEST,
        "missing output was accepted"
    );
    let operation = Uuid::new_v4();
    let mut first = serde_json::to_value(wire::TaskEvent::OutputChunk(chunks[0].clone()))?;
    let response = task_event_request(&fixture.router, &task, operation, &mut first).await?;
    ensure!(response.0 == StatusCode::OK);
    ensure!(response == task_event_request(&fixture.router, &task, operation, &mut first).await?);
    let bad = wire::OutputChunk::new(
        chunks[0].manifest().clone(),
        0,
        &vec![b'z'; wire::OUTPUT_CHUNK_BYTES],
    )?;
    let mut conflict = serde_json::to_value(wire::TaskEvent::OutputChunk(bad))?;
    ensure!(
        task_event_request(&fixture.router, &task, Uuid::new_v4(), &mut conflict)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    task_event(
        &fixture.router,
        &task,
        serde_json::to_value(wire::TaskEvent::OutputChunk(chunks[1].clone()))?,
    )
    .await?;
    task_event(&fixture.router, &task, final_event).await?;
    let attempt = task["payload"]["attemptId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='snapshot'",case_tenant()))?.trim()=="1");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.output_chunks WHERE tenant_id='{}' AND attempt='{attempt}'",case_tenant()))?.trim()=="2");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
