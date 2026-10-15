#[path = "windows_assets.rs"]
mod windows_assets;
use crate::test_support::agent_execution::*;
use crate::test_support::*;
use ring::signature::KeyPair;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn registration_capability_and_wire_gate() -> Result<()> {
    let fixture = Fixture::new().await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let (_,registration)=crate::test_support::agent::enroll_profile(&router,&mut author,case_inventory_credential(),json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
    ensure!(registration["capabilities"] == json!(["inventory.collect.v1"]));
    let taskless = agent_call(
        &router,
        Method::POST,
        "/api/v1/agent/runtime/tasks/claim",
        Some(case_inventory_credential()),
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        taskless.0 == StatusCode::FORBIDDEN,
        "inventory-only registration entered task API: {taskless:?}"
    );
    let (_,registration)=crate::test_support::agent::enroll_profile(&router,&mut author,case_credential(),json!({"capabilities":["inventory.collect.v1","task.execute.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
    ensure!(registration["capabilities"] == json!(["inventory.collect.v1", "task.execute.v1"]));
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
    let operation = Uuid::new_v4();
    let valid = json!({"wireVersion":1,"operationId":operation,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"]});
    for version in [2, 3, 4, 5, 6, 255] {
        let mut retired = valid.clone();
        retired["wireVersion"] = json!(version);
        ensure!(
            agent_call(
                &router,
                Method::POST,
                "/api/v1/agent/runtime/tasks/claim",
                Some(case_credential()),
                Some(retired)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/runtime/tasks/claim",
            Some(case_credential()),
            Some(valid)
        )
        .await?
        .0 == StatusCode::OK
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
            first.1["task"]["payload"]["task"]["taskId"]
                .as_str()
                .unwrap()
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
    let signed: rss_mdm_agent_wire::runtime::SignedTask = serde_json::from_value(task.clone())?;
    let context = crate::test_support::task_signature::TaskVerification {
        key_id: "t2",
        public_key: key.public_key().as_ref(),
        tenant_id: Uuid::parse_str(case_tenant())?,
        device_id: case_device_id(),
        platform: rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
        architecture: rss_mdm_agent_wire::runtime::TaskArchitecture::Aarch64,
        registration_id: Uuid::parse_str(registration["registrationId"].as_str().unwrap())?,
        generation: registration["generation"].as_u64().unwrap(),
        task_id: signed.payload.task_id(),
        attempt_id: signed.payload.attempt_id(),
        permit: rss_mdm_agent_wire::runtime::TaskPermit::Offer,
        now,
    };
    crate::test_support::task_signature::verify(&signed, &context)?;
    let attempt = signed.payload.attempt_id();
    let reserved = pg(&format!(
        "SELECT sequence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='pending' AND sealed_at IS NULL",
        case_tenant()
    ))?;
    ensure!(
        !reserved.trim().is_empty(),
        "collection was not frozen before Offer"
    );
    let event_operation = Uuid::new_v4();
    for version in [2, 3, 4, 5, 6, 255] {
        let retired = json!({"wireVersion":version,"operationId":event_operation,"attemptId":task["payload"]["task"]["attemptId"],"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"event":{"kind":"received"}});
        ensure!(
            agent_call(
                &router,
                Method::POST,
                &format!(
                    "/api/v1/agent/runtime/tasks/{}/events",
                    task["payload"]["task"]["taskId"].as_str().unwrap()
                ),
                Some(case_credential()),
                Some(retired)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    task_event(&router, &task, json!({"kind":"received"})).await?;
    let permit = task_event(&router, &task, json!({"kind":"start"})).await?;
    let ack: rss_mdm_agent_wire::runtime::TaskEventAck = serde_json::from_value(permit)?;
    crate::test_support::task_signature::verify(
        &ack.into_permit().unwrap(),
        &crate::test_support::task_signature::TaskVerification {
            permit: rss_mdm_agent_wire::runtime::TaskPermit::Start,
            ..context
        },
    )?;
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
                "/api/v1/devices/{DEVICE_ID}/inventory",
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
    use rss_mdm_agent_wire::runtime as wire;
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
        2,
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
    let attempt = task["payload"]["task"]["attemptId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='snapshot'",case_tenant()))?.trim()=="1");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.output_chunks WHERE tenant_id='{}' AND attempt='{attempt}'",case_tenant()))?.trim()=="2");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn collection_structure_budget_precedes_partial_field_acceptance() -> Result<()> {
    use rss_mdm_agent_wire::runtime as wire;
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    for mode in ["direct", "chunked", "truncated", "partial"] {
        let (resource, _, _) = fixture.resource_with_output_limit(524288).await?;
        publish(&mut fixture.author, &fixture.router, resource).await?;
        let task = claim(&fixture.router).await?;
        task_event(&fixture.router, &task, json!({"kind":"received"})).await?;
        task_event(&fixture.router, &task, json!({"kind":"start"})).await?;
        let output = if mode == "partial" {
            json!({"healthy":true})
        } else {
            json!({"version":"1.2","healthy":true,"items":[{"id":"a"},{"id":"b"}]})
        };
        let (quality, failure) = if mode == "truncated" {
            (
                wire::OutputQuality::Truncated,
                Some(wire::TaskFailure::OutputLimit),
            )
        } else {
            (wire::OutputQuality::Complete, None)
        };
        let result = wire::TaskResult::new(
            Some(0),
            quality,
            output,
            wire::TaskDiagnostics::new("".into(), "".into(), 1, 1, failure)?,
            2,
        )?;
        let event = if mode == "chunked" {
            let (reference, chunks) = wire::ChunkedTaskResult::split(result)?;
            for chunk in chunks {
                task_event(
                    &fixture.router,
                    &task,
                    serde_json::to_value(wire::TaskEvent::OutputChunk(chunk))?,
                )
                .await?;
            }
            wire::TaskEvent::ChunkedResult(reference)
        } else {
            wire::TaskEvent::Result(result)
        };
        // A budget violation is a terminal failed collection, never a trusted partial
        // snapshot or an endlessly retried transport rejection.
        task_event(&fixture.router, &task, serde_json::to_value(event)?).await?;
        let attempt = task["payload"]["task"]["attemptId"].as_str().unwrap();
        let expected = if mode == "partial" {
            "partial"
        } else {
            "failed"
        };
        ensure!(pg(&format!("SELECT result FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}'",case_tenant()))?.trim()==expected,"invalid collection outcome: {mode}");
        if mode != "partial" {
            let id = task["payload"]["task"]["taskId"].as_str().unwrap();
            ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim()=="failed");
            ensure!(pg(&format!("SELECT result->>'trusted' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim()=="false");
        }
    }
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

/// Synthetic protocol fixture: proves server HTTP/PG semantics, not Windows execution.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_inventory_only_partial_empty_chunked_and_revoked() -> Result<()> {
    native_inventory_case(true, false, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_unmapped_evidence_requires_sensitive_permission() -> Result<()> {
    native_inventory_case(false, false, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_all_query_failures_preserve_execution_completion() -> Result<()> {
    native_inventory_case(false, true, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn macos_native_inventory_partial_empty_chunked_and_context_changed() -> Result<()> {
    native_inventory_case(true, false, true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn macos_native_unmapped_failed_evidence_requires_sensitive_permission() -> Result<()> {
    native_inventory_case(false, true, true).await
}

#[allow(
    clippy::cognitive_complexity,
    reason = "shared HTTP scenario retains distinct authorization, quality and transport assertions"
)]
async fn native_inventory_case(map_software: bool, all_failed: bool, macos: bool) -> Result<()> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_resource as r;
    use sha2::{Digest, Sha256};
    let platform = if macos { "macos" } else { "windows" };
    let software_field = if macos {
        "device.software.receipts"
    } else {
        "device.software.installations"
    };
    let mut f = Fixture::new().await?;
    f.grants
        .retain(|g| g.operation != crate::authorization::Permission::ScriptExecute);
    f.grants
        .extend(crate::test_support::identity::device_grants(
            None,
            &["inventory_collect", "operation_read"],
        )?);
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventorySensitiveRead,
        scope: crate::authorization::Scope::Tenant,
    });
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let context = crate::test_support::software_execution::context(if macos {
        crate::test_support::software_execution::Platform::MacOs
    } else {
        crate::test_support::software_execution::Platform::Windows
    });
    let (_,registration)=crate::test_support::agent::enroll_profile(&f.router,&mut f.author,case_credential(),json!({"capabilities":["inventory.collect.v1","inventory.native.v1"],"platform":platform,"architecture":"x86_64","executionContext":context})).await?;
    let device = registration["deviceId"].as_str().unwrap().to_owned();
    f.scope(case_task_scope(), json!([{"kind":"device","id":device}]))
        .await?;
    let mut specs = Vec::new();
    for id in if macos {
        [
            "macos.agent.memory",
            "macos.agent.network",
            "macos.agent.receipts",
        ]
    } else {
        [
            "windows.agent.memory",
            "windows.agent.network",
            "windows.agent.software",
        ]
    } {
        let r::blueprints::Definition::AgentCollection { template } = r::blueprints::get(
            id,
            if id == "windows.agent.software" {
                "2"
            } else {
                "1"
            },
        )
        .unwrap()
        .definition
        else {
            unreachable!()
        };
        specs.push(template.spec().clone());
    }
    if !macos {
        let r::blueprints::Definition::AgentCollection { template } =
            r::blueprints::get("windows.agent.identity", "2")
                .unwrap()
                .definition
        else {
            unreachable!()
        };
        specs.push(template.spec().clone());
    }
    let mut ps = specs[0].plan.spec().clone();
    let mut mappings = specs[0].mappings.clone();
    for spec in &specs[1..] {
        ps.queries.extend(spec.plan.spec().queries.clone());
        mappings.extend(spec.mappings.clone());
    }
    if !map_software {
        mappings.remove(software_field);
    }
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
        plan: w::NativeCollectionPlan::new(ps)?,
        mappings,
    })?;
    let resource_id = Uuid::new_v4();
    let bytes = definition.canonical();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        0,
        json!({"action":"create","kind":"agent_collection"}),
    )
    .await?;
    resource(&mut f.author,&f.router,resource_id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":platform,"architecture":"x86_64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(
        upload_for(
            &f.author,
            &f.router,
            resource_id,
            &bytes,
            platform,
            "x86_64"
        )
        .await?
            == StatusCode::CREATED
    );
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let worker = worker(&f.base).await?;
    let runtime = agent_runtime(&f.base).await?;
    let inventory = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    let claim_input = |engines: Value| json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"environment":{"edition":null,"tools":{},"nativeEngines":engines},"executionContext":context});
    let policy_input = || json!({"scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":resource_id,"version":"v1","platform":platform,"architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}});
    let mut prior_network = String::new();
    let mut prior_software = String::new();
    for stage in if !macos && map_software && !all_failed {
        vec![0, 1, 4, 5, 2, 3]
    } else {
        vec![0, 1, 2, 3]
    } {
        let policy = Uuid::new_v4();
        let ordinary = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventorySensitiveRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, ordinary).await?;
        let denied = f.author.call(&f.router, Method::POST, &format!("/api/v1/policies/{policy}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_input()}}))).await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN,
            "raw evidence publication bypass: {denied:?}"
        );
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_input()}})).await?;
        let unsupported = agent_call(
            &f.router,
            Method::POST,
            "/api/v1/agent/runtime/tasks/claim",
            Some(case_credential()),
            Some(claim_input(json!({}))),
        )
        .await?;
        ensure!(
            unsupported.0 == StatusCode::OK && unsupported.1["task"].is_null(),
            "unsupported native claim: {unsupported:?}"
        );
        let task = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let response = agent_call(
                    &f.router,
                    Method::POST,
                    "/api/v1/agent/runtime/tasks/claim",
                    Some(case_credential()),
                    Some(claim_input(if macos {
                        json!({"macos.hardware":1,"macos.pkg_receipts":1})
                    } else {
                        json!({"windows.wmi":1,"windows.registry":1,"windows.network":1,"windows.software":1})
                    })),
                )
                .await?;
                ensure!(response.0 == StatusCode::OK, "native claim: {response:?}");
                if !response.1["task"].is_null() {
                    break Ok::<_, anyhow::Error>(serde_json::from_value::<w::SignedTask>(
                        response.1["task"].clone(),
                    )?);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let w::TaskPayload::Collection(spec) = &task.payload else {
            anyhow::bail!("native policy issued another task family");
        };
        let path = format!("/api/v1/agent/runtime/tasks/{}/events", spec.task_id);
        let event = |operation, event: Value| json!({"wireVersion":1,"operationId":operation,"attemptId":spec.attempt_id,"executionContext":context,"event":event});
        let received = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), json!({"kind":"received"}))),
        )
        .await?;
        ensure!(received.0 == StatusCode::OK);
        if stage == 3 {
            let grants = f
                .grants
                .iter()
                .filter(|g| {
                    g.operation
                        != if map_software {
                            crate::authorization::Permission::InventoryCollect
                        } else {
                            crate::authorization::Permission::InventorySensitiveRead
                        }
                })
                .cloned()
                .collect();
            if !macos {
                crate::test_support::identity::set_grants(case_tenant(), &f.author_id, grants)
                    .await?;
            }
            let mut start = event(Uuid::new_v4(), json!({"kind":"start"}));
            if macos {
                start["executionContext"]["revision"] =
                    json!(context["revision"].as_u64().unwrap() + 1);
            }
            let denied = agent_call(
                &f.router,
                Method::POST,
                &path,
                Some(case_credential()),
                Some(start),
            )
            .await?;
            ensure!(
                denied.0 == StatusCode::FORBIDDEN,
                "revoked native Start: {denied:?}"
            );
            break;
        }
        let started = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), json!({"kind":"start"}))),
        )
        .await?;
        ensure!(started.0 == StatusCode::OK, "native Start: {started:?}");
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let mut queries = std::collections::BTreeMap::new();
        for (id, q) in &spec.plan.spec().queries {
            let rows = if !macos && let Some(rows) = windows_assets::rows(id, stage) {
                rows
            } else if id == "memory" {
                vec![
                    [(
                        if macos {
                            "total_bytes"
                        } else {
                            "TotalPhysicalMemory"
                        }
                        .into(),
                        json!((8192 + stage).to_string()),
                    )]
                    .into(),
                ]
            } else if stage == 2 || stage >= 4 {
                vec![]
            } else if id == "software" || id == "receipts" {
                (0..if stage == 0 { 2 } else { 1 })
                    .map(|i| {
                        [
                            ("id".into(), json!(format!("app-{i}"))),
                            ("native_id".into(), json!(format!("native-{i}"))),
                            (
                                "name".into(),
                                json!(if stage == 0 {
                                    "private-software"
                                } else {
                                    "partial-software"
                                }),
                            ),
                            ("version".into(), json!("1.0")),
                            ("publisher".into(), json!("Acme")),
                            ("scope".into(), json!(if macos { "device" } else { "user" })),
                            (
                                "owner".into(),
                                json!(if macos {
                                    String::new()
                                } else {
                                    format!("S-1-5-21-1-2-3-{}", 1001 + i)
                                }),
                            ),
                            (
                                "origin".into(),
                                json!(if macos { "pkg_receipt" } else { "registry" }),
                            ),
                            ("location".into(), json!("C:\\Apps")),
                        ]
                        .into()
                    })
                    .collect()
            } else if stage == 0 {
                (0..24)
                    .map(|i| {
                        [
                            ("id".into(), json!(format!("nic{i}"))),
                            ("name".into(), json!("private-native-evidence")),
                            ("addresses".into(), json!(vec!["x".repeat(220); 64])),
                        ]
                        .into()
                    })
                    .collect()
            } else {
                vec![
                    [
                        ("id".into(), json!("nic0")),
                        ("name".into(), json!("changed-truncated")),
                        ("addresses".into(), json!(["192.0.2.99"])),
                    ]
                    .into(),
                ]
            };
            queries.insert(
                id.clone(),
                w::NativeQueryResult {
                    query_digest: q.digest(),
                    collected_at: now,
                    status: if all_failed {
                        match stage {
                            0 => w::NativeQueryStatus::Denied,
                            1 => w::NativeQueryStatus::Timeout,
                            _ => w::NativeQueryStatus::Invalid,
                        }
                    } else if stage == 1 && (id == "network" || id == "receipts") {
                        w::NativeQueryStatus::Truncated
                    } else {
                        w::NativeQueryStatus::Complete
                    },
                    enumeration_complete: !(stage == 1 && id == "network"),
                    row_count: rows.len() as u32,
                    rows,
                    users: (id == "software").then(|| {
                        let expected: std::collections::BTreeSet<_> = [
                            "S-1-5-21-1-2-3-1001".to_owned(),
                            "S-1-5-21-1-2-3-1002".to_owned(),
                        ]
                        .into();
                        w::NativeUserCoverage {
                            enumeration_complete: true,
                            observed: expected.clone(),
                            completed: if stage == 1 {
                                ["S-1-5-21-1-2-3-1001".to_owned()].into()
                            } else {
                                expected.clone()
                            },
                            expected,
                        }
                    }),
                },
            );
        }
        let result = w::NativeCollectionResult {
            plan_digest: spec.plan_digest,
            collected_at: now,
            queries,
        };
        let body = serde_json::to_vec(&result)?;
        let manifest = w::OutputManifest::new(body.len() as u32, Sha256::digest(&body).into())?;
        let terminal = serde_json::to_value(w::TaskEvent::ChunkedCollectionResult {
            manifest: manifest.clone(),
        })?;
        let missing = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), terminal.clone())),
        )
        .await?;
        ensure!(
            missing.0 == StatusCode::BAD_REQUEST,
            "missing native chunks: {missing:?}"
        );
        if stage != 0 {
            for (i, chunk) in body.chunks(w::OUTPUT_CHUNK_BYTES).enumerate() {
                let chunk = serde_json::to_value(w::TaskEvent::OutputChunk(w::OutputChunk::new(
                    manifest.clone(),
                    i as u16,
                    chunk,
                )?))?;
                let response = agent_call(
                    &f.router,
                    Method::POST,
                    &path,
                    Some(case_credential()),
                    Some(event(Uuid::new_v4(), chunk)),
                )
                .await?;
                ensure!(response.0 == StatusCode::OK);
            }
        }
        let terminal = if stage == 0 {
            ensure!(body.len() > 256 * 1024);
            serde_json::to_value(w::TaskEvent::CollectionResult(result.clone()))?
        } else {
            terminal
        };
        let operation = Uuid::new_v4();
        let input = event(operation, terminal);
        let accepted = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(input.clone()),
        )
        .await?;
        ensure!(accepted.0 == StatusCode::OK, "native result: {accepted:?}");
        ensure!(
            accepted
                == agent_call(
                    &f.router,
                    Method::POST,
                    &path,
                    Some(case_credential()),
                    Some(input)
                )
                .await?
        );
        ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), spec.task_id))?.trim() == "succeeded", "legal finished package did not complete execution");
        if all_failed {
            ensure!(pg(&format!("SELECT result FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), spec.attempt_id))?.trim() == "failed");
            ensure!(pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native'", case_tenant(), spec.registration_id))?.trim() == "0");
        } else {
            tokio::time::timeout(Duration::from_secs(20),async{
            loop{let rows=pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='device.memory.bytes' AND value::jsonb->>'value'='{}'",case_tenant(),spec.registration_id,8192+stage))?;if rows.trim()=="1"{break Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;}
        }).await??;
            let network = pg(&format!(
                "SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='device.network.interfaces'",
                case_tenant(),
                spec.registration_id
            ))?;
            if stage == 0 {
                prior_network = network.clone();
            } else if stage == 1 {
                ensure!(
                    network == prior_network,
                    "truncated result replaced complete inventory"
                );
                ensure!(pg(&format!("SELECT attempts::jsonb#>>'{{fields,device.network.interfaces,quality}}' FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'",case_tenant(),spec.attempt_id))?.trim()=="failed");
            } else {
                let v: Value = serde_json::from_str(network.trim())?;
                ensure!(v["value"] == json!([]));
            }
            if !macos {
                windows_assets::verify_identity(spec.registration_id, spec.attempt_id, stage)?;
                let response = f
                    .author
                    .call(
                        &f.router,
                        Method::GET,
                        &format!("/api/v1/devices/{device}/inventory"),
                        None,
                    )
                    .await?;
                ensure!(response.0 == StatusCode::OK, "asset query: {response:?}");
                ensure!(
                    response.1["asset"]["device"]["fields"]["device.os.edition"]["state"]["value"]
                        ["value"]
                        == "Professional"
                );
            }
            if map_software {
                let software = pg(&format!(
                    "SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='{software_field}'",
                    case_tenant(),
                    spec.registration_id
                ))?;
                if stage == 0 {
                    let value: Value = serde_json::from_str(software.trim())?;
                    if macos {
                        ensure!(
                            value["value"]
                                .as_array()
                                .is_some_and(|rows| rows.len() == 2)
                        );
                    } else {
                        windows_assets::verify_software(&value)?;
                    }
                    prior_software = software;
                } else if stage == 1 || stage >= 4 {
                    ensure!(
                        software == prior_software,
                        "incomplete user coverage replaced the whole software list"
                    );
                } else {
                    let value: Value = serde_json::from_str(software.trim())?;
                    ensure!(
                        value["value"] == json!([]),
                        "complete empty software list was not published"
                    );
                }
            }
        }
        let detail_path = format!("/api/v1/policies/{policy}/runs/{}", spec.task_id);
        let detail = f
            .author
            .call(&f.router, Method::GET, &detail_path, None)
            .await?;
        ensure!(
            detail.0 == StatusCode::OK
                && detail.1["result"]["native"] == serde_json::to_value(&result)?,
            "native evidence recovery failed: {}",
            detail.0
        );
        let ordinary = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventorySensitiveRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, ordinary).await?;
        let denied = f
            .author
            .call(&f.router, Method::GET, &detail_path, None)
            .await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN && !denied.1.to_string().contains("private-software"),
            "raw evidence read bypass: {denied:?}"
        );
        let limited = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventoryRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, limited).await?;
        ensure!(
            f.author
                .call(&f.router, Method::GET, &detail_path, None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        let summary = f
            .author
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/policies/{policy}/runs"),
                None,
            )
            .await?;
        ensure!(summary.0 == StatusCode::OK, "native summary: {summary:?}");
        ensure!(
            summary.1["items"][0]["result"].get("native").is_none()
                && !summary.1.to_string().contains("private-native-evidence")
                && !summary.1.to_string().contains("changed-truncated")
        );
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.action_kind='execution'",case_tenant()))?.trim()=="0");
    }
    crate::test_support::stop_worker(inventory).await?;
    runtime.close_fixture().await?;
    crate::test_support::stop_worker(worker).await?;
    Ok(())
}
