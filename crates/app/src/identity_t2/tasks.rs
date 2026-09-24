//! Real authenticated task authoring, approval, delivery, result intake and projection.
use super::*;
use base64::Engine;
use ring::signature::KeyPair;
use sha2::{Digest, Sha256};
use uuid::Uuid;
const CREDENTIAL: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
const INVENTORY_CREDENTIAL: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
const DEVICE_ID: &str = "enterprise-device";

fn next_new_york_fold(now: i64) -> Result<i64> {
    use jiff::{ToSpan, tz::AmbiguousOffset};
    let zone = jiff::tz::TimeZone::get("America/New_York")?;
    let mut date = zone.to_datetime(jiff::Timestamp::from_second(now)?).date();
    for _ in 0..=366 {
        let ambiguous = zone.to_ambiguous_timestamp(date.at(1, 30, 0, 0));
        if matches!(ambiguous.offset(), AmbiguousOffset::Fold { .. }) {
            let fold = ambiguous.earlier()?.as_second();
            if fold > now {
                return Ok(fold);
            }
        }
        date = date.checked_add(1.days())?;
    }
    anyhow::bail!("next New York DST fold not found")
}

async fn post(browser: &mut Browser, router: &Router, path: &str, body: Value) -> Result<Value> {
    let response = browser.call(router, Method::POST, path, Some(body)).await?;
    ensure!(response.0.is_success(), "{path}: {response:?}");
    Ok(response.1)
}
async fn resource(
    browser: &mut Browser,
    router: &Router,
    id: Uuid,
    revision: u64,
    input: Value,
) -> Result<Value> {
    post(
        browser,
        router,
        &format!("/api/v3/resources/{id}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input}),
    )
    .await
}
async fn upload(browser: &Browser, router: &Router, id: Uuid, bytes: &[u8]) -> Result<StatusCode> {
    let request=Request::builder().method(Method::POST).uri(format!("/api/v3/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64"))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",browser.csrf.as_ref().unwrap())
        .header("cookie",browser.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).header("content-type","application/octet-stream").body(Body::from(bytes.to_vec()))?;
    Ok(router.clone().oneshot(request).await?.status())
}
async fn task_event(router: &Router, task: &Value, mut kind: Value) -> Result<Value> {
    let response = task_event_request(router, task, Uuid::new_v4(), &mut kind).await?;
    ensure!(response.0 == StatusCode::OK, "event: {response:?}");
    Ok(response.1)
}
async fn task_event_request(
    router: &Router,
    task: &Value,
    operation: Uuid,
    kind: &mut Value,
) -> Result<(StatusCode, Value)> {
    if kind["kind"] == "result" && kind.get("diagnostics").is_none() {
        let failure = match kind["quality"].as_str() {
            Some("truncated") => json!("output_limit"),
            Some("failed") => json!("capture_failed"),
            _ => Value::Null,
        };
        kind["diagnostics"] = json!({"stdout":"captured stdout","stderr":"captured stderr","durationMs":1,"executedAt":1,"failure":failure});
    }
    agent_call(router,Method::POST,&format!("/api/agent/v2/tasks/{}/events",task["payload"]["taskId"].as_str().unwrap()),Some(CREDENTIAL),Some(json!({"wireVersion":2,"operationId":operation,"attemptId":task["payload"]["attemptId"],"event":kind}))).await
}
async fn claim_request(router: &Router, operation: Uuid) -> Result<(StatusCode, Value)> {
    agent_call(
        router,
        Method::POST,
        "/api/agent/v2/tasks/claim",
        Some(CREDENTIAL),
        Some(json!({"wireVersion":2,"operationId":operation})),
    )
    .await
}
async fn claim(router: &Router) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = claim_request(router, Uuid::new_v4()).await?;
            ensure!(response.0 == StatusCode::OK, "claim: {response:?}");
            let _: rss_mdm_agent_wire::TaskClaimResponse =
                serde_json::from_value(response.1.clone())?;
            if !response.1["task"].is_null() {
                return Ok::<_, anyhow::Error>(response.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
async fn plan(
    author: &mut Browser,
    reviewer: &mut Browser,
    router: &Router,
    resource: Uuid,
    now: i64,
    commands: &crate::commands::Commands,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let body = json!({"operationId":id,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"manual"},"notBefore":now-1,"until":now+600,"jitterSeconds":0,"window":null},"runLifetimeSeconds":300});
    commands.inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(
        author
            .call(
                router,
                Method::POST,
                "/api/v3/script-plans",
                Some(body.clone())
            )
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let receipt = post(author, router, "/api/v3/script-plans", body.clone()).await?;
    ensure!(
        receipt["operationId"] == id.to_string()
            && receipt["targetCount"] == 1
            && receipt["nextStage"] == "review",
        "plan receipt lacks stable progress feedback: {receipt}"
    );
    ensure!(
        receipt == post(author, router, "/api/v3/script-plans", body).await?,
        "plan replay changed"
    );
    let path = format!("/api/v3/script-plans/{id}/approve");
    ensure!(
        author
            .call(
                router,
                Method::POST,
                &path,
                Some(json!({"operationId":Uuid::new_v4()}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let approval = json!({"operationId":Uuid::new_v4()});
    commands.inject_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    ensure!(
        reviewer
            .call(router, Method::POST, &path, Some(approval.clone()))
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let receipt = post(reviewer, router, &path, approval.clone()).await?;
    ensure!(receipt == post(reviewer, router, &path, approval).await?);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE plan='{id}'"
        ))?
        .trim()
            == "1"
    );
    Ok(id)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2-tasks: isolated TLS PostgreSQL and actual product Router"]
async fn enterprise_task_delivery_and_inventory() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let keyfile = temp.path().join("signing.pk8");
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    std::fs::write(&keyfile, pkcs8.as_ref())?;
    std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600))?;
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["tasks"] = json!({"directory":temp.path(),"private_key_file":keyfile,"key_id":"fixture","trusted_keys":{"fixture":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
    let (router, commands) = crate::api::application_fixture(
        serde_json::from_value(base.clone())?,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access_store(&base).await?,
        None,
    )
    .await?;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut author = Browser::default();
    let mut reviewer = Browser::default();
    ensure!(author.login(&router, "other").await? == StatusCode::OK);
    ensure!(reviewer.login(&router, "admin").await? == StatusCode::OK);
    let author_id = browser_subject(&author, &router).await?;
    let reviewer_id = browser_subject(&reviewer, &router).await?;
    let mut grants = crate::identity_fixture::device_grants(
        Some(DEVICE_ID),
        &[
            "enrollment",
            "inventory_read",
            "script_execute",
            "script_approve",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for operation in [
        crate::authorization::Permission::ResourceWrite,
        crate::authorization::Permission::ResourceRead,
        crate::authorization::Permission::GroupRead,
        crate::authorization::Permission::GroupWrite,
        crate::authorization::Permission::GroupRecompute,
    ] {
        grants.push(crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventoryRead,
        scope: crate::authorization::Scope::AllDevices,
    });
    crate::identity_fixture::set_grants(TENANT, &author_id, grants).await?;
    crate::identity_fixture::set_grants(
        TENANT,
        &reviewer_id,
        crate::identity_fixture::device_grants(Some(DEVICE_ID), &["script_approve"])?,
    )
    .await?;
    author.operation = Some(Uuid::new_v4());
    let password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let enrollment = post(
        &mut author,
        &router,
        "/api/v3/enrollments",
        json!({"deviceId":DEVICE_ID,"password":password,"source":"agent.builtin"}),
    )
    .await?;
    author.operation = None;
    let registration=agent_call(&router,Method::POST,"/api/agent/v2/registrations",None,Some(json!({"wireVersion":2,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":INVENTORY_CREDENTIAL,"capabilities":["inventory.basic.v2"]}))).await?;
    ensure!(
        registration.0 == StatusCode::CREATED
            && registration.1["capabilities"] == json!(["inventory.basic.v2"]),
        "registration: {registration:?}"
    );
    let taskless = agent_call(
        &router,
        Method::POST,
        "/api/agent/v2/tasks/claim",
        Some(INVENTORY_CREDENTIAL),
        Some(json!({"wireVersion":2,"operationId":Uuid::new_v4()})),
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
        json!({"deviceId":DEVICE_ID,"password":password,"source":"agent.builtin"}),
    )
    .await?;
    author.operation = None;
    let registration=agent_call(&router,Method::POST,"/api/agent/v2/registrations",None,Some(json!({"wireVersion":2,"operationId":Uuid::new_v4(),"enrollmentId":enrollment["enrollmentId"],"password":password,"credential":CREDENTIAL,"capabilities":["inventory.basic.v2","task.execute.v2"]}))).await?;
    ensure!(
        registration.0 == StatusCode::CREATED
            && registration.1["capabilities"] == json!(["inventory.basic.v2", "task.execute.v2"]),
        "task registration: {registration:?}"
    );
    // Legacy URL and major cannot enter task intake.
    let old = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/agent/v1/tasks/claim")
                .header("host", "mdm.example.test")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(old.status() == StatusCode::NOT_FOUND);
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/agent/v2/tasks/claim",
            Some(CREDENTIAL),
            Some(json!({"wireVersion":1,"operationId":Uuid::new_v4()}))
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let id = Uuid::new_v4();
    let bytes = b"#!/bin/sh\nprintf '{\"version\":\"1.2\",\"healthy\":true}\n'\n";
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"collection","mappings":{"custom.corporate_agent.version":"/version","custom.corporate_agent.healthy":"/healthy"}},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    resource(
        &mut author,
        &router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(&mut author,&router,id,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"fixture-script","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(upload(&author, &router, id, b"corrupt").await? == StatusCode::BAD_REQUEST);
    ensure!(upload(&author, &router, id, bytes).await? == StatusCode::CREATED);
    ensure!(upload(&author, &router, id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut author,
        &router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let plan_id = plan(&mut author, &mut reviewer, &router, id, now, &commands).await?;
    ensure!(
        author
            .call(
                &router,
                Method::POST,
                &format!("/api/v3/resources/{id}"),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}})),
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let config: Config = serde_json::from_value(base.clone())?;
    let worker = crate::commands::Commands::open(&config).await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::commands::Resource(worker.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(worker.registration().critical());
    launch.finish();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if pg(&format!(
                "SELECT gateway_accepted FROM mdm_commands.action_runs WHERE plan='{plan_id}'"
            ))?
            .trim()
                == "t"
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let claim_operation = Uuid::new_v4();
    commands.inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
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
        key_id: "fixture",
        public_key: key.public_key().as_ref(),
        tenant_id: Uuid::parse_str(TENANT)?,
        device_id: DEVICE_ID,
        platform: rss_mdm_agent_wire::TaskPlatform::Macos,
        architecture: rss_mdm_agent_wire::TaskArchitecture::Aarch64,
        registration_id: Uuid::parse_str(registration.1["registrationId"].as_str().unwrap())?,
        generation: registration.1["generation"].as_u64().unwrap(),
        task_id: signed.payload.task_id,
        attempt_id: signed.payload.attempt_id,
        permit: rss_mdm_agent_wire::TaskPermit::Offer,
        now,
    };
    signed.verify(&context)?;
    range_matrix(&router, &task, bytes).await?;
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
    commands.inject_fault(
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
    ensure!(pg("SELECT count(*) FROM mdm_access.collection_runs WHERE source='agent.script' AND delivery_pending")?.trim()=="2");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM rss_device_command.commands WHERE command_id='{}'",
            signed.payload.task_id
        ))?
        .trim()
            == "0"
    );
    let runtime = agent_runtime(&base).await?;
    let inventory = crate::inventory_runtime::tests::start(runtime.clone()).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if pg(
                "SELECT count(*) FROM mdm.inventory WHERE source='agent.script' AND state='known'",
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
            &format!("/api/v2/devices/{DEVICE_ID}/inventory"),
            None,
        )
        .await?;
    ensure!(
        detail["asset"]["device"]["fields"]["custom.corporate_agent.healthy"]["state"]["value"]["value"]
            == true,
        "detail: {detail}"
    );
    group_matrix(&mut author, &router, &base).await?;
    history::verify(&mut author, &router, plan_id).await?;
    let read = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v3/script-plans/{plan_id}"),
            None,
        )
        .await?;
    ensure!(read.0 == StatusCode::OK);
    plan(&mut author, &mut reviewer, &router, id, now, &commands).await?;
    let task = claim(&router).await?;
    task_event(&router, &task, json!({"kind":"received"})).await?;
    task_event(&router, &task, json!({"kind":"start"})).await?;
    task_event(&router,&task,json!({"kind":"result","exitCode":0,"quality":"truncated","output":{"version":"bad","healthy":false}})).await?;
    tokio::time::timeout(Duration::from_secs(15),async{loop{if pg("SELECT count(*) FROM mdm_access.collection_runs WHERE source='agent.script' AND delivery_pending")?.trim()=="0"{break Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;}}).await??;
    let (_, detail) = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/devices/{DEVICE_ID}/inventory"),
            None,
        )
        .await?;
    ensure!(
        detail["asset"]["device"]["fields"]["custom.corporate_agent.version"]["state"]["value"]["value"]
            == "1.2",
        "bad output replaced trusted value: {detail}"
    );
    let timeout_plan = plan(&mut author, &mut reviewer, &router, id, now, &commands).await?;
    let timeout_task = claim(&router).await?;
    task_event(&router, &timeout_task, json!({"kind":"received"})).await?;
    task_event(&router, &timeout_task, json!({"kind":"start"})).await?;
    let cancel_plan = plan(&mut author, &mut reviewer, &router, id, now, &commands).await?;
    let cancel_task = claim(&router).await?;
    task_event(&router, &cancel_task, json!({"kind":"received"})).await?;
    task_event(&router, &cancel_task, json!({"kind":"start"})).await?;
    let queued_plan = plan(&mut author, &mut reviewer, &router, id, now, &commands).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if pg(&format!(
                "SELECT gateway_accepted FROM mdm_commands.action_runs WHERE plan='{queued_plan}'"
            ))?
            .trim()
                == "t"
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    ensure!(stack.shutdown().join().await?.is_clean());
    capacity::verify(&mut author, &mut reviewer, &router, id, &commands).await?;
    scheduled_matrix(&mut author, &mut reviewer, &router, id, &commands, &config).await?;
    post(
        &mut author,
        &router,
        &format!("/api/v3/script-plans/{cancel_plan}/cancel"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    let timeout_id = timeout_task["payload"]["taskId"].as_str().unwrap();
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{startedAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-61)) WHERE id='{timeout_id}'"
    ))?;
    pg(&format!(
        "UPDATE mdm_commands.action_plans SET recovery_after=NULL WHERE id IN ('{timeout_plan}','{cancel_plan}','{queued_plan}')"
    ))?;
    let before_runs = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    let before_attempts = pg("SELECT count(*) FROM mdm_commands.action_attempts")?;
    let before_outbox = pg("SELECT count(*) FROM rss_transactional_messaging.outbox")?;
    let restarted = crate::commands::Commands::open(&config).await?;
    for plan in [timeout_plan, cancel_plan, queued_plan] {
        restarted.recover_action_fixture(plan).await?;
    }
    ensure!(pg("SELECT count(*) FROM mdm_commands.action_runs")? == before_runs);
    ensure!(pg("SELECT count(*) FROM mdm_commands.action_attempts")? == before_attempts);
    ensure!(pg("SELECT count(*) FROM rss_transactional_messaging.outbox")? == before_outbox);
    ensure!(
        pg(&format!(
            "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE id='{timeout_id}'"
        ))?
        .trim()
            == "unknown"
    );
    let cancel_id = cancel_task["payload"]["taskId"].as_str().unwrap();
    ensure!(
        pg(&format!(
            "SELECT state->>'cancellation' FROM mdm_commands.action_runs WHERE id='{cancel_id}'"
        ))?
        .trim()
            == "requested"
    );
    ensure!(
        pg(&format!(
            "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE plan='{queued_plan}'"
        ))?
        .trim()
            == "not_started"
    );
    task_event(&router,&timeout_task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"late-timeout","healthy":false}})).await?;
    task_event(&router,&cancel_task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"late-cancel","healthy":false}})).await?;
    task_event(&router, &cancel_task, json!({"kind":"cancelled"})).await?;
    for task in [&timeout_task, &cancel_task] {
        let task = task["payload"]["taskId"].as_str().unwrap();
        ensure!(
            pg(&format!(
                "SELECT result->>'trusted' FROM mdm_commands.action_runs WHERE id='{task}'"
            ))?
            .trim()
                == "false"
        );
        ensure!(
            pg(&format!(
                "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE id='{task}'"
            ))?
            .trim()
                == "succeeded"
        );
    }
    ensure!(
        pg(&format!(
            "SELECT state->>'cancellation' FROM mdm_commands.action_runs WHERE id='{cancel_id}'"
        ))?
        .trim()
            == "confirmed"
    );
    rss_runtime::ManagedResource::shutdown(&crate::commands::Resource(restarted)).await?;
    let pending = claim(&router).await?;
    let pending = poll::verify(&router, pending).await?;
    ensure!(
        pending["payload"]["taskId"]
            == pg(&format!(
                "SELECT id FROM mdm_commands.action_runs WHERE plan='{queued_plan}'"
            ))?
            .trim()
    );
    tokio::time::timeout(Duration::from_secs(15),async{loop{if pg("SELECT count(*) FROM mdm_access.collection_runs WHERE source='agent.script' AND delivery_pending")?.trim()=="0"{break Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;}}).await??;
    let (_, recovered_detail) = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/devices/{DEVICE_ID}/inventory"),
            None,
        )
        .await?;
    ensure!(
        recovered_detail["asset"]["device"]["fields"]["custom.corporate_agent.version"]["state"]["value"]
            ["value"]
            == "1.2",
        "late evidence replaced lastKnown: {recovered_detail}"
    );
    crate::identity_fixture::set_grants(TENANT, &reviewer_id, vec![]).await?;
    let event=agent_call(&router,Method::POST,&format!("/api/agent/v2/tasks/{}/events",pending["payload"]["taskId"].as_str().unwrap()),Some(CREDENTIAL),Some(json!({"wireVersion":2,"operationId":Uuid::new_v4(),"attemptId":pending["payload"]["attemptId"],"event":{"kind":"received"}}))).await?;
    ensure!(
        event.0 == StatusCode::FORBIDDEN,
        "revoked approval: {event:?}"
    );
    let path = format!(
        "/api/agent/v2/tasks/{}/content?attempt={}",
        pending["payload"]["taskId"].as_str().unwrap(),
        pending["payload"]["attemptId"].as_str().unwrap()
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", "mdm.example.test")
                .header("authorization", format!("Bearer {CREDENTIAL}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    pg(
        "UPDATE mdm_access.agent_bindings SET wire_version=1,capabilities='[\"inventory.basic.v1\"]'",
    )?;
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/agent/v2/tasks/claim",
            Some(CREDENTIAL),
            Some(json!({"wireVersion":2,"operationId":Uuid::new_v4()}))
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    ensure!(inventory.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;
    Ok(())
}

async fn range_matrix(router: &Router, task: &Value, expected: &[u8]) -> Result<()> {
    let path = format!(
        "/api/agent/v2/tasks/{}/content?attempt={}",
        task["payload"]["taskId"].as_str().unwrap(),
        task["payload"]["attemptId"].as_str().unwrap()
    );
    for (range, if_range, status, bytes) in [
        (
            "bytes=0-3",
            None,
            StatusCode::PARTIAL_CONTENT,
            &expected[..4],
        ),
        ("bytes=0-3", Some("\"different\""), StatusCode::OK, expected),
        (
            "bytes=999999-",
            None,
            StatusCode::RANGE_NOT_SATISFIABLE,
            &[][..],
        ),
    ] {
        let mut request = Request::builder()
            .uri(&path)
            .header("host", "mdm.example.test")
            .header("authorization", format!("Bearer {CREDENTIAL}"))
            .header("range", range);
        if let Some(tag) = if_range {
            request = request.header("if-range", tag);
        }
        let response = router.clone().oneshot(request.body(Body::empty())?).await?;
        ensure!(
            response.status() == status,
            "range {range}: {}",
            response.status()
        );
        if status.is_success() {
            ensure!(response.headers().contains_key("etag"));
            ensure!(response.into_body().collect().await?.to_bytes().as_ref() == bytes);
        }
    }
    let wrong = path.replace(
        task["payload"]["attemptId"].as_str().unwrap(),
        &Uuid::new_v4().to_string(),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(wrong)
                .header("host", "mdm.example.test")
                .header("authorization", format!("Bearer {CREDENTIAL}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    Ok(())
}

async fn scheduled_matrix(
    author: &mut Browser,
    reviewer: &mut Browser,
    router: &Router,
    resource: Uuid,
    commands: &crate::commands::Commands,
    config: &Config,
) -> Result<()> {
    // Seed the capacity boundary, then exercise admission through the authenticated API.
    let seed = Uuid::new_v4();
    let now = pg("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")?
        .trim()
        .parse::<i64>()?;
    let request = json!({"operationId":seed,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"check_in","minimumSeconds":60},"notBefore":now,"until":now+86400,"jitterSeconds":0,"window":null,"misfire":"skip"},"runLifetimeSeconds":300});
    post(author, router, "/api/v3/script-plans", request.clone()).await?;
    pg(&format!(
        "INSERT INTO mdm_commands.action_plans(tenant_id,id,resource,version,document,fingerprint,author,author_approvals,scan_at) SELECT tenant_id,gen_random_uuid(),resource,version,document,fingerprint,author,author_approvals,scan_at FROM mdm_commands.action_plans CROSS JOIN generate_series(1,127) WHERE id='{seed}'"
    ))?;
    // Exact retries remain replayable even at capacity.
    post(author, router, "/api/v3/script-plans", request.clone()).await?;
    let mut over = request;
    over["operationId"] = json!(Uuid::new_v4());
    ensure!(
        author
            .call(
                router,
                Method::POST,
                "/api/v3/script-plans",
                Some(over.clone())
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    post(
        author,
        router,
        &format!("/api/v3/script-plans/{seed}/cancel"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    post(author, router, "/api/v3/script-plans", over).await?;
    pg(
        "UPDATE mdm_commands.action_plans SET active=false WHERE document->'input'->'schedule'->'trigger'->>'kind'='check_in'",
    )?;
    let fold = next_new_york_fold(now)?;
    let mut cases = Vec::new();
    for misfire in ["skip", "coalesce_one"] {
        cases.push((json!({"trigger":{"kind":"interval","anchor":fold-600,"seconds":60},"notBefore":fold-600,"until":fold+86400,"jitterSeconds":0,"window":null,"misfire":misfire}),fold+59,if misfire=="skip"{0}else{1}));
    }
    cases.push((json!({"trigger":{"kind":"weekly","zone":"America/New_York","weekday":7,"minute":90},"notBefore":fold-3600,"until":fold+86400,"jitterSeconds":0,"window":{"zone":"UTC","weekdays":[7],"startMinute":600,"endMinute":660},"misfire":"coalesce_one"}),fold+5400,1));
    for (schedule, at, count) in cases {
        let id = Uuid::new_v4();
        let lifetime = if schedule["trigger"]["kind"] == "weekly" {
            7200
        } else {
            300
        };
        post(author,router,"/api/v3/script-plans",json!({"operationId":id,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":schedule,"runLifetimeSeconds":lifetime})).await?;
        post(
            reviewer,
            router,
            &format!("/api/v3/script-plans/{id}/approve"),
            json!({"operationId":Uuid::new_v4()}),
        )
        .await?;
        // Reopening the actual PG runtime restores the cursor; no in-memory deduplication.
        let restarted = crate::commands::Commands::open(config).await?;
        tokio::try_join!(
            commands.scan_action_fixture(id, at),
            restarted.scan_action_fixture(id, at)
        )?;
        rss_runtime::ManagedResource::shutdown(&crate::commands::Resource(restarted)).await?;
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_commands.action_runs WHERE plan='{id}'"
            ))?
            .trim()
                == count.to_string()
        );
        if schedule["trigger"]["kind"] == "weekly" {
            ensure!(
                pg(&format!(
                    "SELECT occurrence FROM mdm_commands.action_runs WHERE plan='{id}'"
                ))?
                .trim()
                    == format!("timer:{fold}")
            );
            ensure!(
                pg(&format!(
                    "SELECT available_at FROM mdm_commands.action_runs WHERE plan='{id}'"
                ))?
                .trim()
                    == (fold + 16_200).to_string()
            );
            ensure!(
                pg(&format!(
                    "SELECT deadline FROM mdm_commands.action_runs WHERE plan='{id}'"
                ))?
                .trim()
                    == (fold + 19_800).to_string()
            );
        }
        post(
            author,
            router,
            &format!("/api/v3/script-plans/{id}/cancel"),
            json!({"operationId":Uuid::new_v4()}),
        )
        .await?;
    }
    Ok(())
}

async fn group_matrix(author: &mut Browser, router: &Router, config: &Value) -> Result<()> {
    let automation = start_automation(config).await?;
    let criteria = json!({"kind":"predicate","field":"custom.corporate_agent.healthy","op":"eq","value":{"kind":"boolean","value":true}});
    let page = super::assets::ok(
        author,
        router,
        Method::POST,
        "/api/v2/device-queries",
        Some(json!({"criteria":criteria})),
    )
    .await?;
    ensure!(
        page["asset"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["device"] == DEVICE_ID),
        "EA query: {page}"
    );
    let group = format!("/api/v2/groups/{}", Uuid::new_v4());
    super::assets::ok(author,router,Method::POST,&group,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"enterprise-healthy","description":"","criteria":criteria}}))).await?;
    let preview = super::assets::preview(author, router, &group).await?;
    ensure!(
        preview.members.to_string().contains(DEVICE_ID),
        "EA group: {}",
        preview.members
    );
    ensure!(automation.shutdown().join().await?.is_clean());
    Ok(())
}

mod capacity;
mod history;
mod poll;
