//! Real Policy publication, lazy device admission, delivery, result intake and recovery.
use super::*;
use base64::Engine;
use ring::signature::KeyPair;
use sha2::{Digest, Sha256};
use uuid::Uuid;
const CREDENTIAL: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
const INVENTORY_CREDENTIAL: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
const TASK_SCOPE: Uuid = Uuid::from_u128(0x90101010_1234_4321_8123_101010101010);
const EMPTY_SCOPE: Uuid = Uuid::from_u128(0x90101010_1234_4321_8123_202020202020);
const DEVICE_ID: &str = "enterprise-device";

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
    let request=Request::builder().method(Method::POST).uri(format!("/api/v3/resources/{id}/content?version=v1&variant=default&platform=macos&architecture=aarch64&operation={}",Uuid::new_v4()))
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
fn business_event(operation: Uuid) -> Result<String> {
    let operation = operation.to_string();
    let records = audit_records()?;
    let matching: Vec<_> = records
        .iter()
        .filter(|record| {
            record.source() == "mdm.business" && record.operation() == Some(operation.as_str())
        })
        .collect();
    ensure!(
        matching.len() == 1,
        "operation must retain one business event"
    );
    Ok(matching[0]
        .decoded
        .event()
        .identity()
        .event_id()
        .as_str()
        .to_owned())
}

fn policy_definition(resource: Uuid, scope: Uuid) -> Value {
    json!({"resource":{"id":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"scope":scope,"behavior":{"kind":"execution","parameters":{},"runLifetimeSeconds":300}})
}
async fn policy(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let body = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,TASK_SCOPE)}});
    let before = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitPending,
    );
    let path = format!("/api/v2/policies/{id}");
    ensure!(
        author
            .call(router, Method::POST, &path, Some(body.clone()))
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let result = post(author, router, &path, body.clone()).await?;
    ensure!(result["id"] == id.to_string() && result["revision"] == 1);
    let event = business_event(operation)?;
    ensure!(result == post(author, router, &path, body).await?);
    ensure!(business_event(operation)? == event);
    ensure!(
        pg("SELECT count(*) FROM mdm_commands.action_runs")? == before,
        "publication must not fan out runs"
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
    base["content"] = json!({"directory":temp.path(),"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":67108864,"max_bundle_entries":100,"max_expansion_ratio":100});
    base["task_signing"] = json!({"private_key_file":keyfile,"key_id":"fixture","trusted_keys":{"fixture":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
    let (router, execution, plan_runtime) = crate::api::application_fixture(
        serde_json::from_value(base.clone())?,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        database(&base).await?,
        None,
        database(&base)
            .await?
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut author = Browser::default();
    ensure!(author.login(&router, "other").await? == StatusCode::OK);
    let author_id = browser_subject(&author, &router).await?;
    let mut grants = crate::identity_fixture::device_grants(
        Some(DEVICE_ID),
        &[
            "enrollment",
            "inventory_read",
            "script_execute",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for operation in [
        crate::authorization::Permission::PolicyWrite,
        crate::authorization::Permission::PolicyRead,
        crate::authorization::Permission::ResourceWrite,
        crate::authorization::Permission::ResourceRead,
        crate::authorization::Permission::GroupRead,
        crate::authorization::Permission::GroupWrite,
        crate::authorization::Permission::GroupRecompute,
        crate::authorization::Permission::ScopeRead,
        crate::authorization::Permission::ScopeWrite,
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
    grants.extend(crate::identity_fixture::device_grants(
        None,
        &["script_execute"],
    )?);
    crate::identity_fixture::set_grants(TENANT, &author_id, grants.clone()).await?;
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
    let setup_automation = start_automation(&base).await?;
    for (scope, targets) in [
        (TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}])),
        (EMPTY_SCOPE, json!([])),
    ] {
        let created=post(&mut author,&router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":targets,"limitations":null,"exclusions":[]}}})).await?;
        await_task(
            &mut author,
            &router,
            &format!(
                "/api/v2/scopes/{scope}/tasks/{}",
                created["task"].as_str().unwrap()
            ),
        )
        .await?;
    }
    ensure!(setup_automation.shutdown().join().await?.is_clean());
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
    let without_resource = grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ResourceRead)
        .cloned()
        .collect();
    crate::identity_fixture::set_grants(TENANT, &author_id, without_resource).await?;
    let denied=author.call(&router,Method::POST,&format!("/api/v2/policies/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,TASK_SCOPE)}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "publishing without ResourceRead: {denied:?}"
    );
    crate::identity_fixture::set_grants(TENANT, &author_id, grants.clone()).await?;
    let preview_before = pg(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies),(SELECT count(*) FROM mdm_policy.versions),(SELECT count(*) FROM mdm_commands.action_runs),(SELECT count(*) FROM mdm_automation.automation_jobs))",
    )?;
    let preview = post(
        &mut author,
        &router,
        "/api/v2/policies/previews",
        json!({"definition":policy_definition(id,TASK_SCOPE)}),
    )
    .await?;
    ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
    ensure!(
        pg(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies),(SELECT count(*) FROM mdm_policy.versions),(SELECT count(*) FROM mdm_commands.action_runs),(SELECT count(*) FROM mdm_automation.automation_jobs))"
        )? == preview_before,
        "draft preview published work"
    );
    archive_race::verify(&mut author, &router, &definition, bytes).await?;
    let policy_id = policy(&mut author, &router, id, &plan_runtime).await?;
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
    let worker = crate::flow::execution::open(
        &config,
        crate::identity_fixture::audit_store(&config).await?,
    )
    .await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::execution::Resource(worker.clone()),
    ));
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(worker.registration().critical());
    launch.finish();
    let first = claim_request(&router, Uuid::new_v4()).await?;
    ensure!(first.0 == StatusCode::OK, "lazy acceptance: {first:?}");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="1");
    tokio::time::timeout(Duration::from_secs(15),async {loop {
        if pg(&format!("SELECT gateway_accepted FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="t" {break Ok::<_,anyhow::Error>(());}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await??;
    if !first.1["task"].is_null() {
        pg(
            "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{delivery,leaseUntil}','0')",
        )?;
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
    let mut history_grants = grants.clone();
    history_grants.extend(crate::identity_fixture::device_grants(
        None,
        &["operation_read"],
    )?);
    crate::identity_fixture::set_grants(TENANT, &author_id, history_grants).await?;
    history::verify(&mut author, &router, policy_id).await?;
    let completed = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    for _ in 0..3 {
        ensure!(claim_request(&router, Uuid::new_v4()).await?.1["task"].is_null());
    }
    ensure!(
        pg("SELECT count(*) FROM mdm_commands.action_runs")? == completed,
        "once-per-version repeated"
    );
    let rerun = Uuid::new_v4();
    let body = json!({"operationId":rerun,"expectedRevision":1,"input":{"deadline":now+600}});
    let path = format!("/api/v2/policies/{policy_id}/reruns");
    let receipt = post(&mut author, &router, &path, body.clone()).await?;
    ensure!(post(&mut author, &router, &path, body).await? == receipt);
    ensure!(
        pg("SELECT count(*) FROM mdm_commands.action_runs")? == completed,
        "rerun eagerly expanded devices"
    );
    let (a, b) = tokio::join!(
        claim_request(&router, Uuid::new_v4()),
        claim_request(&router, Uuid::new_v4())
    );
    let a = a?;
    let b = b?;
    ensure!(a.0 == StatusCode::OK && b.0 == StatusCode::OK);
    let again = if !a.1["task"].is_null() {
        a.1["task"].clone()
    } else if !b.1["task"].is_null() {
        b.1["task"].clone()
    } else {
        claim(&router).await?
    };
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE occurrence='explicit:{rerun}'"
        ))?
        .trim()
            == "1",
        "concurrent admission duplicated rerun"
    );
    task_event(&router, &again, json!({"kind":"received"})).await?;
    task_event(&router, &again, json!({"kind":"start"})).await?;
    task_event(&router,&again,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    let unknown_policy = policy(&mut author, &router, id, &plan_runtime).await?;
    let pending = claim(&router).await?;
    let pending = poll::verify(&router, pending).await?;
    // Organization assignment survives its author's departure.
    crate::identity_fixture::set_grants(TENANT, &author_id, vec![]).await?;
    task_event(&router, &pending, json!({"kind":"received"})).await?;
    task_event(&router, &pending, json!({"kind":"start"})).await?;
    let task_id = pending["payload"]["taskId"].as_str().unwrap();
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{startedAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-61)) WHERE id='{task_id}'"
    ))?;
    for _ in 0..2 {
        execution.recover_action_fixture(unknown_policy).await?;
    }
    ensure!(
        pg(&format!(
            "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == "unknown"
    );
    let before = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    ensure!(claim_request(&router, Uuid::new_v4()).await?.1["task"].is_null());
    ensure!(
        pg("SELECT count(*) FROM mdm_commands.action_runs")? == before,
        "unknown execution repeated"
    );
    crate::identity_fixture::set_grants(TENANT, &author_id, grants.clone()).await?;
    post(
        &mut author,
        &router,
        &format!("/api/v2/policies/{unknown_policy}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
    execution.recover_action_fixture(unknown_policy).await?;
    ensure!(
        pg(&format!(
            "SELECT state->>'cancellation' FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == "requested"
    );
    pagination(&mut author, &router, id).await?;
    ensure!(stack.shutdown().join().await?.is_clean());
    remote_matrix(&mut author, &router, id, &base, execution.clone(), &grants).await?;
    ensure!(inventory.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;
    Ok(())
}

async fn pagination(author: &mut Browser, router: &Router, resource: Uuid) -> Result<()> {
    let before = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    for n in 1..=70 {
        let id = Uuid::from_u128(n);
        post(author,router,&format!("/api/v2/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,EMPTY_SCOPE)}})).await?;
    }
    let id = Uuid::from_u128(u128::MAX);
    post(author,router,&format!("/api/v2/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,TASK_SCOPE)}})).await?;
    ensure!(pg("SELECT count(*) FROM mdm_commands.action_runs")? == before);
    pg("UPDATE mdm_commands.action_polls SET policy_after=NULL")?;
    let task = claim(router)
        .await
        .map_err(|e| anyhow::anyhow!("policy pagination: {e}"))?;
    let task_id = task["payload"]["taskId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT v.policy FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE r.id='{task_id}'"))?.trim()==id.to_string(),"later policy starved");
    task_event(router, &task, json!({"kind":"received"})).await?;
    task_event(router, &task, json!({"kind":"start"})).await?;
    task_event(router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
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
        let request_id = response.headers()["x-request-id"].to_str()?;
        ensure!(
            audit_count(|record| record.request() == Some(request_id)
                && record.source() == "mdm.request"
                && record.status() == status.as_u16()
                && record.result()
                    == if status.is_success() {
                        "success"
                    } else {
                        "failed"
                    })?
                == 1
        );
        ensure!(audit_count(|record| record.request() == Some(request_id))? == 1);
        if status.is_success() {
            ensure!(response.headers().contains_key("etag"));
            ensure!(response.into_body().collect().await?.to_bytes().as_ref() == bytes);
        }
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("host", "mdm.example.test")
                .header("authorization", format!("Bearer {CREDENTIAL}"))
                .header("range", "bytes=0-3")
                .header("range", "bytes=4-7")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::BAD_REQUEST);
    let request_id = response.headers()["x-request-id"].to_str()?;
    ensure!(
        audit_count(|record| record.request() == Some(request_id)
            && record.status() == 400
            && record.result() == "failed")?
            == 1
    );
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

mod archive_race;
mod history;
mod poll;

async fn remote_matrix(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    base: &Value,
    execution: Arc<crate::execution::ExecutionService>,
    original: &[crate::authorization::Grant],
) -> Result<()> {
    let member = browser_subject(author, router).await?;
    let mut grants = original.to_vec();
    grants.extend(crate::identity_fixture::device_grants(
        None,
        &["operation_read", "operation_cancel"],
    )?);
    crate::identity_fixture::set_grants(TENANT, &member, grants).await?;
    let automation = start_automation(base).await?;
    let scope = Uuid::new_v4();
    let created=post(author,router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":DEVICE_ID}],"limitations":null,"exclusions":[]}}})).await?;
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
    let input = json!({"operationId":id,"resource":policy_definition(resource,EMPTY_SCOPE)["resource"],"targets":{"kind":"scope","id":scope},"action":{"kind":"execute","parameters":{}},"deadline":now+600});
    let before = pg("SELECT count(*) FROM mdm_policy.policies")?;
    let accepted = post(author, router, "/api/v2/remote-operations", input.clone()).await?;
    ensure!(accepted == post(author, router, "/api/v2/remote-operations", input).await?);
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
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let startup = owner.startup()?;
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(execution.registration().critical());
    launch.finish();
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
    let devices = (0..300)
        .map(|n| format!("unregistered-{n:04}"))
        .chain(std::iter::once(DEVICE_ID.to_owned()))
        .collect::<Vec<_>>();
    let bulk = Uuid::new_v4();
    post(author,router,"/api/v2/remote-operations",json!({"operationId":bulk,"resource":policy_definition(resource,EMPTY_SCOPE)["resource"],"targets":{"kind":"devices","devices":devices},"action":{"kind":"execute","parameters":{}},"deadline":now+600})).await?;
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
    ensure!(pg(&format!("SELECT count(*) FROM mdm_planning.remote_operation_targets WHERE operation='{bulk}' AND status='blocked'"))?.trim()=="300");
    ensure!(pg("SELECT count(*) FROM mdm_policy.policies")? == before);
    let task = claim(router).await?;
    let task_id = task["payload"]["taskId"].as_str().unwrap();
    ensure!(
        pg(&format!(
            "SELECT remote_operation FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == bulk.to_string()
    );
    let cancelled = post(
        author,
        router,
        &format!("/api/v2/remote-operations/{bulk}/cancel"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    ensure!(cancelled["cancelled"] == true);
    let mut event = json!({"kind":"start"});
    ensure!(
        task_event_request(router, &task, Uuid::new_v4(), &mut event)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    super::planning::await_ingress().await?;
    ensure!(owner.shutdown().join().await?.is_clean());
    ensure!(automation.shutdown().join().await?.is_clean());
    Ok(())
}
