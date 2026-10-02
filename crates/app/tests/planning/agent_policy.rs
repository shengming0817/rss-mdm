use crate::test_support::agent_execution::*;
use crate::test_support::*;
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

async fn policy(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let body = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}});
    let before = run_count(id)?;
    runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitPending,
    );
    let path = format!("/api/v3/policies/{id}");
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
        run_count(id)? == before,
        "publication must not fan out runs"
    );
    Ok(id)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn preview_publish_authorization_and_commit_replay() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let router = fixture.router;
    let plan_runtime = fixture.plan_runtime;
    let mut author = fixture.author;
    let author_id = fixture.author_id;
    let grants = fixture.grants;
    let without_resource = grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ResourceRead)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &author_id, without_resource).await?;
    let denied=author.call(&router,Method::POST,&format!("/api/v3/policies/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,case_task_scope())}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "publishing without ResourceRead: {denied:?}"
    );
    crate::test_support::identity::set_grants(case_tenant(), &author_id, grants.clone()).await?;
    let preview_before = pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))?;
    let preview = post(
        &mut author,
        &router,
        "/api/v3/policies/previews",
        json!({"definition":policy_definition(id,case_task_scope())}),
    )
    .await?;
    ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
    ensure!(
        pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'))",
            tenant = case_tenant()
        ))? == preview_before,
        "draft preview published work"
    );
    let _policy_id = policy(&mut author, &router, id, &plan_runtime).await?;
    ensure!(
        author
            .call(
                &router,
                Method::POST,
                &format!("/api/v4/resources/{id}"),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}})),
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn explicit_rerun_deduplicates() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let policy_id = publish(&mut author, &router, id).await?;
    let task = claim(&router).await?;
    complete(&router, &task).await?;
    let completed = run_count(policy_id)?;
    for _ in 0..3 {
        ensure!(claim_request(&router, Uuid::new_v4()).await?.1["task"].is_null());
    }
    ensure!(
        run_count(policy_id)? == completed,
        "once-per-version repeated"
    );
    let rerun = Uuid::new_v4();
    let body = json!({"operationId":rerun,"expectedRevision":1,"input":{"deadline":now+600}});
    let path = format!("/api/v3/policies/{policy_id}/reruns");
    let receipt = post(&mut author, &router, &path, body.clone()).await?;
    ensure!(post(&mut author, &router, &path, body).await? == receipt);
    ensure!(
        run_count(policy_id)? == completed,
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
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_scan_reaches_late_match() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    fixture.scope(case_empty_scope(), json!([])).await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}'",
        case_tenant(),
        case_device_id()
    ))?;
    let ordered_namespace = case::id("policy-scan") & !0xffff;
    for n in 1..=70 {
        let id = Uuid::from_u128(ordered_namespace | n);
        post(author,router,&format!("/api/v3/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_empty_scope())}})).await?;
    }
    let id = Uuid::from_u128(ordered_namespace | 0xffff);
    post(author,router,&format!("/api/v3/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(resource,case_task_scope())}})).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}'",
            case_tenant(),
            case_device_id()
        ))? == before
    );
    pg(&format!(
        "UPDATE mdm_commands.action_polls SET policy_after=NULL WHERE tenant_id='{}' AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}')",
        case_tenant(),
        case_tenant(),
        case_device_id()
    ))?;
    let task = claim(router)
        .await
        .map_err(|e| anyhow::anyhow!("policy pagination: {e}"))?;
    let task_id = task["payload"]["taskId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT v.policy FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE r.id='{task_id}'"))?.trim()==id.to_string(),"later policy starved");
    task_event(router, &task, json!({"kind":"received"})).await?;
    task_event(router, &task, json!({"kind":"start"})).await?;
    task_event(router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_reference_and_archive_are_serialized() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture.scope(case_empty_scope(), json!([])).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    // Both authenticated requests contend on the same active resource version.
    let policy = Uuid::new_v4();
    let create = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,case_empty_scope())}});
    let policy_path = format!("/api/v3/policies/{policy}");
    let archive = json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}});
    let path = format!("/api/v4/resources/{id}");
    let mut archiver = author.clone();
    let (created, archived) = tokio::try_join!(
        author.call(router, Method::POST, &policy_path, Some(create)),
        archiver.call(router, Method::POST, &path, Some(archive.clone()))
    )?;
    ensure!(
        created.0.is_success() != archived.0.is_success(),
        "archive race: {created:?} / {archived:?}"
    );
    if created.0.is_success() {
        ensure!(archived.0 == StatusCode::CONFLICT);
        post(
            author,
            router,
            &policy_path,
            json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
        )
        .await?;
        let historical = archiver
            .call(router, Method::POST, &path, Some(archive))
            .await?;
        ensure!(
            historical.0 == StatusCode::CONFLICT,
            "disabled policy lost historical reference: {historical:?}"
        );
    } else {
        ensure!(
            created.0 == StatusCode::CONFLICT,
            "archived resource admitted: {created:?}"
        );
    }
    Ok(())
}

async fn reject_script_at_all_entrances(
    fixture: &mut Fixture,
    definition: Value,
    expected: StatusCode,
) -> Result<()> {
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let requests = [
        (
            "/api/v3/policies/previews".to_owned(),
            json!({"definition":definition}),
        ),
        (
            format!("/api/v3/policies/{}", Uuid::new_v4()),
            json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}}),
        ),
        (
            "/api/v3/remote-operations".to_owned(),
            json!({"operationId":Uuid::new_v4(),"resource":definition["action"]["resource"],"targets":{"kind":"devices","devices":[case_device_id()]},"action":{"kind":"execute","parameters":definition["action"]["parameters"]},"deadline":now+600}),
        ),
    ];
    let mut code = None;
    for (path, body) in requests {
        let response = fixture
            .author
            .call(&fixture.router, Method::POST, &path, Some(body))
            .await?;
        ensure!(response.0 == expected, "{path}: {response:?}");
        if let Some(code) = &code {
            ensure!(
                &response.1 == code,
                "inconsistent script rejection: {response:?}"
            );
        }
        code = Some(response.1);
    }
    Ok(())
}

async fn script_resource(
    fixture: &mut Fixture,
    definition: &Value,
    length: u64,
    digest: [u8; 32],
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let author = &mut fixture.author;
    let router = &fixture.router;
    resource(
        author,
        router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(author, router, id, 1, json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"prepared-script","length":length,"sha256":digest},"definition":definition}}]})).await?;
    resource(
        author,
        router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    Ok(id)
}

fn script_effects() -> Result<String> {
    pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_planning.remote_operations WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm.collection_definitions WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn script_preparation_is_shared_without_preview_effects() -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut fixture = Fixture::new().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let _server =
        crate::test_support::software::HttpServer::start(listener, fixture.router.clone());
    fixture.author.network = Some((
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()?,
        format!("http://{address}"),
    ));
    fixture.register().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let (id, _, declaration) = fixture.resource().await?;
    let before = script_effects()?;
    let definition = policy_definition(id, case_task_scope());
    let preview = post(
        &mut fixture.author,
        &fixture.router,
        "/api/v3/policies/previews",
        json!({"definition":definition}),
    )
    .await?;
    ensure!(preview["items"][0]["eligibility"]["state"] == "eligible");
    let mut invalid = definition.clone();
    invalid["action"]["parameters"] = json!({"unexpected":true});
    reject_script_at_all_entrances(&mut fixture, invalid, StatusCode::BAD_REQUEST).await?;
    let mut invalid = definition.clone();
    invalid["action"]["resource"]["architecture"] = json!("x86_64");
    reject_script_at_all_entrances(&mut fixture, invalid, StatusCode::BAD_REQUEST).await?;
    let digest: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
    let oversized = script_resource(&mut fixture, &declaration, 16_777_217, digest).await?;
    reject_script_at_all_entrances(
        &mut fixture,
        policy_definition(oversized, case_task_scope()),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let mut sql = declaration.clone();
    sql["profile"] = json!("osquery");
    sql["sql"] = json!("SELECT version FROM osquery_info");
    let mismatch = script_resource(&mut fixture, &sql, 3, digest).await?;
    reject_script_at_all_entrances(
        &mut fixture,
        policy_definition(mismatch, case_task_scope()),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    // Unique bytes isolate the missing/corrupt content checks from other T2 cases.
    let bytes = format!("#!/bin/sh\n# {}\nprintf '{{}}'\n", Uuid::new_v4());
    let digest: [u8; 32] = Sha256::digest(bytes.as_bytes()).into();
    let content_id =
        script_resource(&mut fixture, &declaration, bytes.len() as u64, digest).await?;
    let content_definition = policy_definition(content_id, case_task_scope());
    reject_script_at_all_entrances(
        &mut fixture,
        content_definition.clone(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    ensure!(
        upload(
            &fixture.author,
            &fixture.router,
            content_id,
            bytes.as_bytes()
        )
        .await?
            == StatusCode::CREATED
    );
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::path::Path::new(fixture.base["content"]["directory"].as_str().unwrap())
        .join(case_tenant())
        .join(hex);
    std::fs::write(&path, "x".repeat(bytes.len()))?;
    let rejected = reject_script_at_all_entrances(
        &mut fixture,
        content_definition,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    std::fs::write(&path, &bytes)?;
    rejected?;
    ensure!(
        script_effects()? == before,
        "preview or rejected script wrote execution facts"
    );
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let input = json!({"operationId":Uuid::new_v4(),"resource":definition["action"]["resource"],"targets":{"kind":"devices","devices":[case_device_id()]},"action":{"kind":"execute","parameters":{}},"deadline":now+600});
    let accepted = post(
        &mut fixture.author,
        &fixture.router,
        "/api/v3/remote-operations",
        input.clone(),
    )
    .await?;
    ensure!(
        post(
            &mut fixture.author,
            &fixture.router,
            "/api/v3/remote-operations",
            input
        )
        .await?
            == accepted
    );
    Ok(())
}
