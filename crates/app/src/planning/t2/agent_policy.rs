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
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn preview_publish_authorization_and_commit_replay() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
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
    crate::test_support::identity::set_grants(TENANT, &author_id, without_resource).await?;
    let denied=author.call(&router,Method::POST,&format!("/api/v2/policies/{}",Uuid::new_v4()),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,TASK_SCOPE)}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "publishing without ResourceRead: {denied:?}"
    );
    crate::test_support::identity::set_grants(TENANT, &author_id, grants.clone()).await?;
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
    let _policy_id = policy(&mut author, &router, id, &plan_runtime).await?;
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
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn explicit_rerun_deduplicates() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let policy_id = publish(&mut author, &router, id).await?;
    let task = claim(&router).await?;
    complete(&router, &task).await?;
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
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_scan_reaches_late_match() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    fixture.scope(EMPTY_SCOPE, json!([])).await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
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
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.agent_policy"]
async fn policy_reference_and_archive_are_serialized() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture.scope(EMPTY_SCOPE, json!([])).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    // Both authenticated requests contend on the same active resource version.
    let policy = Uuid::new_v4();
    let create = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_definition(id,EMPTY_SCOPE)}});
    let policy_path = format!("/api/v2/policies/{policy}");
    let archive = json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"input":{"action":"archive","version":"v1"}});
    let path = format!("/api/v3/resources/{id}");
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
