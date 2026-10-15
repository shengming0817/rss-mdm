//! Persisted admission, entry coordinates and trigger deduplication through real claim requests.
use crate::test_support::agent_execution::*;
use crate::test_support::*;

async fn publish(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    scope: Uuid,
    frequency: &str,
    schedule: Option<Value>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut definition = policy_definition(resource, scope);
    definition["action"]["frequency"] = json!(frequency);
    if let Some(schedule) = schedule {
        definition["action"]["schedule"] = schedule;
    }
    post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})).await?;
    Ok(id)
}
async fn disable(author: &mut Browser, router: &Router, id: Uuid) -> Result<()> {
    post(
        author,
        router,
        &format!("/api/v1/policies/{id}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
    Ok(())
}
async fn complete(router: &Router, task: &Value) -> Result<()> {
    task_event(router, task, json!({"kind":"received"})).await?;
    task_event(router, task, json!({"kind":"start"})).await?;
    task_event(router,task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    Ok(())
}
fn count(id: Uuid) -> Result<i64> {
    Ok(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE v.policy='{id}'"))?.trim().parse()?)
}
async fn no_repeat(router: &Router, id: Uuid, expected: i64) -> Result<()> {
    for _ in 0..3 {
        let reply = claim_request(router, Uuid::new_v4()).await?;
        ensure!(
            reply.0 == StatusCode::OK && reply.1["task"].is_null(),
            "unexpected repeated offer: {reply:?}"
        );
    }
    ensure!(count(id)? == expected);
    Ok(())
}
fn belongs_to(task: &Value, id: Uuid) -> Result<()> {
    let task = task["payload"]["task"]["taskId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT policy FROM mdm_policy.versions WHERE id=(SELECT policy_version FROM mdm_commands.action_runs WHERE id='{task}')"))?.trim()==id.to_string());
    Ok(())
}
// Advance only Scope publication, leaving every PolicyReconcile job queued. This
// reproduces exit/reentry before asynchronous assignment observes either transition.
async fn publish_scope_without_assignments(
    service: &crate::planning::Planning,
    author: &mut Browser,
    router: &Router,
    scope: Uuid,
    group: Uuid,
    revision: u64,
    exclude: bool,
) -> Result<i64> {
    let changed=post(author,router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":if exclude{vec![json!({"kind":"device","id":case_device_id()})]}else{vec![]}}}})).await?;
    let task = Uuid::parse_str(changed["task"].as_str().unwrap())?;
    for _ in 0..32 {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            service.tenant.to_string(),
            "management_write",
        );
        rss_mdm_flow_service::transaction::run(
            &service.audit_store,
            &service.runtime,
            service.tenant,
            &audit,
            (service, task, scope),
            |ctx, tx| {
                Box::pin(async move { ctx.0.advance_scope_job_in(tx, ctx.1, ctx.2, None).await })
            },
            rss_mdm_flow_service::transaction::TransactionOwner::Planning,
        )
        .await?;
        audit.finalize(None);
        if pg(&format!(
            "SELECT phase FROM mdm_planning.scope_runs WHERE id='{task}'"
        ))?
        .trim()
            == "published"
        {
            let coordinate = pg(&format!(
                "SELECT entry_revision FROM mdm_planning.scope_channel_results WHERE run='{task}' AND channel='agent' AND device='{}'",
                case_device_id()
            ))?;
            ensure!(
                !coordinate.trim().is_empty(),
                "scope projection missing for revision {revision}, exclude={exclude}: {}",
                pg(&format!(
                    "SELECT input::text FROM mdm_planning.scope_runs WHERE id='{task}'; SELECT row_to_json(r)::text FROM mdm_planning.scope_channel_results r WHERE run='{task}'"
                ))?
            );
            return Ok(coordinate.trim().parse()?);
        }
    }
    anyhow::bail!("scope publication did not complete")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.frequency"]
async fn once_per_entry_tracks_membership_epochs() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    let stack = worker(&fixture.base).await?;
    let base = &fixture.base;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let automation = start_automation(base).await?;
    let group = Uuid::new_v4();
    let scope = Uuid::new_v4();
    post(author,router,&format!("/api/v1/groups/{group}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","assetContext":"endpoint","name":"entry-frequency","description":"","criteria":null}})).await?;
    let added=post(author,router,&format!("/api/v1/groups/{group}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"members","add":[{"kind":"endpoint","id":case_device_id()}],"remove":[]}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v1/groups/{group}/tasks/{}",
            added["task"].as_str().unwrap()
        ),
    )
    .await?;
    let created=post(author,router,&format!("/api/v1/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v1/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    let entry = publish(author, router, resource, scope, "once_per_entry", None).await?;
    let first = claim(router).await?;
    belongs_to(&first, entry)?;
    complete(router, &first).await?;
    no_repeat(router, entry, 1).await?;
    tokio::time::timeout(Duration::from_secs(30),async {
        while pg(&format!("SELECT count(*) FROM mdm_planning.policy_assignments WHERE policy='{entry}' AND entry_revision>0"))?.trim()=="0" {tokio::time::sleep(Duration::from_millis(50)).await;}
        Ok::<_,anyhow::Error>(())
    }).await??;
    crate::test_support::stop_worker(automation).await?;
    let service = crate::planning::test_support::planning(rss_request_context::TenantId::parse(
        case_tenant(),
    )?)
    .await;
    let original=pg(&format!("SELECT min(entry_revision) FROM mdm_planning.policy_assignments WHERE policy='{entry}' AND entry_revision>0"))?.trim().parse::<i64>()?;
    let continuous =
        publish_scope_without_assignments(&service, author, router, scope, group, 1, false).await?;
    ensure!(
        continuous == original,
        "continuous membership changed entry coordinate"
    );
    no_repeat(router, entry, 1).await?;
    let exited =
        publish_scope_without_assignments(&service, author, router, scope, group, 2, true).await?;
    ensure!(exited == 0, "published exit retained eligible entry");
    // Move only the test's admission timestamp to represent an elapsed check-in interval.
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET created_at=created_at-61 WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{entry}')"
    ))?;
    no_repeat(router, entry, 1).await?;
    let reentered =
        publish_scope_without_assignments(&service, author, router, scope, group, 3, false).await?;
    ensure!(
        reentered > original,
        "reentry did not advance durable Scope entry"
    );
    ensure!(pg(&format!("SELECT min(entry_revision) FROM mdm_planning.policy_assignments WHERE policy='{entry}' AND entry_revision>0"))?.trim().parse::<i64>()?==original,"test allowed asynchronous assignment to observe transition");
    let second = claim(router).await?;
    belongs_to(&second, entry)?;
    complete(router, &second).await?;
    ensure!(count(entry)? == 2);
    ensure!(pg(&format!("SELECT count(DISTINCT occurrence) FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{entry}')"))?.trim()=="2");
    disable(author, router, entry).await?;
    service.runtime.close().await;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.frequency"]
async fn registration_and_checkin_survive_router_restart() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let base = &fixture.base;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let registration = publish(
        author,
        router,
        resource,
        case_task_scope(),
        "every_trigger",
        Some(json!({"trigger":{"kind":"registration"},"notBefore":0,"jitterSeconds":0})),
    )
    .await?;
    let task = claim(router).await?;
    belongs_to(&task, registration)?;
    complete(router, &task).await?;
    let restarted = app_with_access(base, database(base).await?).await?.0;
    no_repeat(&restarted, registration, 1).await?;
    disable(author, router, registration).await?;
    let checkin = publish(
        author,
        router,
        resource,
        case_task_scope(),
        "every_trigger",
        None,
    )
    .await?;
    let task = claim(&restarted).await?;
    belongs_to(&task, checkin)?;
    complete(&restarted, &task).await?;
    no_repeat(&restarted, checkin, 1).await?;
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET created_at=created_at-61 WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{checkin}')"
    ))?;
    let task = claim(&restarted).await?;
    belongs_to(&task, checkin)?;
    complete(&restarted, &task).await?;
    ensure!(count(checkin)? == 2);
    disable(author, router, checkin).await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.frequency"]
async fn interval_misfire_skip_and_coalesce() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let trigger = json!({"kind":"interval","anchor":now-7320,"seconds":3600});
    let skip=publish(author,router,resource,case_task_scope(),"every_trigger",Some(json!({"trigger":trigger,"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"skip","maxLatenessSeconds":30}}))).await?;
    no_repeat(router, skip, 0).await?;
    disable(author, router, skip).await?;
    let coalesce=publish(author,router,resource,case_task_scope(),"every_trigger",Some(json!({"trigger":trigger,"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}}))).await?;
    let task = claim(router).await?;
    belongs_to(&task, coalesce)?;
    complete(router, &task).await?;
    no_repeat(router, coalesce, 1).await?;
    ensure!(pg(&format!("SELECT occurrence LIKE 'timer:{}:%' FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{coalesce}')",now-120))?.trim()=="t");
    disable(author, router, coalesce).await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
