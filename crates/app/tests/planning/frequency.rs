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
    definition["behavior"]["frequency"] = json!(frequency);
    if let Some(schedule) = schedule {
        definition["behavior"]["schedule"] = schedule;
    }
    post(author,router,&format!("/api/v2/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})).await?;
    Ok(id)
}
async fn disable(author: &mut Browser, router: &Router, id: Uuid) -> Result<()> {
    post(
        author,
        router,
        &format!("/api/v2/policies/{id}"),
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
    let task = task["payload"]["taskId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT policy FROM mdm_policy.versions WHERE id=(SELECT policy_version FROM mdm_commands.action_runs WHERE id='{task}')"))?.trim()==id.to_string());
    Ok(())
}
async fn membership(
    author: &mut Browser,
    router: &Router,
    group: Uuid,
    revision: u64,
    present: bool,
    scope: Uuid,
) -> Result<()> {
    let changed=post(author,router,&format!("/api/v2/groups/{group}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"members","add":if present {vec![DEVICE_ID]}else{vec![]},"remove":if present {vec![]}else{vec![DEVICE_ID]}}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/groups/{group}/tasks/{}",
            changed["task"].as_str().unwrap()
        ),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = pg(&format!(
                "SELECT mdm_planning.scope_admission('{scope}','{DEVICE_ID}')->>'state'"
            ))?;
            if state.trim() == if present { "eligible" } else { "excluded" } {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
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
    post(author,router,&format!("/api/v2/groups/{group}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"entry-frequency","description":"","criteria":null}})).await?;
    let added=post(author,router,&format!("/api/v2/groups/{group}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"members","add":[DEVICE_ID],"remove":[]}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/groups/{group}/tasks/{}",
            added["task"].as_str().unwrap()
        ),
    )
    .await?;
    let created=post(author,router,&format!("/api/v2/scopes/{scope}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}}})).await?;
    await_task(
        author,
        router,
        &format!(
            "/api/v2/scopes/{scope}/tasks/{}",
            created["task"].as_str().unwrap()
        ),
    )
    .await?;
    let entry = publish(author, router, resource, scope, "once_per_entry", None).await?;
    let first = claim(router).await?;
    belongs_to(&first, entry)?;
    complete(router, &first).await?;
    no_repeat(router, entry, 1).await?;
    membership(author, router, group, 2, false, scope).await?;
    // Move only the test's admission timestamp to represent an elapsed check-in interval.
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET created_at=created_at-61 WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{entry}')"
    ))?;
    no_repeat(router, entry, 1).await?;
    membership(author, router, group, 3, true, scope).await?;
    let second = claim(router).await?;
    belongs_to(&second, entry)?;
    complete(router, &second).await?;
    ensure!(count(entry)? == 2);
    ensure!(pg(&format!("SELECT count(DISTINCT occurrence) FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{entry}')"))?.trim()=="2");
    disable(author, router, entry).await?;
    ensure!(automation.shutdown().join().await?.is_clean());
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.frequency"]
async fn registration_and_checkin_survive_router_restart() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    let stack = worker(&fixture.base).await?;
    let base = &fixture.base;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let registration = publish(
        author,
        router,
        resource,
        TASK_SCOPE,
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
    let checkin = publish(author, router, resource, TASK_SCOPE, "every_trigger", None).await?;
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
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.frequency"]
async fn interval_misfire_skip_and_coalesce() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let trigger = json!({"kind":"interval","anchor":now-7320,"seconds":3600});
    let skip=publish(author,router,resource,TASK_SCOPE,"every_trigger",Some(json!({"trigger":trigger,"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"skip","maxLatenessSeconds":30}}))).await?;
    no_repeat(router, skip, 0).await?;
    disable(author, router, skip).await?;
    let coalesce=publish(author,router,resource,TASK_SCOPE,"every_trigger",Some(json!({"trigger":trigger,"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}}))).await?;
    let task = claim(router).await?;
    belongs_to(&task, coalesce)?;
    complete(router, &task).await?;
    no_repeat(router, coalesce, 1).await?;
    ensure!(pg(&format!("SELECT occurrence LIKE 'timer:{}:%' FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{coalesce}')",now-120))?.trim()=="t");
    disable(author, router, coalesce).await?;
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
