use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn rollout_time_success_gates_and_stage_evidence() -> Result<()> {
    let mut fixture = Fixture::approved(Platform::MacOs).await?;
    let empty_scope =
        prepared_scope(&fixture.base, &mut fixture.author, &fixture.router, &[]).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let first_operation = fixture.first_operation;
    let future = Uuid::new_v4();
    let future_path = format!("/api/v3/policies/{future}");
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let future_definition = |opens_at: i64, minimum: Option<u8>| json!({"scope":scope,"action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"admissionOperation":first_operation,"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":empty_scope,"opensAt":0},{"scope":scope,"opensAt":opens_at,"minimumVerifiedPercent":minimum}]}}});
    let future_policy = write(
        &mut author,
        &router,
        &future_path,
        0,
        json!({"action":"put","enabled":true,"definition":future_definition(now+3600,None)}),
    )
    .await?;
    let frozen_version = future_policy["versionId"].clone();
    let device_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v3/policies/{future}/devices"),
            None,
        )
        .await?;
    ensure!(
        device_page.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "device page misstates execution eligibility: {device_page:?}"
    );
    let preview=author.call(&router,Method::POST,"/api/v3/policies/previews",Some(json!({"definition":future_definition(now+3600,None),"after":null,"scopeResult":null}))).await?;
    ensure!(
        preview.1["items"][0]["taskAdmission"]["state"] == "scheduled",
        "preview misstates execution eligibility: {preview:?}"
    );
    let waiting = agent(
        &router,
        "/api/agent/v6/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
        "/api/agent/v6/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        gated.0 == StatusCode::OK && gated.1["task"].is_null(),
        "optional success gate: {gated:?}"
    );
    let resumed = write(
        &mut author,
        &router,
        &future_path,
        4,
        json!({"action":"put","enabled":true,"definition":future_definition(1,None)}),
    )
    .await?;
    ensure!(resumed["versionId"] == frozen_version);
    let resumed_task = claim(&router).await?;
    ensure!(
        resumed_task["payload"]["steps"][1]["action"]["package"] == "Private.Controlled",
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
    let reordered=write(&mut author,&router,&future_path,5,json!({"action":"put","enabled":true,
        "definition":{"scope":scope,
        "action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"macos_aarch64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"admissionOperation":first_operation,"runLifetimeSeconds":600,
        "rollout":{"stages":[{"scope":scope,"opensAt":0},{"scope":empty_scope,"opensAt":1}]}}}})).await?;
    ensure!(reordered["versionId"] == frozen_version);
    let reordered_status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{future}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        reordered_status.1["stages"][0]["verifiedSuccess"] == 1
            && reordered_status.1["stages"][1]["verifiedSuccess"] == 0,
        "stage edit reused another scope's evidence: {reordered_status:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.software"]
async fn new_approval_changes_execution_version() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let first_operation = fixture.first_operation;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v3/policies/{policy}");
    let published = write(
        &mut author,
        &router,
        &policy_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install", &first_operation)}),
    )
    .await?;
    ensure!(published["version"] == 1, "publish: {published}");
    write(
        &mut author,
        &router,
        &policy_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw","evidence":["version-identity"]}),
    )
    .await?;
    let reapproved = write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        2,
        json!({"action":"approve","evidence":["reapproved-for-future-task"]}),
    )
    .await?;
    let second_operation = reapproved["admission"]["operation"].clone();
    let rebound = write(
        &mut author,
        &router,
        &policy_path,
        2,
        json!({"action":"put","enabled":false,"definition":authored("required_install", &second_operation)}),
    )
    .await?;
    ensure!(
        rebound["versionId"] != published["versionId"],
        "reapproval must create a new execution version: {rebound}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
