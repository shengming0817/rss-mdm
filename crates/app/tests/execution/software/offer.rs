mod formats;
use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn required_available_and_uninstall_delivery() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs)
        .await
        .map_err(|e| anyhow::anyhow!("approved fixture: {e:#}"))?;
    let stack = worker(&fixture.base, fixture.content.clone())
        .await
        .map_err(|e| anyhow::anyhow!("software worker: {e:#}"))?;
    let router = fixture.router;
    let mut author = fixture.author;
    let bytes = fixture.bytes;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
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
    let task = claim(&router).await?;
    ensure!(
        task["payload"]["steps"][0]["action"]["package"] == "Private.Dependency"
            && task["payload"]["steps"][1]["action"]["package"] == "Private.Controlled"
            && task["payload"]["softwareResource"].is_null()
            && task["payload"]["admissionOperation"].is_null()
            && task["payload"]["startMode"] == "automatic",
        "offer: {task}"
    );
    ensure!(task["payload"]["steps"][1]["artifacts"][0]["length"] == bytes.len());
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    let start = event(&router, &task, json!({"kind":"start"})).await?;
    ensure!(
        start.0 == StatusCode::OK && start.1["permit"]["payload"]["permit"] == "start",
        "start: {start:?}"
    );
    let result = event(
        &router,
        &task,
        result_event(&task, "install", Some(0), "present", false)?,
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "result: {result:?}");
    let status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(status.0 == StatusCode::OK, "rollout: {status:?}");
    ensure!(
        status.1["stages"][0]["totalTargets"] == 1
            && status.1["stages"][0]["reported"] == 1
            && status.1["stages"][0]["unknown"] == 0
            && status.1["stages"][0]["verifiedSuccess"] == 1,
        "counts: {status:?}"
    );
    let runs = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/runs"),
            None,
        )
        .await?;
    ensure!(
        runs.1["items"][0]["effect"] == "verified",
        "run list effect: {runs:?}"
    );
    let detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{policy}/runs/{}",
                task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        detail.1["effect"] == "verified",
        "run detail effect: {detail:?}"
    );
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_commands.action_runs SET created_at=created_at-120 WHERE id=$1::uuid")
        .bind(task["payload"]["taskId"].as_str().unwrap())
        .execute(&mut owner)
        .await?;
    owner.close().await?;
    let repeated = agent(
        &router,
        "/api/agent/v6/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        repeated.1["task"].is_null(),
        "verified software was scheduled again: {repeated:?}"
    );
    write(
        &mut author,
        &router,
        &policy_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let available = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v3/policies/{available}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("available_install", &first_operation)}),
    )
    .await?;
    let optional = claim(&router).await?;
    ensure!(
        optional["payload"]["intent"] == "install"
            && optional["payload"]["startMode"] == "user_initiated",
        "optional: {optional}"
    );
    let awaiting = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{available}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        awaiting.1["stages"][0]["reported"] == 0,
        "self-service task auto-reported: {awaiting:?}"
    );
    ensure!(
        awaiting.1["stages"][0]["waitingUser"] == 1,
        "optional offer not visible as waiting_user: {awaiting:?}"
    );
    let optional_detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{available}/runs/{}",
                optional["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        optional_detail.1["userAction"] == "waiting_user",
        "optional run missing user wait: {optional_detail:?}"
    );
    ensure!(
        event(&router, &optional, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&router, &optional, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    ensure!(
        event(
            &router,
            &optional,
            result_event(&optional, "install", Some(17), "present", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let optional_status = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{available}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        optional_status.1["stages"][0]["verifiedSuccess"] == 1,
        "detector must be independent of installer exit: {optional_status:?}"
    );
    write(
        &mut author,
        &router,
        &format!("/api/v3/policies/{available}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let uninstall = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v3/policies/{uninstall}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("explicit_uninstall", &first_operation)}),
    )
    .await?;
    let removal_task = claim(&router).await?;
    ensure!(
        removal_task["payload"]["intent"] == "uninstall"
            && removal_task["payload"]["startMode"] == "automatic",
        "uninstall: {removal_task}"
    );
    ensure!(
        event(&router, &removal_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &removal_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(
            &router,
            &removal_task,
            result_event(&removal_task, "uninstall", Some(0), "absent", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let removed = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{uninstall}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        removed.1["stages"][0]["verifiedSuccess"] == 1,
        "uninstall detection: {removed:?}"
    );
    write(
        &mut author,
        &router,
        &format!("/api/v3/policies/{uninstall}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn windows_variant_delivery_and_detection() -> Result<()> {
    let fixture = Fixture::approved(Platform::Windows).await?;
    let stack = worker(&fixture.base, fixture.content.clone())
        .await
        .map_err(|e| anyhow::anyhow!("software worker: {e:#}"))?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let windows_scope = fixture.scope;
    let windows_credential = fixture.credential;
    let first_operation = fixture.first_operation;
    let windows_policy = Uuid::new_v4();
    write(&mut author,&router,&format!("/api/v3/policies/{windows_policy}"),0,json!({"action":"put","enabled":true,
        "definition":{"scope":windows_scope,
        "action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"admissionOperation":first_operation,"runLifetimeSeconds":600,
        "rollout":{"stages":[{"scope":windows_scope,"opensAt":0}]}}}})).await?;
    let windows_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v3/policies/{windows_policy}/devices"),
            None,
        )
        .await?;
    ensure!(
        windows_page.1["items"][0]["taskAdmission"]["state"] == "eligible",
        "windows admission: {windows_page:?}"
    );
    let windows_task = claim_with(&router, &windows_credential, Platform::Windows).await?;
    ensure!(
        windows_task["payload"]["platform"] == "windows"
            && windows_task["payload"]["architecture"] == "x86_64"
            && windows_task["payload"]["steps"][0]["action"]["package"]
                == "Private.WindowsDependency"
            && windows_task["payload"]["steps"][1]["action"]["behavior"]["kind"] == "msi",
        "windows variant: {windows_task}"
    );
    ensure!(
        event_with(
            &router,
            &windows_credential,
            &windows_task,
            json!({"kind":"received"})
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        event_with(
            &router,
            &windows_credential,
            &windows_task,
            json!({"kind":"start"})
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        event_with(
            &router,
            &windows_credential,
            &windows_task,
            result_event(&windows_task, "install", Some(0), "present", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let windows_rollout = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{windows_policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        windows_rollout.1["stages"][0]["verifiedSuccess"] == 1,
        "windows verification: {windows_rollout:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
