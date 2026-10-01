use crate::test_support::software::write;
use crate::test_support::software_execution::case_device;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn known_failure_has_bounded_retries() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.execution.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let failed_policy = Uuid::new_v4();
    let failed_path = format!("/api/v2/policies/{failed_policy}");
    write(&mut author,&router,&failed_path,0,json!({"action":"put","enabled":true,"definition":authored("required_install",&first_operation)})).await?;
    let failed_task = claim(&router).await?;
    ensure!(
        event(&router, &failed_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &failed_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(
            &router,
            &failed_task,
            result_event(&failed_task, "install", Some(1), "absent", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let failed_detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{failed_policy}/runs/{}",
                failed_task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        failed_detail.1["effect"] == "failed",
        "known detector failure: {failed_detail:?}"
    );
    let mut previous_failure = failed_task["payload"]["taskId"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..2 {
        let mut owner =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query(
            "UPDATE mdm_commands.action_runs SET created_at=created_at-600 WHERE id=$1::uuid",
        )
        .bind(&previous_failure)
        .execute(&mut owner)
        .await?;
        owner.close().await?;
        let retry = claim(&router).await?;
        ensure!(event(&router, &retry, json!({"kind":"received"})).await?.0 == StatusCode::OK);
        ensure!(event(&router, &retry, json!({"kind":"start"})).await?.0 == StatusCode::OK);
        ensure!(
            event(
                &router,
                &retry,
                result_event(&retry, "install", Some(1), "absent", false)?
            )
            .await?
            .0 == StatusCode::OK
        );
        previous_failure = retry["payload"]["taskId"].as_str().unwrap().to_owned();
    }
    let exhausted = agent(
        &router,
        "/api/agent/v4/tasks/claim",
        Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        exhausted.1["task"].is_null(),
        "failed deployment exceeded bounded retries: {exhausted:?}"
    );
    write(
        &mut author,
        &router,
        &failed_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn reboot_waits_for_detection() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.execution.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let reboot_policy = Uuid::new_v4();
    let reboot_path = format!("/api/v2/policies/{reboot_policy}");
    write(&mut author,&router,&reboot_path,0,json!({"action":"put","enabled":true,"definition":authored("required_install",&first_operation)})).await?;
    let reboot_task = claim(&router).await?;
    ensure!(
        event(&router, &reboot_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &reboot_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(
            &router,
            &reboot_task,
            result_event(&reboot_task, "install", Some(0), "absent", true)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let reboot_detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/policies/{reboot_policy}/runs/{}",
                reboot_task["payload"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        reboot_detail.1["effect"] == "waiting_reboot",
        "pending reboot: {reboot_detail:?}"
    );
    let reboot_retry = agent(
        &router,
        "/api/agent/v4/tasks/claim",
        Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        reboot_retry.1["task"].is_null(),
        "reboot caused blind retry: {reboot_retry:?}"
    );
    ensure!(
        event(
            &router,
            &reboot_task,
            result_event(&reboot_task, "install", Some(0), "present", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    write(
        &mut author,
        &router,
        &reboot_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unknown_effect_survives_registration_replacement() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.execution.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let unknown_policy = Uuid::new_v4();
    write(&mut author,&router,&format!("/api/v2/policies/{unknown_policy}"),0,json!({"action":"put","enabled":true,"definition":authored("required_install",&first_operation)})).await?;
    let unknown_task = claim(&router).await?;
    ensure!(
        event(&router, &unknown_task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(&router, &unknown_task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        event(
            &router,
            &unknown_task,
            result_event(&unknown_task, "install", None, "unknown", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let next_password = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    let next_credential = &crate::test_support::credential("replacement");
    author.operation = Some(Uuid::new_v4());
    let next_enrollment = author
        .call(
            &router,
            Method::POST,
            "/api/v3/enrollments",
            Some(
                json!({"deviceId":case_device(),"password":next_password,"source":"agent.builtin"}),
            ),
        )
        .await?;
    ensure!(
        next_enrollment.0.is_success(),
        "replacement enrollment: {next_enrollment:?}"
    );
    author.operation = None;
    let next_registration=agent_call(&router,Method::POST,"/api/agent/v4/registrations",None,Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4(),"enrollmentId":next_enrollment.1["enrollmentId"],"password":next_password,"credential":next_credential,"platform":"macos","architecture":"aarch64","capabilities":["inventory.basic.v4","software.pkg.system.v4"]}))).await?;
    ensure!(
        next_registration.0 == StatusCode::CREATED,
        "replacement registration: {next_registration:?}"
    );
    let after_reenroll = agent_call(
        &router,
        Method::POST,
        "/api/agent/v4/tasks/claim",
        Some(next_credential),
        Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        after_reenroll.0 == StatusCode::OK && after_reenroll.1["task"].is_null(),
        "unknown side effect retried after registration replacement: {after_reenroll:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unknown_result_replay_and_late_detection() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.execution.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v2/policies/{policy}");
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
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    ensure!(event(&router, &task, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    let unknown_operation = Uuid::new_v4();
    let unknown_request = json!({"wireVersion":4,"executionContext":task["payload"]["executionContext"],"operationId":unknown_operation,"attemptId":task["payload"]["attemptId"],"event":result_event(&task,"install",Some(0),"unknown",false)?});
    let result = agent(
        &router,
        &format!(
            "/api/agent/v4/tasks/{}/events",
            task["payload"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request.clone()),
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "unknown result: {result:?}");
    let replay = agent(
        &router,
        &format!(
            "/api/agent/v4/tasks/{}/events",
            task["payload"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request),
    )
    .await?;
    ensure!(replay == result, "result replay: {replay:?}");
    let uncertainty = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        uncertainty.1["stages"][0]["reported"] == 1
            && uncertainty.1["stages"][0]["unknown"] == 1
            && uncertainty.1["stages"][0]["verifiedSuccess"] == 0,
        "unknown denominator: {uncertainty:?}"
    );
    let no_retry = agent(
        &router,
        "/api/agent/v4/tasks/claim",
        Some(json!({"wireVersion":4,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        no_retry.0 == StatusCode::OK && no_retry.1["task"].is_null(),
        "unknown effect was blindly retried: {no_retry:?}"
    );
    let late = event(
        &router,
        &task,
        result_event(&task, "install", Some(0), "present", false)?,
    )
    .await?;
    ensure!(late.0 == StatusCode::OK, "late detection: {late:?}");
    let resolved = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/software/rollout"),
            None,
        )
        .await?;
    ensure!(
        resolved.1["stages"][0]["unknown"] == 0 && resolved.1["stages"][0]["verifiedSuccess"] == 1,
        "late detection did not resolve unknown: {resolved:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
