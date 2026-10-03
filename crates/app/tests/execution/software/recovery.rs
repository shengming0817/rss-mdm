use crate::test_support::software::write;
use crate::test_support::software_execution::case_device;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn known_failure_has_bounded_retries() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let failed_policy = Uuid::new_v4();
    let failed_path = format!("/api/v3/policies/{failed_policy}");
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
        "/api/agent/runtime/v1/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let reboot_policy = Uuid::new_v4();
    let reboot_path = format!("/api/v3/policies/{reboot_policy}");
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
        "/api/agent/runtime/v1/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
async fn unknown_effect_survives_credential_recovery() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
    let unknown_policy = Uuid::new_v4();
    write(&mut author,&router,&format!("/api/v3/policies/{unknown_policy}"),0,json!({"action":"put","enabled":true,"definition":authored("required_install",&first_operation)})).await?;
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
    let registration: String = pg(&format!("SELECT id FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}' AND channel='agent' AND state='active'",case_tenant(),case_device()))?.trim().into();
    let secret = credential("recovery-software");
    set_device_grants(
        &mut author,
        &router,
        case_device(),
        &[
            "credentials",
            "inventory_read",
            "inventory_collect",
            "configuration_write",
            "operation_read",
        ],
    )
    .await?;
    let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":secret,"platform":"macos","csr":crate::test_support::agent::csr()?});
    let grant = author
        .call(
            &router,
            Method::POST,
            &format!("/api/v3/agent-registrations/{registration}/recovery"),
            Some(input.clone()),
        )
        .await?;
    ensure!(grant.0 == StatusCode::OK, "{grant:?}");
    let mut signing = input;
    signing["runtime"] = json!({"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v6","software.pkg.system.v6"],"executionContext":context(Platform::MacOs)});
    let service = crate::test_support::agent::service(&authority::Authority::open().await?)?;
    let next_credential = &credential("replacement");
    let next_registration =
        crate::test_support::agent::complete_grant(&service, &grant.1, &signing, next_credential)
            .await?;
    ensure!(next_registration["registrationId"] == registration);
    let after_reenroll = agent_call(
        &router,
        Method::POST,
        "/api/agent/runtime/v1/tasks/claim",
        Some(next_credential),
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
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
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    ensure!(event(&router, &task, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    let unknown_operation = Uuid::new_v4();
    let unknown_request = json!({"wireVersion":6,"executionContext":task["payload"]["executionContext"],"operationId":unknown_operation,"attemptId":task["payload"]["attemptId"],"event":result_event(&task,"install",Some(0),"unknown",false)?});
    let result = agent(
        &router,
        &format!(
            "/api/agent/runtime/v1/tasks/{}/events",
            task["payload"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request.clone()),
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "unknown result: {result:?}");
    let replay = agent(
        &router,
        &format!(
            "/api/agent/runtime/v1/tasks/{}/events",
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
        "/api/agent/runtime/v1/tasks/claim",
        Some(json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn withdrawn_software_does_not_poison_claims_for_other_policies_or_outside_scope()
-> Result<()> {
    let mut f = Fixture::approved(Platform::MacOs).await?;
    let outside = prepared_scope(&f.base, &mut f.author, &f.router, &[]).await?;
    let dependency = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v3/software/resources/{}/versions/v1", f.dependency),
            None,
        )
        .await?;
    ensure!(dependency.0 == StatusCode::OK);
    let approval = dependency.1["admission"]["operation"].clone();
    let mut ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    ids.sort();
    for (policy, resource, scope, operation) in [
        (ids[0], f.resource, f.scope, &f.first_operation),
        (ids[1], f.resource, outside, &f.first_operation),
        (ids[2], f.dependency, f.scope, &approval),
    ] {
        write(&mut f.author,&f.router,&format!("/api/v3/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":authored(resource,scope,"required_install",operation)})).await?;
    }
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v3/software/resources/{}/versions/v1", f.resource),
        1,
        json!({"action":"withdraw","evidence":["withdraw only the root"]}),
    )
    .await?;
    let stack = worker(&f.base, f.content.clone()).await?;
    let task = claim(&f.router).await?;
    ensure!(
        task["payload"]["steps"].as_array().is_some_and(
            |steps| steps.len() == 1 && steps[0]["action"]["package"] == "Private.Dependency"
        ),
        "withdrawal blocked unrelated valid policy: {task}"
    );
    let page = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v3/policies/{}/devices", ids[0]),
            None,
        )
        .await?;
    ensure!(
        page.0 == StatusCode::OK
            && page.1["items"][0]["taskAdmission"]["state"] == "approval_withdrawn",
        "withdrawal diagnosis: {page:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
