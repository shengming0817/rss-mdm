use crate::test_support::software::write;
use crate::test_support::software_execution::case_device;
use crate::test_support::software_execution::*;
use crate::test_support::{agent::*, http::*, process::*, runtime::*, *};
use sqlx::Connection;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn successful_removal_invalidates_prior_installation_across_policies() -> Result<()> {
    let mut f = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let stack = worker(&f.base, f.execution.clone()).await?;
    let install = Uuid::new_v4();
    let duplicate = Uuid::new_v4();
    let removal = Uuid::new_v4();
    let install_path = format!("/api/v1/policies/{install}");
    let duplicate_path = format!("/api/v1/policies/{duplicate}");
    let removal_path = format!("/api/v1/policies/{removal}");
    write(&mut f.author, &f.router, &install_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install")})).await?;
    let installed = claim(&f.router).await?;
    complete_effect(&f.router, &installed, "install", "present").await?;
    write(
        &mut f.author,
        &f.router,
        &install_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(&mut f.author, &f.router, &duplicate_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install")})).await?;
    assert_no_software_run(&f.router, duplicate).await?;
    write(
        &mut f.author,
        &f.router,
        &duplicate_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(&mut f.author, &f.router, &removal_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"explicit_uninstall")})).await?;
    let removed = claim(&f.router).await?;
    ensure!(removed["payload"]["task"]["authorization"]["policyId"] == removal.to_string());
    complete_effect(&f.router, &removed, "uninstall", "absent").await?;
    write(
        &mut f.author,
        &f.router,
        &removal_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(
        &mut f.author,
        &f.router,
        &duplicate_path,
        2,
        json!({"action":"enable"}),
    )
    .await?;
    let reinstalled = claim(&f.router).await?;
    ensure!(
        reinstalled["payload"]["task"]["authorization"]["policyId"] == duplicate.to_string(),
        "successful removal must permit the same version to be installed again: {reinstalled}"
    );
    complete_effect(&f.router, &reinstalled, "install", "present").await?;
    write(
        &mut f.author,
        &f.router,
        &duplicate_path,
        3,
        json!({"action":"disable"}),
    )
    .await?;
    let after_reinstall = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{after_reinstall}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install")})).await?;
    assert_no_software_run(&f.router, after_reinstall).await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

async fn complete_effect(
    router: &Router,
    task: &Value,
    intent: &str,
    observation: &str,
) -> Result<()> {
    ensure!(event(router, task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    ensure!(event(router, task, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    ensure!(
        event(
            router,
            task,
            result_event(task, intent, Some(0), observation, false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    Ok(())
}

async fn assert_no_software_run(router: &Router, policy: Uuid) -> Result<()> {
    let response = agent(router, "/api/v1/agent/runtime/tasks/claim", Some(json!({"wireVersion":1,"executionContext":context(Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(
        response.0 == StatusCode::OK && response.1["task"].is_null(),
        "conflicting/satisfied effect was offered: {response:?}"
    );
    // Queue admission occurs in the request transaction, before asynchronous relay.
    // Checking the rows prevents a not-yet-relayed forbidden Run from looking like no work.
    let mut conn =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(policy).fetch_one(&mut conn).await?;
    ensure!(
        queued == 0,
        "policy {policy} admitted {queued} forbidden runs"
    );
    conn.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unresolved_installation_blocks_removal_and_other_versions() -> Result<()> {
    let mut f = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let stack = worker(&f.base, f.execution.clone()).await?;
    let original = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{original}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install")})).await?;
    let running = claim(&f.router).await?;
    ensure!(
        event(&f.router, &running, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&f.router, &running, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    let removal = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{removal}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"explicit_uninstall")})).await?;
    assert_no_software_run(&f.router, removal).await?;
    publish_next_software_version(&mut f).await?;
    let replacement = Uuid::new_v4();
    let mut next = authored(f.resource, f.scope, "required_install");
    next["action"]["resource"]["version"] = json!("v2");
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/policies/{replacement}"),
        0,
        json!({"action":"put","enabled":true,"definition":next}),
    )
    .await?;
    assert_no_software_run(&f.router, replacement).await?;
    ensure!(
        event(
            &f.router,
            &running,
            result_event(&running, "install", None, "unknown", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    assert_no_software_run(&f.router, removal).await?;
    assert_no_software_run(&f.router, replacement).await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

async fn publish_next_software_version(f: &mut Fixture) -> Result<()> {
    let path = format!("/api/v1/resources/{}", f.resource);
    let current = f.author.call(&f.router, Method::GET, &path, None).await?;
    ensure!(current.0 == StatusCode::OK);
    let mut variants = current.1["versions"][0]["variants"].clone();
    variants[0]["declaration"]["definition"]["version"] = json!("2");
    variants[0]["declaration"]["definition"]["behavior"]["detect"]["version"] = json!("2");
    let revision = current.1["revision"].as_u64().unwrap();
    write(
        &mut f.author,
        &f.router,
        &path,
        revision,
        json!({"action":"version","version":"v2","kind":"software","variants":variants}),
    )
    .await?;
    for (artifact, bytes) in [(None, &f.bytes), (Some("remover"), &f.removal)] {
        let mut uri = format!(
            "{path}/content?version=v2&variant=default&platform=macos&architecture=aarch64&operation={}",
            Uuid::new_v4()
        );
        if let Some(artifact) = artifact {
            uri.push_str(&format!("&artifact={artifact}"));
        }
        let upload = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", "mdm.example.test")
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1")
            .header("x-csrf-token", f.author.csrf.as_ref().unwrap())
            .header(
                "cookie",
                f.author
                    .cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
            .header("content-type", "application/octet-stream")
            .body(Body::from(bytes.clone()))?;
        let _guard = crate::test_support::software::content_setup_guard().await?;
        ensure!(f.router.clone().oneshot(upload).await?.status() == StatusCode::CREATED);
    }
    write(
        &mut f.author,
        &f.router,
        &path,
        revision + 1,
        json!({"action":"activate","version":"v2"}),
    )
    .await?;
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{}/versions/v2", f.resource),
        0,
        json!({"action":"enable"}),
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn known_failure_has_bounded_retries() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;

    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str| authored(resource, scope, intent);
    let failed_policy = Uuid::new_v4();
    let failed_path = format!("/api/v1/policies/{failed_policy}");
    write(
        &mut author,
        &router,
        &failed_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install")}),
    )
    .await?;
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
                "/api/v1/policies/{failed_policy}/runs/{}",
                failed_task["payload"]["task"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        failed_detail.1["effect"] == "failed",
        "known detector failure: {failed_detail:?}"
    );
    let mut previous_failure = failed_task["payload"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..2 {
        let mut owner =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut owner).await?;
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
        previous_failure = retry["payload"]["task"]["taskId"]
            .as_str()
            .unwrap()
            .to_owned();
    }
    pg(&format!("UPDATE mdm_commands.action_runs SET created_at=created_at-600 WHERE tenant_id='{}' AND id='{previous_failure}'", case_tenant()))?;
    let exhausted = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        exhausted.0 == StatusCode::OK && exhausted.1["task"].is_null(),
        "failed deployment exceeded bounded retries: {exhausted:?}"
    );
    ensure!(pg(&format!("SELECT jsonb_build_array(count(*),count(DISTINCT r.id),count(*) FILTER(WHERE r.result->>'effect'='failed')) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{failed_policy}'", case_tenant()))?.trim() == "[3, 3, 3]");
    write(
        &mut author,
        &router,
        &failed_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn reboot_waits_for_detection() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;

    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str| authored(resource, scope, intent);
    let reboot_policy = Uuid::new_v4();
    let reboot_path = format!("/api/v1/policies/{reboot_policy}");
    write(
        &mut author,
        &router,
        &reboot_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install")}),
    )
    .await?;
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
                "/api/v1/policies/{reboot_policy}/runs/{}",
                reboot_task["payload"]["task"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        reboot_detail.1["effect"] == "waiting_reboot",
        "pending reboot: {reboot_detail:?}"
    );
    let reboot_run = reboot_task["payload"]["task"]["taskId"].as_str().unwrap();
    pg(&format!("UPDATE mdm_commands.action_runs SET created_at=created_at-600 WHERE tenant_id='{}' AND id='{reboot_run}'", case_tenant()))?;
    let reboot_retry = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        reboot_retry.0 == StatusCode::OK && reboot_retry.1["task"].is_null(),
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
    let resolved = author.call(&router, Method::GET, &format!("/api/v1/policies/{reboot_policy}/runs/{reboot_run}"), None).await?;
    ensure!(resolved.0 == StatusCode::OK && resolved.1["effect"] == "verified");
    let rollout = ready_rollout(&mut author, &router, reboot_policy).await?;
    ensure!(rollout.1["stages"][0]["waitingReboot"] == 0 && rollout.1["stages"][0]["verifiedSuccess"] == 1);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{reboot_policy}'", case_tenant()))?.trim() == "1");
    write(
        &mut author,
        &router,
        &reboot_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unknown_effect_survives_credential_recovery() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;

    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str| authored(resource, scope, intent);
    let unknown_policy = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v1/policies/{unknown_policy}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install")}),
    )
    .await?;
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
    let opposing = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v1/policies/{opposing}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("explicit_uninstall")}),
    )
    .await?;
    assert_no_software_run(&router, opposing).await?;
    let registration: String = pg(&format!("SELECT id FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{}' AND channel='agent' AND state='active'",case_tenant(),case_device()))?.trim().into();
    let old_generation: u64 = pg(&format!("SELECT generation FROM mdm_access.registrations WHERE tenant_id='{}' AND id='{registration}'", case_tenant()))?.trim().parse()?;
    let old_credential = pg(&format!("SELECT id FROM mdm_access.credentials WHERE tenant_id='{}' AND registration='{registration}' AND state='active'", case_tenant()))?.trim().to_owned();
    let secret = credential("recovery-software");
    change_device_grants(&mut author,
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
            &format!("/api/v1/agent-registrations/{registration}/recovery"),
            Some(input.clone()),
        )
        .await?;
    ensure!(grant.0 == StatusCode::OK, "{grant:?}");
    let mut signing = input;
    signing["runtime"] = json!({"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v1","software.pkg.system.v1"],"executionContext":context(Platform::MacOs)});
    let mut authority = authority::Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources.finish(async {
    let service = crate::test_support::agent::service(&authority).await?;
    let next_credential = &credential("replacement");
    let next_registration =
        crate::test_support::agent::complete_grant(&service, &grant.1, &signing, next_credential)
            .await?;
    ensure!(next_registration["registrationId"] == registration);
    // Credential recovery preserves the registration/runtime identity and fences the predecessor credential.
    ensure!(next_registration["generation"].as_u64().unwrap() == old_generation);
    let current_credential = pg(&format!("SELECT id FROM mdm_access.credentials WHERE tenant_id='{}' AND registration='{registration}' AND state='active'", case_tenant()))?.trim().to_owned();
    ensure!(!current_credential.is_empty() && current_credential != old_credential);
    ensure!(pg(&format!("SELECT state FROM mdm_access.credentials WHERE tenant_id='{}' AND id='{old_credential}'", case_tenant()))?.trim() == "superseded");
    let old = agent(&router, "/api/v1/agent/runtime/tasks/claim", Some(json!({"wireVersion":1,"executionContext":context(Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(old.0 == StatusCode::UNAUTHORIZED || old.0 == StatusCode::FORBIDDEN, "old credential still authorized: {old:?}");
    let after_reenroll = agent_call(
        &router,
        Method::POST,
        "/api/v1/agent/runtime/tasks/claim",
        Some(next_credential),
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        after_reenroll.0 == StatusCode::OK && after_reenroll.1["task"].is_null(),
        "unknown side effect retried after registration replacement: {after_reenroll:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{unknown_policy}'",case_tenant()))?.trim() == "1");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{opposing}'",case_tenant()))?.trim() == "0", "opposing intent bypassed Unknown after credential generation changed");

    Ok(())
    }).await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unknown_result_replay_and_late_detection() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;

    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str| authored(resource, scope, intent);
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v1/policies/{policy}");
    let published = write(
        &mut author,
        &router,
        &policy_path,
        0,
        json!({"action":"put","enabled":true,"definition":authored("required_install")}),
    )
    .await?;
    ensure!(published["version"] == 1, "publish: {published}");
    let task = claim(&router).await?;
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    ensure!(event(&router, &task, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    let unknown_operation = Uuid::new_v4();
    let unknown_request = json!({"wireVersion":1,"executionContext":task["payload"]["task"]["executionContext"],"operationId":unknown_operation,"attemptId":task["payload"]["task"]["attemptId"],"event":result_event(&task,"install",Some(0),"unknown",false)?});
    let result = agent(
        &router,
        &format!(
            "/api/v1/agent/runtime/tasks/{}/events",
            task["payload"]["task"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request.clone()),
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "unknown result: {result:?}");
    let replay = agent(
        &router,
        &format!(
            "/api/v1/agent/runtime/tasks/{}/events",
            task["payload"]["task"]["taskId"].as_str().unwrap()
        ),
        Some(unknown_request),
    )
    .await?;
    ensure!(replay == result, "result replay: {replay:?}");
    let uncertainty = ready_rollout(&mut author, &router, policy).await?;
    ensure!(
        uncertainty.1["stages"][0]["reported"] == 1
            && uncertainty.1["stages"][0]["unknown"] == 1
            && uncertainty.1["stages"][0]["verifiedSuccess"] == 0,
        "unknown denominator: {uncertainty:?}"
    );
    let task_id = task["payload"]["task"]["taskId"].as_str().unwrap();
    pg(&format!("UPDATE mdm_commands.action_runs SET created_at=created_at-600 WHERE tenant_id='{}' AND id='{task_id}'", case_tenant()))?;
    let no_retry = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        no_retry.0 == StatusCode::OK && no_retry.1["task"].is_null(),
        "unknown effect was blindly retried: {no_retry:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{policy}'",case_tenant()))?.trim() == "1");
    let late = event(
        &router,
        &task,
        result_event(&task, "install", Some(0), "present", false)?,
    )
    .await?;
    ensure!(late.0 == StatusCode::OK, "late detection: {late:?}");
    let resolved = ready_rollout(&mut author, &router, policy).await?;
    ensure!(
        resolved.1["stages"][0]["unknown"] == 0 && resolved.1["stages"][0]["verifiedSuccess"] == 1,
        "late detection did not resolve unknown: {resolved:?}"
    );
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn withdrawn_software_does_not_poison_claims_for_other_policies_or_outside_scope()
-> Result<()> {
    let mut f = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let outside = prepared_scope(&f.planning, &[]).await?;
    let dependency = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/software/resources/{}/versions/v1", f.dependency),
            None,
        )
        .await?;
    ensure!(dependency.0 == StatusCode::OK);

    let mut ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
    ids.sort();
    for (policy, resource, scope) in [
        (ids[0], f.resource, f.scope),
        (ids[1], f.resource, outside),
        (ids[2], f.dependency, f.scope),
    ] {
        write(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":authored(resource,scope,"required_install")})).await?;
    }
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{}/versions/v1", f.resource),
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    let stack = worker(&f.base, f.execution.clone()).await?;
    let task = claim(&f.router).await?;
    ensure!(
        task["payload"]["task"]["steps"].as_array().is_some_and(
            |steps| steps.len() == 1 && steps[0]["action"]["package"] == "Private.Dependency"
        ),
        "withdrawal blocked unrelated valid policy: {task}"
    );
    ensure!(task["payload"]["task"]["authorization"]["policyId"] == ids[2].to_string());
    for policy in &ids[..2] {
        ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{policy}'",case_tenant()))?.trim() == "0");
    }
    let page = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/policies/{}/assignments", ids[0]),
            None,
        )
        .await?;
    ensure!(
        page.0 == StatusCode::OK
            && page.1["items"][0]["taskAdmission"]["state"] == "authorization_withdrawn",
        "withdrawal diagnosis: {page:?}"
    );
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
