use crate::test_support::software::write;
use crate::test_support::software_execution::case_device;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn successful_removal_invalidates_prior_installation_across_policies() -> Result<()> {
    let mut f = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&f.base, f.content.clone()).await?;
    let install = Uuid::new_v4();
    let duplicate = Uuid::new_v4();
    let removal = Uuid::new_v4();
    let install_path = format!("/api/v1/policies/{install}");
    let duplicate_path = format!("/api/v1/policies/{duplicate}");
    let removal_path = format!("/api/v1/policies/{removal}");
    write(&mut f.author, &f.router, &install_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install",&f.first_operation)})).await?;
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
    write(&mut f.author, &f.router, &duplicate_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install",&f.first_operation)})).await?;
    assert_no_software_run(&f.router, duplicate).await?;
    write(
        &mut f.author,
        &f.router,
        &duplicate_path,
        1,
        json!({"action":"disable"}),
    )
    .await?;
    write(&mut f.author, &f.router, &removal_path, 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"explicit_uninstall",&f.first_operation)})).await?;
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
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{after_reinstall}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install",&f.first_operation)})).await?;
    assert_no_software_run(&f.router, after_reinstall).await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
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
    let mut f = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&f.base, f.content.clone()).await?;
    let original = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{original}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install",&f.first_operation)})).await?;
    let running = claim(&f.router).await?;
    ensure!(
        event(&f.router, &running, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(event(&f.router, &running, json!({"kind":"start"})).await?.0 == StatusCode::OK);
    let removal = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{removal}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"explicit_uninstall",&f.first_operation)})).await?;
    assert_no_software_run(&f.router, removal).await?;
    let next_approval = publish_next_software_version(&mut f).await?;
    let replacement = Uuid::new_v4();
    let mut next = authored(f.resource, f.scope, "required_install", &next_approval);
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
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

async fn publish_next_software_version(f: &mut Fixture) -> Result<Value> {
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
    let approved = write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{}/versions/v2", f.resource),
        0,
        json!({"action":"approve","evidence":["new-version"]}),
    )
    .await?;
    Ok(approved["admission"]["operation"].clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.recovery"]
async fn unsent_predecessor_software_blocks_conflicts_until_current_offer_binds_effect()
-> Result<()> {
    let mut f = Fixture::approved(Platform::MacOs).await?;
    let queued_policy = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{queued_policy}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"required_install",&f.first_operation)})).await?;
    // Without relay, the authenticated check-in creates a real unsent queued Run.
    let accepted = agent(&f.router, "/api/v1/agent/runtime/tasks/claim", Some(json!({"wireVersion":1,"executionContext":context(Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(accepted.0 == StatusCode::OK && accepted.1["task"].is_null());
    let mut conn =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let (run, occurrence, attempts): (Uuid, String, i64) = sqlx::query_as("SELECT r.id,r.occurrence,(SELECT count(*) FROM mdm_commands.action_attempts a WHERE (a.tenant_id,a.run)=(r.tenant_id,r.id)) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.state->'delivery'->>'kind'='queued'")
        .bind(case_tenant()).bind(queued_policy).fetch_one(&mut conn).await?;
    ensure!(attempts == 0);
    // The explicitly accepted predecessor transition leaves unoffered software
    // runs without an effect key because their concrete target was never signed.
    sqlx::query("UPDATE mdm_commands.action_runs SET software_effect=NULL WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).execute(&mut conn).await?;
    let conflicting = Uuid::new_v4();
    write(&mut f.author, &f.router, &format!("/api/v1/policies/{conflicting}"), 0, json!({"action":"put","enabled":true,"definition":authored(f.resource,f.scope,"explicit_uninstall",&f.first_operation)})).await?;
    // The shared relay may already have accepted the original Run. A probe must
    // permit that legal Offer while still proving the conflicting policy queues nothing.
    let probe = agent(&f.router, "/api/v1/agent/runtime/tasks/claim", Some(json!({"wireVersion":1,"executionContext":context(Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(probe.0 == StatusCode::OK);
    let conflicting_runs: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2")
        .bind(case_tenant()).bind(conflicting).fetch_one(&mut conn).await?;
    ensure!(
        conflicting_runs == 0,
        "a predecessor queued effect must exclude the conflicting policy"
    );
    let stack = worker(&f.base, f.content.clone()).await?;
    let offered = if probe.1["task"].is_null() {
        claim(&f.router).await?
    } else {
        probe.1["task"].clone()
    };
    ensure!(offered["payload"]["task"]["taskId"] == run.to_string());
    let (current_occurrence, effect): (String, Value) = sqlx::query_as("SELECT occurrence,software_effect FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(run).fetch_one(&mut conn).await?;
    ensure!(
        current_occurrence == occurrence
            && effect["resource"] == f.resource.to_string()
            && effect["target"] == json!({"kind":"device"}),
        "first current Offer must bind the original queued Run's effect: {effect}"
    );
    complete_effect(&f.router, &offered, "install", "present").await?;
    conn.close().await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
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
    let failed_path = format!("/api/v1/policies/{failed_policy}");
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
    let exhausted = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
    let reboot_path = format!("/api/v1/policies/{reboot_policy}");
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
    let reboot_retry = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
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
    write(&mut author,&router,&format!("/api/v1/policies/{unknown_policy}"),0,json!({"action":"put","enabled":true,"definition":authored("required_install",&first_operation)})).await?;
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
    write(&mut author, &router, &format!("/api/v1/policies/{opposing}"), 0, json!({"action":"put","enabled":true,"definition":authored("explicit_uninstall",&first_operation)})).await?;
    assert_no_software_run(&router, opposing).await?;
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
            &format!("/api/v1/agent-registrations/{registration}/recovery"),
            Some(input.clone()),
        )
        .await?;
    ensure!(grant.0 == StatusCode::OK, "{grant:?}");
    let mut signing = input;
    signing["runtime"] = json!({"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v1","software.pkg.system.v1"],"executionContext":context(Platform::MacOs)});
    let service = crate::test_support::agent::service(&authority::Authority::open().await?).await?;
    let next_credential = &credential("replacement");
    let next_registration =
        crate::test_support::agent::complete_grant(&service, &grant.1, &signing, next_credential)
            .await?;
    ensure!(next_registration["registrationId"] == registration);
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
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{opposing}'",case_tenant()))?.trim() == "0", "opposing intent bypassed Unknown after credential generation changed");
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
    let policy_path = format!("/api/v1/policies/{policy}");
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
            &format!("/api/v1/software/resources/{}/versions/v1", f.dependency),
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
        write(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),0,json!({"action":"put","enabled":true,"definition":authored(resource,scope,"required_install",operation)})).await?;
    }
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{}/versions/v1", f.resource),
        1,
        json!({"action":"withdraw","evidence":["withdraw only the root"]}),
    )
    .await?;
    let stack = worker(&f.base, f.content.clone()).await?;
    let task = claim(&f.router).await?;
    ensure!(
        task["payload"]["task"]["steps"].as_array().is_some_and(
            |steps| steps.len() == 1 && steps[0]["action"]["package"] == "Private.Dependency"
        ),
        "withdrawal blocked unrelated valid policy: {task}"
    );
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
            && page.1["items"][0]["taskAdmission"]["state"] == "approval_withdrawn",
        "withdrawal diagnosis: {page:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
