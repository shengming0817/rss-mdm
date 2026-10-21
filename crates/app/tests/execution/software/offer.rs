mod formats;
use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::{process::*, runtime::*, *};
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn required_available_and_uninstall_delivery() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs)
        .await
        .map_err(|e| anyhow::anyhow!("authorized fixture: {e:#}"))?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.content.clone())
        .await
        .map_err(|e| anyhow::anyhow!("software worker: {e:#}"))?;
    let router = fixture.router;
    let mut author = fixture.author;
    let bytes = fixture.bytes;

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
    ensure!(
        task["payload"]["task"]["steps"][0]["action"]["package"] == "Private.Dependency"
            && task["payload"]["task"]["steps"][1]["action"]["package"] == "Private.Controlled"
            && task["payload"]["task"]["softwareResource"].is_null()
            && task["payload"]["task"]["admissionOperation"].is_null()
            && task["payload"]["task"]["startMode"] == "automatic",
        "offer: {task}"
    );
    ensure!(task["payload"]["task"]["steps"][1]["artifacts"][0]["length"] == bytes.len());
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    let start = event(&router, &task, json!({"kind":"start"})).await?;
    ensure!(
        start.0 == StatusCode::OK && start.1["permit"]["payload"]["task"]["permit"] == "start",
        "start: {start:?}"
    );
    let result = event(
        &router,
        &task,
        result_event(&task, "install", Some(0), "present", false)?,
    )
    .await?;
    ensure!(result.0 == StatusCode::OK, "result: {result:?}");
    let status = ready_rollout(&mut author, &router, policy).await?;
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
            &format!("/api/v1/policies/{policy}/runs"),
            None,
        )
        .await?;
    ensure!(
        runs.0 == StatusCode::OK && runs.1["items"].as_array().unwrap().iter().any(|r| r["taskId"] == task["payload"]["task"]["taskId"] && r["effect"] == "verified"),
        "run list effect: {runs:?}"
    );
    let detail = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v1/policies/{policy}/runs/{}",
                task["payload"]["task"]["taskId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        detail.0 == StatusCode::OK && detail.1["taskId"] == task["payload"]["task"]["taskId"] && detail.1["effect"] == "verified",
        "run detail effect: {detail:?}"
    );
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_commands.action_runs SET created_at=created_at-120 WHERE id=$1::uuid")
        .bind(task["payload"]["task"]["taskId"].as_str().unwrap())
        .execute(&mut owner)
        .await?;
    owner.close().await?;
    let repeated = agent(
        &router,
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        repeated.0 == StatusCode::OK && repeated.1["task"].is_null(),
        "verified software was scheduled again: {repeated:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.policy='{policy}'",case_tenant()))?.trim() == "1");
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
        &format!("/api/v1/policies/{available}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("available_install")}),
    )
    .await?;
    let poll = agent(&router,"/api/v1/agent/runtime/tasks/claim",Some(json!({"wireVersion":1,"executionContext":context(Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(
        poll.0 == StatusCode::OK && poll.1["task"].is_null(),
        "AvailableInstall must never queue before an explicit request"
    );
    let awaiting = ready_rollout(&mut author, &router, available).await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{available}')",case_tenant()))?.trim()=="0", "statistics created an Available execution");
    ensure!(
        awaiting.1["stages"][0]["totalTargets"] == 1
            && awaiting.1["stages"][0]["reported"] == 0
            && awaiting.1["stages"][0]["waitingUser"] == 0
    );
    write(
        &mut author,
        &router,
        &format!("/api/v1/policies/{available}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let uninstall = Uuid::new_v4();
    write(
        &mut author,
        &router,
        &format!("/api/v1/policies/{uninstall}"),
        0,
        json!({"action":"put","enabled":true,"definition":authored("explicit_uninstall")}),
    )
    .await?;
    let removal_task = claim(&router).await?;
    ensure!(
        removal_task["payload"]["task"]["intent"] == "uninstall"
            && removal_task["payload"]["task"]["startMode"] == "automatic",
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
    let removed = ready_rollout(&mut author, &router, uninstall).await?;
    ensure!(
        removed.1["stages"][0]["verifiedSuccess"] == 1,
        "uninstall detection: {removed:?}"
    );
    write(
        &mut author,
        &router,
        &format!("/api/v1/policies/{uninstall}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn windows_variant_delivery_and_detection() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::Windows).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.content.clone())
        .await
        .map_err(|e| anyhow::anyhow!("software worker: {e:#}"))?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let windows_scope = fixture.scope;
    let windows_credential = fixture.credential;

    let windows_policy = Uuid::new_v4();
    write(&mut author,&router,&format!("/api/v1/policies/{windows_policy}"),0,json!({"action":"put","enabled":true,
        "definition":{"scope":windows_scope,
        "action": {"resource": {"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"kind":"software","intent":"required_install","delivery":{"kind":"direct"},"runLifetimeSeconds":600,
        "rollout":{"stages":[{"scope":windows_scope,"opensAt":0}]}}}})).await?;
    let windows_page = author
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/policies/{windows_policy}/assignments"),
            None,
        )
        .await?;
    ensure!(
        windows_page.1["items"][0]["taskAdmission"]["state"] == "eligible",
        "windows admission: {windows_page:?}"
    );
    let windows_task = claim_with(&router, &windows_credential, Platform::Windows).await?;
    ensure!(
        windows_task["payload"]["task"]["platform"] == "windows"
            && windows_task["payload"]["task"]["architecture"] == "x86_64"
            && windows_task["payload"]["task"]["steps"][0]["action"]["package"]
                == "Private.WindowsDependency"
            && windows_task["payload"]["task"]["steps"][1]["action"]["behavior"]["kind"] == "msi",
        "windows variant: {windows_task}"
    );
    let windows_content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            windows_task["payload"]["task"]["taskId"].as_str().unwrap(),
            windows_task["payload"]["task"]["attemptId"]
                .as_str()
                .unwrap()
        ))
        .header("host", "mdm.example.test:9445")
        .extension(
            crate::test_support::agent::evidence(&windows_credential).expect("registered TLS peer"),
        )
        .body(Body::empty())?;
    let windows_content = router.clone().oneshot(windows_content).await?;
    ensure!(windows_content.status() == StatusCode::OK);
    ensure!(windows_content.into_body().collect().await?.to_bytes() == fixture.windows_bytes);
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
    let windows_rollout = ready_rollout(&mut author, &router, windows_policy).await?;
    ensure!(
        windows_rollout.1["stages"][0]["verifiedSuccess"] == 1,
        "windows verification: {windows_rollout:?}"
    );
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.offer"]
async fn explicit_mdm_requires_capability_and_does_not_rewrite_agent_policy() -> Result<()> {
    let mut f = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let capability=f.author.call(&f.router,Method::GET,"/api/v1/policies/capabilities",None).await?;
        ensure!(capability.0==StatusCode::OK && capability.1==json!({"defaultSoftwareChannel":"agent","mdmSoftwareDistributionEnabled":false}),"capabilities {capability:?}");
        let id=Uuid::new_v4();let path=format!("/api/v1/policies/{id}");
        let original=authored(f.resource,f.scope,"required_install");
        let saved=write(&mut f.author,&f.router,&path,0,json!({"action":"put","enabled":false,"definition":original})).await?;
        ensure!(saved["definition"]["action"]["channel"]=="agent","normalized {saved}");
        let mut mdm=original.clone();mdm["action"]["channel"]=json!("mdm");
        let denied=f.author.call(&f.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":true,"definition":mdm}}))).await?;
        ensure!(denied.0==StatusCode::CONFLICT && denied.1["code"]=="mdm_software_disabled","disabled MDM {denied:?}");
        let unchanged=f.author.call(&f.router,Method::GET,&path,None).await?;
        ensure!(unchanged.0==StatusCode::OK && unchanged.1["definition"]["action"]["channel"]=="agent" && unchanged.1["revision"]==1,"unchanged {unchanged:?}");
        Ok(())
    }).await
}
