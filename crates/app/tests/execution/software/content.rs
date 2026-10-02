use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.content"]
async fn expiry_dependency_paths_and_withdrawal_fence() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let dependency_bytes = fixture.dependency_bytes;
    let bytes = fixture.bytes;
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
    let task = claim(&router).await?;
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,expiresAt}','0'::jsonb) WHERE id=$1::uuid")
        .bind(task["payload"]["attemptId"].as_str().unwrap()).execute(&mut owner).await?;
    let expired = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header(
            "authorization",
            format!("Bearer {CREDENTIAL}", CREDENTIAL = case_credential()),
        )
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(expired).await?.status() == StatusCode::FORBIDDEN);
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,expiresAt}',to_jsonb($2::bigint)) WHERE id=$1::uuid")
        .bind(task["payload"]["attemptId"].as_str().unwrap())
        .bind(task["payload"]["expiresAt"].as_i64().unwrap()).execute(&mut owner).await?;
    owner.close().await?;
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header(
            "authorization",
            format!("Bearer {CREDENTIAL}", CREDENTIAL = case_credential()),
        )
        .body(Body::empty())?;
    let content = router.clone().oneshot(content).await?;
    ensure!(
        content.status() == StatusCode::OK,
        "content: {}",
        content.status()
    );
    ensure!(content.into_body().collect().await?.to_bytes() == bytes);
    let prerequisite = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=0%2Fscripts%2Finstall.sh",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header(
            "authorization",
            format!("Bearer {CREDENTIAL}", CREDENTIAL = case_credential()),
        )
        .body(Body::empty())?;
    let prerequisite = router.clone().oneshot(prerequisite).await?;
    ensure!(prerequisite.status() == StatusCode::OK);
    ensure!(prerequisite.into_body().collect().await?.to_bytes() == dependency_bytes);
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    write(
        &mut author,
        &router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw","evidence":["deployment-revocation"]}),
    )
    .await?;
    let denied = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["taskId"].as_str().unwrap(),
            task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header(
            "authorization",
            format!("Bearer {CREDENTIAL}", CREDENTIAL = case_credential()),
        )
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(denied).await?.status() == StatusCode::FORBIDDEN);
    ensure!(event(&router, &task, json!({"kind":"start"})).await?.0 == StatusCode::FORBIDDEN);
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.content"]
async fn uninstall_content_permission() -> Result<()> {
    let fixture = Fixture::approved(Platform::MacOs).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let removal = fixture.removal;
    let first_operation = fixture.first_operation;
    let resource = fixture.resource;
    let scope = fixture.scope;
    let authored = |intent: &str, operation: &Value| authored(resource, scope, intent, operation);
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
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=0%2Fremove",
            removal_task["payload"]["taskId"].as_str().unwrap(),
            removal_task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header(
            "authorization",
            format!("Bearer {CREDENTIAL}", CREDENTIAL = case_credential()),
        )
        .body(Body::empty())?;
    let content = router.clone().oneshot(content).await?;
    ensure!(
        content.status() == StatusCode::OK,
        "remove content: {}",
        content.status()
    );
    ensure!(content.into_body().collect().await?.to_bytes() == removal);
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.content"]
async fn windows_variant_content() -> Result<()> {
    let fixture = Fixture::approved(Platform::Windows).await?;
    let stack = worker(&fixture.base, fixture.content.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let windows_scope = fixture.scope;
    let windows_bytes = fixture.windows_bytes;
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
    let windows_content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/agent/v5/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            windows_task["payload"]["taskId"].as_str().unwrap(),
            windows_task["payload"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test")
        .header("authorization", format!("Bearer {windows_credential}"))
        .body(Body::empty())?;
    let windows_content = router.clone().oneshot(windows_content).await?;
    ensure!(windows_content.status() == StatusCode::OK);
    ensure!(windows_content.into_body().collect().await?.to_bytes() == windows_bytes);
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
