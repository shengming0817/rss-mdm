use crate::test_support::software::write;
use crate::test_support::software_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.content"]
async fn expiry_dependency_paths_and_withdrawal_fence() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let stack = worker(&fixture.base, fixture.execution.clone()).await?;
    let router = fixture.router;
    let mut author = fixture.author;
    let resource = fixture.resource;
    let dependency_bytes = fixture.dependency_bytes;
    let bytes = fixture.bytes;

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
    let mut owner =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,task,expiresAt}','0'::jsonb) WHERE id=$1::uuid")
        .bind(task["payload"]["task"]["attemptId"].as_str().unwrap()).execute(&mut owner).await?;
    let expires:i64=sqlx::query_scalar("SELECT (offer#>>'{payload,task,expiresAt}')::bigint FROM mdm_commands.action_attempts WHERE id=$1::uuid").bind(task["payload"]["task"]["attemptId"].as_str().unwrap()).fetch_one(&mut owner).await?;
    ensure!(expires == 0);
    let expired = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["task"]["taskId"].as_str().unwrap(),
            task["payload"]["task"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test:9445")
        .extension(
            crate::test_support::agent::evidence(case_credential()).expect("registered TLS peer"),
        )
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(expired).await?.status() == StatusCode::OK);
    sqlx::query("UPDATE mdm_commands.action_attempts SET offer=jsonb_set(offer,'{payload,task,expiresAt}',to_jsonb($2::bigint)) WHERE id=$1::uuid")
        .bind(task["payload"]["task"]["attemptId"].as_str().unwrap())
        .bind(task["payload"]["task"]["expiresAt"].as_i64().unwrap()).execute(&mut owner).await?;
    owner.close().await?;
    let content = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["task"]["taskId"].as_str().unwrap(),
            task["payload"]["task"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test:9445")
        .extension(
            crate::test_support::agent::evidence(case_credential()).expect("registered TLS peer"),
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
            "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=0%2Fscripts%2Finstall.sh",
            task["payload"]["task"]["taskId"].as_str().unwrap(),
            task["payload"]["task"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test:9445")
        .extension(
            crate::test_support::agent::evidence(case_credential()).expect("registered TLS peer"),
        )
        .body(Body::empty())?;
    let prerequisite = router.clone().oneshot(prerequisite).await?;
    ensure!(prerequisite.status() == StatusCode::OK);
    ensure!(prerequisite.into_body().collect().await?.to_bytes() == dependency_bytes);
    ensure!(event(&router, &task, json!({"kind":"received"})).await?.0 == StatusCode::OK);
    write(
        &mut author,
        &router,
        &format!("/api/v1/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    let denied = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=1%2Fpackage",
            task["payload"]["task"]["taskId"].as_str().unwrap(),
            task["payload"]["task"]["attemptId"].as_str().unwrap()
        ))
        .header("host", "mdm.example.test:9445")
        .extension(
            crate::test_support::agent::evidence(case_credential()).expect("registered TLS peer"),
        )
        .body(Body::empty())?;
    ensure!(router.clone().oneshot(denied).await?.status() == StatusCode::FORBIDDEN);
    ensure!(event(&router, &task, json!({"kind":"start"})).await?.0 == StatusCode::FORBIDDEN);
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.software.content"]
async fn uninstall_content_selection() -> Result<()> {
    let mut fixture = Fixture::authorized(Platform::MacOs).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let stack = worker(&fixture.base, fixture.execution.clone()).await?;
            let router = fixture.router;
            let mut author = fixture.author;
            let removal = fixture.removal;

            let resource = fixture.resource;
            let scope = fixture.scope;
            let authored = |intent: &str| authored(resource, scope, intent);
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
                removal_task["payload"]["task"]["intent"] == "uninstall",
                "uninstall: {removal_task}"
            );
            let content = Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/agent/runtime/tasks/{}/content?attempt={}&artifact=0%2Fremove",
                    removal_task["payload"]["task"]["taskId"].as_str().unwrap(),
                    removal_task["payload"]["task"]["attemptId"]
                        .as_str()
                        .unwrap()
                ))
                .header("host", "mdm.example.test:9445")
                .extension(
                    crate::test_support::agent::evidence(case_credential())
                        .expect("registered TLS peer"),
                )
                .body(Body::empty())?;
            let content = router.clone().oneshot(content).await?;
            ensure!(
                content.status() == StatusCode::OK,
                "remove content: {}",
                content.status()
            );
            ensure!(content.into_body().collect().await?.to_bytes() == removal);
            crate::test_support::runtime::stop_worker(stack).await?;
            Ok(())
        })
        .await
}
