use super::*;
pub(super) async fn verify(
    author: &mut Browser,
    reviewer: &mut Browser,
    router: &Router,
    resource: Uuid,
    execution: &crate::execution::ExecutionService,
) -> Result<()> {
    let mut failures = Vec::new();
    let missing = author
        .call(
            router,
            Method::GET,
            &format!(
                "/api/v3/script-plans/{}/runs/{}",
                Uuid::new_v4(),
                Uuid::new_v4()
            ),
            None,
        )
        .await?;
    if missing.0 != StatusCode::NOT_FOUND || missing.1["code"] != "task_not_found" {
        failures.push(format!("missing task: {missing:?}"));
    }
    let missing_agent = agent_call(
        router,
        Method::GET,
        &format!(
            "/api/agent/v2/tasks/{}/content?attempt={}",
            Uuid::new_v4(),
            Uuid::new_v4()
        ),
        Some(CREDENTIAL),
        None,
    )
    .await?;
    if missing_agent.0 != StatusCode::NOT_FOUND || missing_agent.1["code"] != "task_not_found" {
        failures.push(format!("agent missing task: {missing_agent:?}"));
    }
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let id = Uuid::new_v4();
    let request = json!({"operationId":id,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"manual"},"notBefore":now-1,"until":now+5,"jitterSeconds":0,"window":null},"runLifetimeSeconds":60});
    let created = post(author, router, "/api/v3/script-plans", request.clone()).await?;
    let approval = json!({"operationId":Uuid::new_v4()});
    let path = format!("/api/v3/script-plans/{id}/approve");
    let approved = post(reviewer, router, &path, approval.clone()).await?;
    let run = pg(&format!(
        "SELECT id::text FROM mdm_commands.action_runs WHERE plan='{id}'"
    ))?
    .trim()
    .to_owned();
    let mismatch = author
        .call(
            router,
            Method::GET,
            &format!("/api/v3/script-plans/{}/runs/{run}", Uuid::new_v4()),
            None,
        )
        .await?;
    if mismatch.0 != StatusCode::NOT_FOUND || mismatch.1["code"] != "task_not_found" {
        failures.push(format!("wrong task owner: {mismatch:?}"));
    }
    post(
        author,
        router,
        &format!("/api/v3/script-plans/{id}/cancel"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    let replay = reviewer
        .call(router, Method::POST, &path, Some(approval.clone()))
        .await?;
    if replay.0 != StatusCode::OK || replay.1 != approved {
        failures.push(format!("cancelled approval replay: {replay:?}"));
    }
    tokio::time::sleep(Duration::from_secs(6)).await;
    let replay = author
        .call(
            router,
            Method::POST,
            "/api/v3/script-plans",
            Some(request.clone()),
        )
        .await?;
    if replay.0 != StatusCode::ACCEPTED || replay.1 != created {
        failures.push(format!("expired create replay: {replay:?}"));
    }
    let replay = reviewer
        .call(router, Method::POST, &path, Some(approval))
        .await?;
    if replay.0 != StatusCode::OK || replay.1 != approved {
        failures.push(format!("expired approval replay: {replay:?}"));
    }
    let mut expired = request;
    expired["operationId"] = json!(Uuid::new_v4());
    let rejected = author
        .call(router, Method::POST, "/api/v3/script-plans", Some(expired))
        .await?;
    ensure!(
        rejected.0 == StatusCode::BAD_REQUEST,
        "fresh expired plan admitted: {rejected:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE plan='{id}'"
        ))?
        .trim()
            == "1",
        "replay dispatched a duplicate run"
    );
    execution.recover_action_fixture(id).await?;
    ensure!(
        failures.is_empty(),
        "recovery contracts: {}",
        failures.join("; ")
    );
    Ok(())
}
