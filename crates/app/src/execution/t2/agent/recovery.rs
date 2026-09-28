use crate::test_support::agent_execution::*;
use crate::test_support::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.recovery"]
async fn started_execution_becomes_unknown_and_disabled_policy_cancels() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = fixture.router;
    let execution = fixture.execution;
    let mut author = fixture.author;
    let author_id = fixture.author_id;
    let grants = fixture.grants;
    let unknown_policy = publish(&mut author, &router, id).await?;
    let pending = claim(&router).await?;
    // Organization assignment survives its author's departure.
    crate::test_support::identity::set_grants(TENANT, &author_id, vec![]).await?;
    task_event(&router, &pending, json!({"kind":"received"})).await?;
    task_event(&router, &pending, json!({"kind":"start"})).await?;
    let task_id = pending["payload"]["taskId"].as_str().unwrap();
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{startedAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-61)) WHERE id='{task_id}'"
    ))?;
    for _ in 0..2 {
        execution.recover_action_fixture(unknown_policy).await?;
    }
    ensure!(
        pg(&format!(
            "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == "unknown"
    );
    let before = pg("SELECT count(*) FROM mdm_commands.action_runs")?;
    ensure!(claim_request(&router, Uuid::new_v4()).await?.1["task"].is_null());
    ensure!(
        pg("SELECT count(*) FROM mdm_commands.action_runs")? == before,
        "unknown execution repeated"
    );
    crate::test_support::identity::set_grants(TENANT, &author_id, grants.clone()).await?;
    post(
        &mut author,
        &router,
        &format!("/api/v2/policies/{unknown_policy}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
    execution.recover_action_fixture(unknown_policy).await?;
    ensure!(
        pg(&format!(
            "SELECT state->>'cancellation' FROM mdm_commands.action_runs WHERE id='{task_id}'"
        ))?
        .trim()
            == "requested"
    );
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
