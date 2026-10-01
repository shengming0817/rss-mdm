use crate::test_support::agent_execution::*;
use crate::test_support::*;
use anyhow::Context;
use std::collections::BTreeSet;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.poll"]
async fn cancellation_backlog_does_not_starve_live_offer() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let _policy = publish(author, router, resource).await?;
    let pending = claim(router).await?;
    let id = pending["payload"]["taskId"].as_str().unwrap();
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'starvation-fixture:'||n,created_at,0,1,jsonb_set(jsonb_set(state,'{{execution}}','\"unknown\"'),'{{cancellation}}','\"requested\"'),true,dispatch_fingerprint FROM mdm_commands.action_runs CROSS JOIN generate_series(1,129) n WHERE id='{id}'; UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{delivery,leaseUntil}}','0') WHERE id='{id}'"
    ))?;
    let before = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_receipts WHERE tenant_id='{}'",
        case_tenant()
    ))?
    .trim()
    .parse::<i64>()?;
    let mut seen = BTreeSet::new();
    let mut offered = None;
    for _ in 0..4 {
        let response = agent_call(
            router,
            Method::POST,
            "/api/agent/v5/tasks/claim",
            Some(case_credential()),
            Some(json!({"wireVersion":5,"operationId":Uuid::new_v4(),"profiles":["posix_sh","bash","power_shell7","osquery"]})),
        )
        .await?;
        ensure!(response.0 == StatusCode::OK, "poll paging: {response:?}");
        for item in response.1["cancellations"].as_array().unwrap() {
            seen.insert(item["taskId"].as_str().unwrap().to_owned());
        }
        if !response.1["task"].is_null() {
            ensure!(offered.is_none());
            offered = Some(response.1["task"].clone());
        }
    }
    let offered = offered.context("cancel backlog starved the live task")?;
    ensure!(offered["payload"]["taskId"] == pending["payload"]["taskId"]);
    ensure!(
        seen.len() == 129,
        "cancellation cursor did not traverse backlog: {}",
        seen.len()
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_receipts WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
        .parse::<i64>()?
            == before + 1,
        "empty claim grew permanent receipts"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_polls WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "1"
    );
    pg(&format!(
        "DELETE FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}' AND occurrence LIKE 'starvation-fixture:%'",
        case_tenant(),
        case_device_id()
    ))?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
