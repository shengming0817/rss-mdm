use super::*;
use anyhow::Context;
use std::collections::BTreeSet;

pub(super) async fn verify(router: &Router, pending: Value) -> Result<Value> {
    let id = pending["payload"]["taskId"].as_str().unwrap();
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,plan,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),plan,device,registration,generation,'starvation-fixture:'||n,created_at,0,1,jsonb_set(jsonb_set(state,'{{execution}}','\"unknown\"'),'{{cancellation}}','\"requested\"'),true,dispatch_fingerprint FROM mdm_commands.action_runs CROSS JOIN generate_series(1,129) n WHERE id='{id}'; UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{delivery,leaseUntil}}','0') WHERE id='{id}'"
    ))?;
    let before = pg("SELECT count(*) FROM mdm_commands.action_receipts")?
        .trim()
        .parse::<i64>()?;
    let mut seen = BTreeSet::new();
    let mut offered = None;
    for _ in 0..4 {
        let response = agent_call(
            router,
            Method::POST,
            "/api/agent/v2/tasks/claim",
            Some(CREDENTIAL),
            Some(json!({"wireVersion":2,"operationId":Uuid::new_v4()})),
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
        pg("SELECT count(*) FROM mdm_commands.action_receipts")?
            .trim()
            .parse::<i64>()?
            == before + 1,
        "empty claim grew permanent receipts"
    );
    ensure!(pg("SELECT count(*) FROM mdm_commands.action_polls")?.trim() == "1");
    pg("DELETE FROM mdm_commands.action_runs WHERE occurrence LIKE 'starvation-fixture:%'")?;
    Ok(offered)
}
