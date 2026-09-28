use crate::test_support::agent_execution::*;
use crate::test_support::*;
use anyhow::Context;
use std::collections::BTreeSet;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn policy_run_history_cursor_summary_and_detail() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(TASK_SCOPE, json!([{"kind":"device","id":DEVICE_ID}]))
        .await?;
    let mut grants = fixture.grants.clone();
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["operation_read"],
    )?);
    crate::test_support::identity::set_grants(TENANT, &fixture.author_id, grants).await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let plan = publish(author, router, resource).await?;
    let completed = claim(router).await?;
    complete(router, &completed).await?;
    let task = pg(&format!(
        "SELECT id FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{plan}') AND occurrence NOT LIKE 'history-fixture:%' ORDER BY created_at,id LIMIT 1"
    ))?
    .trim()
    .to_owned();
    Uuid::parse_str(&task)?;
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'history-fixture:'||n,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result FROM mdm_commands.action_runs CROSS JOIN generate_series(1,25) n WHERE id='{task}'"
    ))?;

    let result: Result<()> = async {
        let available_at = pg(&format!(
            "SELECT available_at FROM mdm_commands.action_runs WHERE id='{task}'"
        ))?
        .trim()
        .parse::<i64>()?;
        let mut path = format!("/api/v2/policies/{plan}/runs");
        let mut ids = Vec::new();
        let mut unique = BTreeSet::new();
        loop {
            let (status, page) = author.call(router, Method::GET, &path, None).await?;
            ensure!(status == StatusCode::OK, "run history page: {status} {page}");
            let items = page["items"].as_array().context("run history items")?;
            ensure!(items.len() <= 20, "unbounded run history page: {page}");
            for item in items {
                ensure!(
                    item["availableAt"].as_i64() == Some(available_at),
                    "history fixture changed the shared ordering coordinate: {item}"
                );
                ensure!(
                    item["result"].get("output").is_none(),
                    "run summary exposed output: {item}"
                );
                ensure!(
                    item["result"]["diagnostics"].get("stdout").is_none()
                        && item["result"]["diagnostics"].get("stderr").is_none(),
                    "run summary exposed diagnostic streams: {item}"
                );
                let id = item["taskId"].as_str().context("history taskId")?.to_owned();
                ensure!(unique.insert(id.clone()), "duplicate run history item: {id}");
                ids.push(id);
            }
            let Some(cursor) = page["nextCursor"].as_object() else {
                ensure!(page["nextCursor"].is_null(), "invalid run cursor: {page}");
                break;
            };
            let after_at = cursor["availableAt"].as_i64().context("cursor availableAt")?;
            let after_id = cursor["taskId"].as_str().context("cursor taskId")?;
            path = format!(
                "/api/v2/policies/{plan}/runs?afterAt={after_at}&afterId={after_id}"
            );
        }
        ensure!(ids.len() == 26, "run history lost records: {ids:?}");
        ensure!(
            ids.windows(2).all(|pair| pair[0] > pair[1]),
            "equal-time run history was not ordered by descending task id: {ids:?}"
        );

        let (status, detail) = author
            .call(
                router,
                Method::GET,
                &format!("/api/v2/policies/{plan}/runs/{task}"),
                None,
            )
            .await?;
        ensure!(status == StatusCode::OK, "run detail: {status} {detail}");
        ensure!(detail["result"]["output"]["version"] == "1.2", "run detail: {detail}");
        ensure!(
            detail["result"]["diagnostics"]["stdout"] == "captured stdout"
                && detail["result"]["diagnostics"]["stderr"] == "captured stderr",
            "run detail lost diagnostic streams: {detail}"
        );
        ensure!(
            author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v2/policies/{}/runs/{task}", Uuid::new_v4()),
                    None,
                )
                .await?
                .0
                == StatusCode::NOT_FOUND
        );
        ensure!(
            author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v2/policies/{plan}/runs?afterAt={available_at}"),
                    None,
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );

        let records=audit_records()?;
        let version=pg(&format!("SELECT policy_version FROM mdm_commands.action_runs WHERE id='{task}'"))?;
        let found=records.iter().find(|r|r.payload["plan"]==version.trim() && r.target()==task && r.action()=="command_accept").expect("task/policy-version audit coordinates");
        let registration=found.payload["registration"].as_str().expect("task registration");uuid::Uuid::parse_str(registration)?;
        ensure!(pg(&format!("SELECT device FROM mdm_access.registrations WHERE tenant_id='{TENANT}' AND id='{registration}'"))?.trim()==DEVICE_ID);
        Ok(())
    }
    .await;
    let cleanup =
        pg("DELETE FROM mdm_commands.action_runs WHERE occurrence LIKE 'history-fixture:%'");
    result?;
    cleanup?;
    ensure!(stack.shutdown().join().await?.is_clean());
    Ok(())
}
