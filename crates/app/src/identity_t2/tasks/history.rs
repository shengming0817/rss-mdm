use super::*;
use anyhow::Context;
use std::collections::BTreeSet;

pub(super) async fn verify(author: &mut Browser, router: &Router, plan: Uuid) -> Result<()> {
    let task = pg(&format!(
        "SELECT id FROM mdm_commands.action_runs WHERE plan='{plan}' AND occurrence NOT LIKE 'history-fixture:%' ORDER BY created_at,id LIMIT 1"
    ))?
    .trim()
    .to_owned();
    Uuid::parse_str(&task)?;
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,plan,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result) SELECT tenant_id,gen_random_uuid(),plan,device,registration,generation,'history-fixture:'||n,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result FROM mdm_commands.action_runs CROSS JOIN generate_series(1,25) n WHERE id='{task}'"
    ))?;

    let result: Result<()> = async {
        let available_at = pg(&format!(
            "SELECT available_at FROM mdm_commands.action_runs WHERE id='{task}'"
        ))?
        .trim()
        .parse::<i64>()?;
        let mut path = format!("/api/v3/script-plans/{plan}/runs");
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
                "/api/v3/script-plans/{plan}/runs?afterAt={after_at}&afterId={after_id}"
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
                &format!("/api/v3/script-plans/{plan}/runs/{task}"),
                None,
            )
            .await?;
        ensure!(status == StatusCode::OK, "run detail: {status} {detail}");
        ensure!(detail["result"]["output"]["version"] == "1.2", "run detail: {detail}");
        ensure!(
            author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v3/script-plans/{}/runs/{task}", Uuid::new_v4()),
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
                    &format!("/api/v3/script-plans/{plan}/runs?afterAt={available_at}"),
                    None,
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );

        ensure!(
            pg(&format!(
                "SELECT count(*)>0 FROM mdm_access.audit a JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(a.tenant_id,a.registration_id) WHERE a.plan='{plan}' AND a.target='{task}' AND a.action='command_accept' AND r.device='{DEVICE_ID}'"
            ))?
            .trim()
                == "t",
            "task event audit lost task/plan/registration coordinates"
        );
        ensure!(
            pg(&format!(
                "SELECT count(*)>0 FROM mdm_access.audit WHERE plan='{plan}' AND action='command_approve'"
            ))?
            .trim()
                == "t",
            "approval audit lost its plan coordinate"
        );
        Ok(())
    }
    .await;
    let cleanup =
        pg("DELETE FROM mdm_commands.action_runs WHERE occurrence LIKE 'history-fixture:%'");
    result?;
    cleanup?;
    Ok(())
}
