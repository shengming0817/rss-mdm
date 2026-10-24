use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn console_mixed_kind_cursor_and_device_visibility() -> anyhow::Result<()> {
    use crate::test_support::{agent_execution as agent, identity};
    let mut base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    // The real Windows Host below owns this case's Windows endpoint and trust.
    base["native_protocols"]
        .as_object_mut()
        .unwrap()
        .remove("windows");
    let mut fixture = agent::Fixture::from_config(base).await?;
    fixture.register().await?;
    let (resource, _, _) = fixture.resource().await?;
    fixture
        .scope(
            agent::case_task_scope(),
            json!([{"kind":"device","id":agent::case_device_id()}]),
        )
        .await?;
    let worker = agent::worker(&fixture.base).await?;
    agent::publish(&mut fixture.author, &fixture.router, resource).await?;
    let task = agent::claim(&fixture.router).await?;
    agent::complete(&fixture.router, &task).await?;
    let id = Uuid::parse_str(task["payload"]["task"]["taskId"].as_str().unwrap())?;
    crate::test_support::runtime::stop_worker(worker).await?;
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let _peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    // IDs belong to their original owners; equal IDs must not lose either kind.
    client.operation = id;
    client.known_windows_capability(case_device()).await?;
    client.accept_authorized().await?;
    client.publish_operation(id).await?;
    let mut grants = fixture.grants.clone();
    grants.extend(identity::device_grants(None, &["operation_read"])?);
    identity::set_grants(case_tenant(), &fixture.author_id, grants).await?;
    for descending in [false, true] {
        let sort = if descending { "-id,-kind" } else { "id,kind" };
        let mut path = format!("/api/v1/operations?limit=1&sort={sort}");
        let mut kinds = Vec::new();
        loop {
            let (status, page) = fixture
                .author
                .call(&fixture.router, Method::GET, &path, None)
                .await?;
            ensure!(status == StatusCode::OK, "mixed directory: {status} {page}");
            let (_, statistics) = fixture
                .author
                .call(
                    &fixture.router,
                    Method::GET,
                    "/api/v1/operations/statistics",
                    None,
                )
                .await?;
            ensure!(
                statistics["statistics"]["total"] == 2
                    && statistics["statistics"]["commands"] == 1
                    && statistics["statistics"]["actionRuns"] == 1,
                "mixed statistics: {page}"
            );
            let item = &page["items"][0];
            ensure!(item["id"] == id.to_string(), "mixed ID: {item}");
            let kind = item["kind"].as_str().unwrap();
            kinds.push(kind.to_owned());
            if kind == "command" {
                ensure!(
                    item["evidence"]["commandStatus"] == "published"
                        && item["evidence"]["observation"]["effect"] == "waiting",
                    "receipt became effect: {item}"
                );
                ensure!(item["evidence"]["observation"].get("value").is_none());
                ensure!(
                    item["detailUrl"]
                        == format!("/api/v1/devices/{}/operations/{id}", case_device())
                );
            } else {
                ensure!(item["evidence"]["result"].get("output").is_none());
                ensure!(
                    item["evidence"]["result"]["diagnostics"]
                        .get("stdout")
                        .is_none()
                );
            }
            let detail_path = item["detailUrl"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing execution detail URL"))?;
            let detail = fixture
                .author
                .call(&fixture.router, Method::GET, detail_path, None)
                .await?;
            ensure!(
                detail.0 == StatusCode::OK,
                "unusable execution detail URL {detail_path}: {:?}",
                detail
            );
            let Some(cursor) = page["nextCursor"].as_str() else {
                break;
            };
            path = format!("/api/v1/operations?limit=1&sort={sort}&cursor={cursor}");
            ensure!(kinds.len() <= 2, "cursor repeated: {kinds:?}");
        }
        let expected = if descending {
            vec!["command", "action_run"]
        } else {
            vec!["action_run", "command"]
        };
        ensure!(kinds == expected, "mixed cursor lost an owner: {kinds:?}");
    }
    identity::set_grants(case_tenant(), &fixture.author_id, fixture.grants.clone()).await?;
    let (status, page) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations?limit=1",
            None,
        )
        .await?;
    let (_, statistics) = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations/statistics",
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK
            && statistics["statistics"]["total"] == 1
            && statistics["statistics"]["commands"] == 0
            && page["items"][0]["kind"] == "action_run"
            && page["nextCursor"].is_null(),
        "hidden command affected count or cursor: {page}"
    );
    let hidden = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v1/operations?filter=device=={}", case_device()),
            None,
        )
        .await?;
    ensure!(hidden.0 == StatusCode::OK && hidden.1["items"] == json!([]));
    host.close().await?;
    Ok(())
}
