use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_audit_integration::RequestAudit;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn console_mixed_kind_cursor_and_device_visibility() -> anyhow::Result<()> {
    use crate::test_support::query_reads::QueryReadCounts;
    use crate::test_support::{agent_execution as agent, identity};
    use std::sync::atomic::Ordering::Relaxed;
    use tracing_subscriber::layer::SubscriberExt;
    // Provider work runs in owned runtime tasks, so a future-local subscriber
    // cannot see it. T2 executes this case in its own nextest process.
    let measured = QueryReadCounts::new("execution.");
    let unselected_runs = QueryReadCounts::new("execution.runs");
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(measured.clone())
            .with(unselected_runs.clone()),
    )?;

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
    // An unrelated protected input larger than the entire hydration budget must
    // never be transferred or decrypted when selecting another command.
    let revision_sql = "SELECT coalesce((SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid),0)";
    let before = crate::test_support::process::pg(revision_sql)?;
    let rejected = Uuid::new_v4();
    client
        .app
        .execution
        .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(client.call(Method::POST,"",Some(json!({"operationId":rejected,"action":{"kind":"restart"},"deadline":host.app.clock.unix_seconds()?+300}))).await?.0==StatusCode::SERVICE_UNAVAILABLE);
    ensure!(
        crate::test_support::process::pg(revision_sql)? == before,
        "rolled-back command advanced query generation"
    );
    ensure!(
        crate::test_support::process::pg(&format!(
            "SELECT count(*) FROM rss_device_command.commands WHERE command_id='{rejected}'"
        ))?
        .trim()
            == "0",
        "command rollback leaked state"
    );
    let large = Uuid::new_v4();
    ensure!(client.call(Method::POST, "", Some(json!({"operationId":large,"action":{"kind":"restart"},"deadline":host.app.clock.unix_seconds()?+300}))).await?.0 == StatusCode::ACCEPTED);
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_commands.operations SET request=convert_to(repeat('x',20000000),'UTF8') WHERE id='{large}'"
    ))?;
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{output}}',jsonb_build_object('canary',repeat('off-page-',100000))) WHERE id='{id}'"
    ))?;
    measured.reset();
    unselected_runs.reset();
    let selected = format!("/api/v1/operations?limit=1&filter=id=={id}&sort=-id,-kind");
    let response = fixture
        .author
        .call(&fixture.router, Method::GET, &selected, None)
        .await?;
    ensure!(
        response.0 == StatusCode::OK,
        "bounded selected evidence: {response:?}"
    );
    ensure!(measured.calls.load(Relaxed) <= 5 && measured.rows.load(Relaxed) <= 16);
    ensure!(
        unselected_runs.calls.load(Relaxed) == 0,
        "off-page action run evidence reached hydration"
    );
    ensure!(
        measured.bytes.load(Relaxed) > 0 && measured.bytes.load(Relaxed) < 65536,
        "provider read budget: calls={} rows={} bytes={}",
        measured.calls.load(Relaxed),
        measured.rows.load(Relaxed),
        measured.bytes.load(Relaxed)
    );
    println!(
        "QUERY-05 execution calls={} rows={} payload_bytes={}",
        measured.calls.load(Relaxed),
        measured.rows.load(Relaxed),
        measured.bytes.load(Relaxed)
    );
    let cursor = response.1["nextCursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("mixed continuation"))?;
    let continuation = format!("{selected}&cursor={cursor}");
    let audit = RequestAudit::new(case_tenant().into(), "management_read");
    client.app.execution.recover_operation(id, &audit).await?;
    audit.finalize(None);
    ensure!(
        fixture
            .author
            .call(&fixture.router, Method::GET, &continuation, None)
            .await?
            .0
            == StatusCode::OK,
        "no-op recovery invalidated a cursor"
    );
    measured.reset();
    let response = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/operations?filter=kind==command&fields=id,kind&limit=100",
            None,
        )
        .await?;
    ensure!(
        response.0 == StatusCode::OK,
        "metadata projection read protected payload: {response:?}"
    );
    ensure!(
        measured.calls.load(Relaxed) == 0,
        "unrequested evidence reached a provider read"
    );
    println!(
        "QUERY-05 execution metadata-only provider_calls={}",
        measured.calls.load(Relaxed)
    );
    let oversized = fixture
        .author
        .call(
            &fixture.router,
            Method::GET,
            &format!("/api/v1/operations?filter=id=={large}"),
            None,
        )
        .await?;
    ensure!(
        oversized.0 == StatusCode::SERVICE_UNAVAILABLE,
        "budget overflow became conflict: {oversized:?}"
    );
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
