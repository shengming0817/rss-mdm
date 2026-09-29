use super::*;
use anyhow::Context;
pub(crate) struct Server(pub(crate) tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let (status, result) = settled_write(
        browser,
        router,
        path,
        json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}),
    )
    .await?;
    if status == StatusCode::CONFLICT && path.starts_with("/api/v2/groups/") {
        let current = browser.call(router, Method::GET, path, None).await?;
        anyhow::bail!(
            "group write at expected revision {revision}: {status} {result}; observed {current:?}"
        );
    }
    ensure!(
        status == StatusCode::OK || status == StatusCode::ACCEPTED,
        "planning request {path}: {status} {result}"
    );
    if let Some(task) = result["task"].as_str() {
        let status_url = result["statusUrl"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{path}/tasks/{task}"));
        await_task(browser, router, &status_url).await?;
    }
    Ok(result)
}
// Normal writes can collide with the live automation worker's serializable
// transaction. Retry the exact identity/body; injected failures bypass this helper.
pub(crate) async fn settled_write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value)> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let result = browser
                .call(router, Method::POST, path, Some(body.clone()))
                .await?;
            if result.0 != StatusCode::SERVICE_UNAVAILABLE {
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("planning write did not settle")?
}
pub(crate) async fn await_ingress() -> Result<()> {
    let settled=tokio::time::timeout(Duration::from_secs(90),async {
        loop {
            let ready=pg(&format!("SELECT coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id='{TENANT}'),0)=coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),0) AND NOT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id='{TENANT}' AND NOT completed)", TENANT = case_tenant()))?;
            if ready.trim()=="t" { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await;
    if let Ok(outcome) = settled {
        return outcome;
    }
    let progress = pg(&format!(
        "SELECT jsonb_build_object('clock',(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),'checkpoint',(SELECT to_jsonb(d)-'cursor' FROM mdm_planning.asset_dispatch d WHERE tenant_id='{TENANT}'),'jobs',(SELECT jsonb_agg(p) FROM (SELECT j.id,j.kind,j.forwarded,j.failure,r.phase,r.object_count FROM mdm_automation.automation_jobs j LEFT JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{TENANT}' AND NOT j.completed ORDER BY j.id LIMIT 16)p))",
        TENANT = case_tenant()
    ))?;
    anyhow::bail!("fixture ingress did not settle: {progress}")
}
