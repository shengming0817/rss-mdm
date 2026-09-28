use super::*;
async fn source_matrix(browser: &mut Browser, router: &Router) -> Result<()> {
    let (mdm, _) = seed_source("asset-b", "mdm", "mdm.windows", "Same")?;
    let (agent, _) = seed_source("asset-b", "agent", "agent.builtin", "Same")?;
    let path = "/api/v2/devices/asset-b/inventory";
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "known");
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["sources"]
            .as_array()
            .unwrap()
            .len()
            == 2
    );
    pg(&format!(
        "UPDATE mdm.inventory SET value='Different' WHERE registration='{agent}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "conflict");
    let query = json!({"criteria":predicate("device.model","string",json!("Same"))});
    let found = ok(
        browser,
        router,
        Method::POST,
        "/api/v2/device-queries",
        Some(query.clone()),
    )
    .await?;
    ensure!(found["asset"]["summary"]["matched"] == 0 && found["asset"]["summary"]["unknown"] == 2);
    pg(&format!(
        "UPDATE mdm.inventory SET state='deleted',value=NULL WHERE registration='{agent}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"] == "Same"
    );
    pg(&format!(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE id='{mdm}'; UPDATE mdm.inventory SET value='Late old value' WHERE registration='{mdm}';"
    ))?;
    let detail = ok(browser, router, Method::GET, path, None).await?;
    ensure!(detail["asset"]["device"]["fields"]["device.model"]["state"]["kind"] == "deleted");
    ensure!(
        detail["asset"]["device"]["fields"]["device.model"]["sources"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    Ok(())
}
async fn retained_collection_quality(browser: &mut Browser, router: &Router) -> Result<()> {
    let (registration, epoch) = seed_source("tie-b", "agent", "agent.builtin", "quality-sequence")?;
    let scope = crate::device::scope(
        rss_request_context::TenantId::parse(TENANT)?,
        registration,
        "agent.builtin",
        epoch,
    )?
    .encode()?
    .replace('\'', "''");
    let older = "80000000-0000-4000-8000-000000000001";
    let newer = "80000000-0000-4000-8000-000000000002";
    for id in [older, newer] {
        pg(&format!(
            "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) SELECT tenant_id,'{id}','{registration}','agent.builtin','{epoch}','{scope}',7,started_at,attempts,result,reason,batch,digest,sealed_at,false FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND source='mdm.windows' AND reason='complete' AND batch IS NOT NULL ORDER BY sequence DESC LIMIT 1"
        ))?;
    }
    let query = json!({"criteria":predicate("device.model","string",json!("quality-sequence"))});
    for expected in [newer, older] {
        let detail = ok(
            browser,
            router,
            Method::GET,
            "/api/v2/devices/tie-b/inventory",
            None,
        )
        .await?;
        ensure!(detail["asset"]["device"]["quality"][0]["runId"] == expected);
        let page = ok(
            browser,
            router,
            Method::POST,
            "/api/v2/device-queries",
            Some(query.clone()),
        )
        .await?;
        ensure!(
            page["asset"]["items"][0]["quality"] == detail["asset"]["device"]["quality"],
            "retaining one run must not erase another with the same sequence"
        );
        if expected == newer {
            pg(&format!(
                "DELETE FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{newer}'"
            ))?;
        }
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.sources: real Router and persisted assets"]
async fn sources_resolution_and_retained_quality() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    source_matrix(&mut browser, router).await?;
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-b')"
    ))?;
    crate::test_support::inventory::completed_windows_run(&fixture.base, "asset-a").await?;
    retained_collection_quality(&mut browser, router).await?;
    fixture.close().await
}
