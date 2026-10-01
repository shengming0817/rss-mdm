#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
async fn collection_matrix(browser: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    use crate::inventory_runtime::test_support::{report, start, wait_ready_projection};
    let (registration, _) = seed_source("tie-a", "mdm", "mdm.windows", "seed")?;
    let locator = crate::test_support::secret("channel-proof-121")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator='{locator}' WHERE registration='{registration}'"
    ))?;
    let access = database(base).await?;
    let service = crate::device::DeviceService::new(
        access.registration(),
        case_tenant().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let proof =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 121);
    let config: Config = serde_json::from_value(base.clone())?;
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.inventory(),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let owner = start(runtime.clone()).await?;
    let full = report(&service, &access, &proof, [Some("Collected"), Some("11")]).await?;
    wait_ready_projection(&runtime, &full).await?;
    let criteria = predicate("device.model", "string", json!("Collected"));
    for (values, result) in [
        ([Some("Unconfirmed"), None], "partial"),
        ([None, None], "failed"),
    ] {
        let incomplete = report(&service, &access, &proof, values).await?;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let delivery = runtime.inspect(&incomplete).await?;
                if delivery.receipt.is_some()
                    && delivery.projection
                        == crate::inventory_runtime::ProjectionStatus::NotApplicable
                {
                    return Ok::<_, crate::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        let detail = ok(
            browser,
            router,
            Method::GET,
            "/api/v2/devices/tie-a/inventory",
            None,
        )
        .await?;
        ensure!(
            detail["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                == "Collected"
        );
        ensure!(detail["asset"]["device"]["quality"][0]["result"] == result);
        let quality = &detail["asset"]["device"]["quality"][0];
        ensure!(quality["source"] == "mdm.windows" && quality["channel"] == "mdm");
        ensure!(
            quality["registration"] == registration.to_string()
                && quality["registrationGeneration"] == 1
        );
        ensure!(quality["epoch"].as_str().is_some());
        let search = ok(
            browser,
            router,
            Method::POST,
            "/api/v2/device-queries",
            Some(json!({"criteria":criteria})),
        )
        .await?;
        ensure!(
            search["asset"]["summary"]["matched"] == 1
                && search["asset"]["items"][0]["device"] == "tie-a"
        );
        ensure!(
            search["asset"]["items"][0]["quality"] == detail["asset"]["device"]["quality"],
            "query lost frozen collection quality"
        );
        let group = format!("/api/v2/groups/{}", Uuid::new_v4());
        ok(browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","name":result,"description":"collection proof","criteria":criteria})))).await?;
        let preview = preview(browser, router, &group).await?;
        ensure!(preview.members["page"]["items"] == json!(["tie-a"]));
        ensure!(ok(browser, router, Method::GET, &group, None).await?["group"]["memberCount"] == 1);
    }
    let unsupported = crate::inventory_runtime::test_support::report_statuses(
        &service,
        &access,
        &proof,
        [None, Some("11")],
        [501, 200],
    )
    .await?;
    wait_ready_projection(&runtime, &unsupported).await?;
    let detail = ok(
        browser,
        router,
        Method::GET,
        "/api/v2/devices/tie-a/inventory",
        None,
    )
    .await?;
    let field = &detail["asset"]["device"]["fields"]["device.model"];
    ensure!(field["state"]["kind"] == "unsupported");
    ensure!(field["sources"][0]["lastKnown"]["value"]["value"] == "Collected");
    let query = ok(
        browser,
        router,
        Method::POST,
        "/api/v2/device-queries",
        Some(json!({"criteria":criteria})),
    )
    .await?;
    ensure!(
        query["asset"]["summary"]["matched"] == 0
            && query["asset"]["summary"]["unknown"].as_u64().unwrap() > 0
    );
    let group = format!("/api/v2/groups/{}", Uuid::new_v4());
    ok(browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","name":"unsupported","description":"explicit source status","criteria":criteria})))).await?;
    let preview = preview(browser, router, &group).await?;
    ensure!(preview.members["page"]["items"] == json!([]));
    ensure!(
        preview.decisions["page"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["explanations"][0]["outcome"] == "unsupported")
    );
    ensure!(ok(browser, router, Method::GET, &group, None).await?["group"]["memberCount"] == 0);
    crate::test_support::stop_worker(owner).await?;
    runtime.close_fixture().await?;
    access.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.group_input: real Router and persisted assets"]
async fn typed_and_collected_facts_become_group_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    for (field, kind, value) in [
        ("custom.asset_tag", "string", json!("A-2463")),
        ("custom.office_floor", "integer", json!(3)),
        ("custom.is_loaner", "boolean", json!(false)),
        ("custom.purchase_date", "time", json!(1_700_000_000)),
    ] {
        ok(
            &mut browser,
            router,
            Method::PUT,
            &format!("/api/v2/devices/asset-a/manual-fields/{field}"),
            Some(request(
                0,
                json!({"action":"set","value":{"kind":kind,"value":value}}),
            )),
        )
        .await?;
        let group = format!("/api/v2/groups/{}", Uuid::new_v4());
        ok(&mut browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","name":field,"description":"asset input","criteria":predicate(field,kind,value)})))).await?;
        ensure!(
            preview(&mut browser, router, &group).await?.members["page"]["items"]
                == json!(["asset-a"])
        );
    }
    seed_source("asset-b", "mdm", "mdm.windows", "Same")?;
    seed_source("asset-b", "agent", "agent.builtin", "Different")?;
    let query = json!({"criteria":predicate("device.model","string",json!("Same"))});
    let group = format!("/api/v2/groups/{}", Uuid::new_v4());
    ok(&mut browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","name":"conflict","description":"","criteria":query["criteria"]})))).await?;
    let preview = preview(&mut browser, router, &group).await?;
    ensure!(
        preview.members["page"]["items"] == json!([])
            && preview.decisions["page"]["items"][1]["explanations"][0]["outcome"] == "conflict"
    );
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-a')",
        TENANT = case_tenant()
    ))?;
    collection_matrix(&mut browser, router, &fixture.base).await?;
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.group_input: projected Agent script facts reach Query and Group"]
async fn script_health_projection_is_queryable_group_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let mut browser = fixture.browser.clone();
    // Producer execution/projection is covered by execution.agent.delivery.
    // This consumer starts from a legal registered source and its projected fact.
    let (registration, _) = seed_source("asset-a", "agent", "agent.builtin", "fixture")?;
    let epoch = Uuid::new_v4();
    let field = rss_mdm_inventory::builtin::CORPORATE_AGENT_HEALTHY;
    let scope = crate::device::scope_dataset(
        rss_request_context::TenantId::parse(case_tenant())?,
        registration,
        "agent.script",
        epoch,
        field.as_str(),
    )?
    .encode()?
    .replace('\'', "''");
    let coverage = serde_json::to_string(
        &crate::test_support::inventory::definition(field.as_str(), "agent.script", &[field])
            .coverage()?,
    )?;
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::Boolean(true))?;
    pg(&format!("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','agent.script','{epoch}','enterprise-task-v1',true);
        INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch)
        VALUES('{TENANT}','mdm.observation.v1','inventory-v3','{scope}','{coverage}','custom.corporate_agent.healthy','{value}','script-fixture',1,2,'known','{value}','script-fixture',1,2,'{registration}','agent.script','{epoch}');", TENANT = case_tenant()))?;
    let criteria = predicate("custom.corporate_agent.healthy", "boolean", json!(true));
    let query = ok(
        &mut browser,
        &fixture.router,
        Method::POST,
        "/api/v2/device-queries",
        Some(json!({"criteria":criteria})),
    )
    .await?;
    ensure!(query["asset"]["summary"]["matched"] == 1);
    ensure!(query["asset"]["items"][0]["device"] == "asset-a");
    let group = format!("/api/v2/groups/{}", Uuid::new_v4());
    ok(&mut browser, &fixture.router, Method::POST, &group,
        Some(request(0,json!({"action":"create","name":"healthy-script","description":"projected Agent input","criteria":criteria})))).await?;
    ensure!(
        preview(&mut browser, &fixture.router, &group)
            .await?
            .members["page"]["items"]
            == json!(["asset-a"])
    );
    fixture.close().await
}
