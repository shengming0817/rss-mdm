#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
async fn collection_matrix(
    browser: &mut Browser,
    router: &Router,
    authority: &authority::Authority,
) -> Result<()> {
    use crate::inventory_runtime::test_support::{report, start, wait_ready_projection};
    let (registration, _) = seed_source("tie-a", "mdm", "mdm.windows", "seed")?;
    let locator = crate::test_support::runtime::secret("channel-proof-121")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator='{locator}' WHERE registration='{registration}'"
    ))?;
    let service = crate::device::DeviceService::new(
        authority.registration.clone(),
        case_tenant().into(),
        authority.audit.clone(),
    );
    let proof =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 121);
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        Arc::new(rss_mdm_inventory_service::Store::from_pool(
            authority.pool.clone(),
        )),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
        authority.audit.clone(),
    )
    .await?;
    let owner = start(runtime.clone()).await?;
    let full = report(
        &service,
        &rss_mdm_inventory_service::Store::from_pool(authority.pool.clone()),
        &authority.audit,
        &proof,
        [Some("Collected"), Some("11")],
    )
    .await?;
    wait_ready_projection(&runtime, &full).await?;
    let criteria = predicate("device.model", "string", json!("Collected"));
    {
        let result = "snapshot";
        let detail = ok(
            browser,
            router,
            Method::GET,
            "/api/v1/devices/tie-a/inventory",
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
        ensure!(
            quality["runId"] == full.id.to_string(),
            "query must retain the projected producer coordinate"
        );
        let search = ok(
            browser,
            router,
            Method::POST,
            "/api/v1/device-queries",
            Some(rsql_query(criteria.clone())),
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
        let group = format!("/api/v1/groups/{}", Uuid::new_v4());
        ok(browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":result,"description":"collection proof"},"criteria":criteria})))).await?;
        let preview = preview(browser, router, &group).await?;
        ensure!(preview.members["page"]["items"] == json!([{"kind":"endpoint","id":"tie-a"}]));
        ensure!(ok(browser, router, Method::GET, &group, None).await?["group"]["memberCount"] == 1);
    }
    let unsupported = Uuid::new_v4();
    pg(&format!(
        "SELECT mdm.lock_asset_watermark('{tenant}'); UPDATE mdm.inventory SET state='unsupported',value=NULL,value_version=NULL,batch_id='{unsupported}',collection_sequence=collection_sequence+1 WHERE tenant_id='{tenant}' AND registration='{registration}' AND field='device.model'",
        tenant = case_tenant()
    ))?;
    let detail = ok(
        browser,
        router,
        Method::GET,
        "/api/v1/devices/tie-a/inventory",
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
        "/api/v1/device-queries",
        Some(rsql_query(criteria.clone())),
    )
    .await?;
    ensure!(
        query["asset"]["summary"]["matched"] == 0
            && query["asset"]["summary"]["unknown"].as_u64().unwrap() > 0
    );
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"unsupported","description":"explicit source status"},"criteria":criteria})))).await?;
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
    crate::test_support::runtime::stop_worker(owner).await?;
    runtime.close_fixture().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.group_input: real Router and persisted assets"]
async fn typed_and_collected_facts_become_group_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let mut browser = fixture.browser.clone();
    let (field, kind, value) = ("custom.office_floor", "integer", json!(3));

    ok(
        &mut browser,
        router,
        Method::PUT,
        &format!("/api/v1/devices/asset-a/manual-fields/{field}"),
        Some(request(
            0,
            json!({"action":"set","value":{"kind":kind,"value":value}}),
        )),
    )
    .await?;
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(&mut browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":field,"description":"asset input"},"criteria":predicate(field,kind,value)})))).await?;
    ensure!(
        preview(&mut browser, router, &group).await?.members["page"]["items"]
            == json!([{"kind":"endpoint","id":"asset-a"}])
    );
    seed_source("asset-b", "mdm", "mdm.windows", "Same")?;
    seed_source("asset-b", "agent", "agent.builtin", "Different")?;
    let query = json!({"criteria":predicate("device.model","string",json!("Same"))});
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(&mut browser,router,Method::POST,&group,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"conflict","description":""},"criteria":query["criteria"]})))).await?;
    let preview = preview(&mut browser, router, &group).await?;
    ensure!(
        preview.members["page"]["items"] == json!([])
            && preview.decisions["page"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|decision| decision["object"]["id"] == "asset-b"
                    && decision["explanations"][0]["outcome"] == "conflict")
    );
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','tie-a')",
        TENANT = case_tenant()
    ))?;
    collection_matrix(&mut browser, router, &fixture.authority).await?;
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=assets.group_input: projected Agent script facts reach Query and Group"]
async fn projected_script_fact_is_queryable_group_input() -> Result<()> {
    let fixture = Fixture::open().await?;
    let mut browser = fixture.browser.clone();
    // Producer execution/projection is covered by execution.agent.delivery.
    // This consumer starts from a legal registered source and its projected fact.
    let registration = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let credential = Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES('{tenant}','{grant}','{operation}','download','fixture','{INSTANCE}','asset-a','macos',repeat('0',64),repeat('0',64),'consumed',clock_timestamp()+interval '24 hours'); INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch) VALUES('{tenant}','{registration}','asset-a','agent',1,'{grant}','active','primary',gen_random_uuid()); INSERT INTO mdm_access.credentials VALUES('{tenant}','{credential}','{registration}','agent',md5('{credential}')||md5('{registration}'),'active');",
        tenant = case_tenant()
    ))?;
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
    crate::test_support::inventory::register_definition(
        &crate::test_support::inventory::definition(field.as_str(), "agent.script", &[field]),
    )?;
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::Boolean(true))?;
    pg(&format!("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES('{TENANT}','{registration}','agent.script','{epoch}',true);
        INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence)
        VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{TENANT}','mdm.observation.v1','inventory-projection-v1','{scope}','{coverage}','custom.corporate_agent.healthy','{value}','script-fixture',1,2,'known','{value}','script-fixture',1,2,'{registration}','agent.script','{epoch}',0);", TENANT = case_tenant()))?;
    let criteria = predicate("custom.corporate_agent.healthy", "boolean", json!(true));
    let query = ok(
        &mut browser,
        &fixture.router,
        Method::POST,
        "/api/v1/device-queries",
        Some(rsql_query(criteria.clone())),
    )
    .await?;
    ensure!(query["asset"]["summary"]["matched"] == 1);
    ensure!(query["asset"]["items"][0]["device"] == "asset-a");
    let group = format!("/api/v1/groups/{}", Uuid::new_v4());
    ok(&mut browser, &fixture.router, Method::POST, &group,
        Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"healthy-script","description":"projected Agent input"},"criteria":criteria})))).await?;
    ensure!(
        preview(&mut browser, &fixture.router, &group)
            .await?
            .members["page"]["items"]
            == json!([{"kind":"endpoint","id":"asset-a"}])
    );
    fixture.close().await
}
