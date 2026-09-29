#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
async fn collected_facts(b: &mut Browser, router: &Router, base: &Value) -> Result<()> {
    use crate::inventory_runtime::test_support::{report, start, wait_ready_projection};
    let device = "collected-compliance";
    pg(&format!(
        "INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}')",
        TENANT = case_tenant()
    ))?;
    let (registration, _) =
        crate::test_support::inventory::seed_source(device, "mdm", "mdm.windows", "seed")?;
    let locator = crate::test_support::secret("channel-proof-121")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator='{locator}' WHERE registration='{registration}'"
    ))?;
    let access = database(base).await?;
    let service = crate::device::DeviceService::new(
        access.clone(),
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
        access.clone(),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
    )
    .await?;
    let owner = start(runtime.clone()).await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v2/compliance-rules/{id}");
    let mut def = definition(json!({"kind":"all"}));
    def["platform"] = json!("windows");
    def["criteria"] = json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Collected"}});
    ok(b, router, Method::PUT, &path, Some(request(0, def.clone()))).await?;
    for (model, expected) in [("Collected", "compliant"), ("Changed", "non_compliant")] {
        let run = report(&service, &access, &proof, [Some(model), Some("11")]).await?;
        wait_ready_projection(&runtime, &run).await?;
        let response = status(b, router, device, expected).await?;
        let current = &response["rules"][0]["current"];
        ensure!(current["applicability"]["platformDecision"] == "match");
        ensure!(current["evidence"][0]["sources"][0]["source"] == "mdm.windows");
        if model == "Collected" {
            for values in [[Some("Unconfirmed"), None], [None, None]] {
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
                let retained = status(b, router, device, "compliant").await?;
                ensure!(
                    retained["rules"][0]["current"]["evidence"] == current["evidence"],
                    "failed collection replaced verified facts"
                );
                // Explicit reevaluation also uses the same complete fact, even at a newer watermark.
                let run = ok(
                    b,
                    router,
                    Method::POST,
                    &format!("{path}/recompute"),
                    Some(request(1, json!({}))),
                )
                .await?;
                task_phase(
                    b,
                    router,
                    &format!("{path}/tasks/{}", run["task"].as_str().unwrap()),
                    "published",
                )
                .await?;
                ensure!(
                    status(b, router, device, "compliant").await?["rules"][0]["current"]["status"]
                        == "compliant"
                );
            }
        }
    }
    def["enabled"] = json!(false);
    ok(b, router, Method::PUT, &path, Some(request(1, def))).await?;
    crate::test_support::stop_worker(owner).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.evaluation: real HTTP and durable worker contract"]
async fn manual_and_collected_facts_evaluate_with_provenance() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    let (agent, _) = crate::test_support::inventory::seed_source(
        "compliance-b",
        "agent",
        "agent.builtin",
        "seed",
    )?;
    for source in ["agent.script", "agent.osquery"] {
        let epoch = Uuid::new_v4();
        pg(&format!(
            "INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{agent}','{source}','{epoch}','enterprise-task-v1',true)",
            TENANT = case_tenant()
        ))?;
    }
    let (_, path, _) = fixture.rule().await?;
    let automation = start_automation(base).await?;
    let unknown = status(&mut browser, router, "compliance-a", "unknown").await?;
    ensure!(unknown["rules"][0]["current"]["reason"] == "facts_unknown");
    assign(&mut browser, router, "compliance-a", 0, false).await?;
    let passed = status(&mut browser, router, "compliance-a", "compliant").await?;
    let old = passed["rules"][0]["current"].clone();
    ensure!(old["evidence"][0]["sources"][0]["snapshotId"].is_string());
    assign(&mut browser, router, "compliance-a", 1, true).await?;
    let failed = status(&mut browser, router, "compliance-a", "non_compliant").await?;
    ensure!(
        failed["rules"][0]["current"]["factWatermark"].as_i64() > old["factWatermark"].as_i64()
    );
    let mut disabled = definition(json!({"kind":"all"}));
    disabled["enabled"] = json!(false);
    ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(1, disabled)),
    )
    .await?;
    collected_facts(&mut browser, router, base).await?;
    crate::test_support::stop_worker(automation).await?;
    fixture.close().await;
    Ok(())
}
