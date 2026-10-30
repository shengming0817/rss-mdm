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
    let locator = crate::test_support::runtime::secret("channel-proof-121")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_access.credentials SET locator='{locator}' WHERE registration='{registration}'"
    ))?;
    let mut authority = authority::Authority::from_config(base.clone()).await?;
    let inventory = Arc::new(rss_mdm_inventory_service::Store::from_pool(
        authority.pool.clone(),
    ));
    let service = crate::device::DeviceService::new(
        authority.registration.clone(),
        case_tenant().into(),
        authority.audit.clone(),
    );
    let proof =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 121);
    let config: Config = serde_json::from_value(base.clone())?;
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        inventory.clone(),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
        authority.audit.clone(),
    )
    .await?;
    authority
        .resources
        .resource(InventoryFixtureResource(runtime.clone()));
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let owner = start(runtime.clone()).await?;
    let id = Uuid::new_v4();
    let path = format!("/api/v1/compliance-rules/{id}");
    let mut def = definition(json!({"kind":"all"}));
    def["platform"] = json!("windows");
    def["criteria"]["criteria"] = json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Collected"}});
    ok(b, router, Method::PUT, &path, Some(request(0, def.clone()))).await?;
    for (model, expected) in [("Collected", "compliant"), ("Changed", "non_compliant")] {
        let snapshot = if model == "Collected" {
            let run = report(&service, &inventory, &authority.audit, &proof, [Some(model), Some("11")]).await?;
            wait_ready_projection(&runtime, &run).await?;
            run.id.to_string()
        } else {
            let snapshot = Uuid::new_v4().to_string();
            let value = serde_json::to_string(&rss_mdm_inventory::Scalar::String(model.into()))?;
            pg(&format!("SELECT mdm.lock_asset_watermark('{tenant}'); UPDATE mdm.inventory SET value='{value}',value_version=NULL,batch_id='{snapshot}',last_known='{value}',last_known_batch='{snapshot}',collection_sequence=collection_sequence+1 WHERE tenant_id='{tenant}' AND registration='{registration}' AND field='device.model'", tenant=case_tenant()))?;
            snapshot
        };
        let response = status(b, router, device, expected).await?;
        let current = &response["rules"][0]["current"];
        ensure!(current["applicability"]["platformDecision"] == "match");
        ensure!(current["evidence"][0]["sources"][0]["source"] == "mdm.windows");
        ensure!(current["evidence"][0]["sources"][0]["snapshotId"] == snapshot);
    }

    def["enabled"] = json!(false);
    ok(b, router, Method::PUT, &path, Some(request(1, def))).await?;
    crate::test_support::runtime::stop_worker(owner).await?;
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.evaluation: real HTTP and durable worker contract"]
async fn manual_and_collected_facts_evaluate_with_provenance() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
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
    crate::test_support::runtime::stop_worker(automation).await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.evaluation: large immutable arrays across Query, Group and Compliance"]
async fn large_object_streams_through_all_consumers_and_recovers_progress() -> Result<()> {
    use rss_mdm_inventory::{
        CollectionScope, Evidence, FieldKey, Scalar, Source, State, ValueType, builtin,
    };
    let fixture = Fixture::open().await?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    fixture
        .inventory_runtime
        .local_tx(
            tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(60),
            ),
            |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            let seed = async {
                                for (name, tail) in
                                    [("custom.stream_a", "tail-a"), ("custom.stream_b", "tail-b")]
                                {
                                    let mut field = builtin::fields()
                                        .into_iter()
                                        .find(|f| f.key == builtin::OFFICE_FLOOR)
                                        .unwrap();
                                    field.key = FieldKey::parse(name)?;
                                    field.value_type = ValueType::Array {
                                        items: Box::new(ValueType::String {
                                            max_length: 60000,
                                            allow_empty: false,
                                        }),
                                        max_items: 1000,
                                    };
                                    anyhow::ensure!(
                                        rss_mdm_inventory_postgres::publish_field_in(
                                            c, tenant, 0, &field
                                        )
                                        .await?
                                    );
                                    let mut items = vec![Scalar::String("x".repeat(60000)); 200];
                                    items.push(Scalar::String(tail.into()));
                                    let evidence = Evidence {
                                        scope: CollectionScope::Device,
                                        source: Source::Manual,
                                        dataset: None,
                                        registration: None,
                                        registration_generation: None,
                                        epoch: None,
                                        snapshot_id: name.into(),
                                        observed_at: 1,
                                        received_at: 1,
                                        actor: Some("stream-fixture".into()),
                                    };
                                    anyhow::ensure!(
                                        rss_mdm_inventory_postgres::assign_in(
                                            c,
                                            tenant,
                                            "compliance-a",
                                            field.key,
                                            0,
                                            &State::Known(Scalar::Array(items)),
                                            &evidence
                                        )
                                        .await?
                                            == Some(1)
                                    );
                                }
                                Ok::<_, anyhow::Error>(())
                            }
                            .await;
                            seed.map_err(|e| sqlx::Error::Protocol(e.to_string()))
                        })
                    })
                    .await
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!("seed {e:?}")),
            |e| Err(anyhow::anyhow!("seed {e:?}")),
            |e| Err(anyhow::anyhow!("seed {e:?}")),
            |e| Err(anyhow::anyhow!("seed {e:?}")),
            |e| Err(anyhow::anyhow!("seed {e:?}")),
        )?;
    let old_size=pg("SELECT sum(v.canonical_bytes)*3 FROM mdm.manual_assignments m JOIN mdm.array_versions v ON (v.tenant_id,v.version)=(m.tenant_id,m.value_version) WHERE m.device='compliance-a' AND m.field IN('custom.stream_a','custom.stream_b')")?.trim().parse::<usize>()?;
    ensure!(
        old_size > 64 * 1024 * 1024,
        "fixture must exceed the retired snapshot bound"
    );
    let mut browser = fixture.browser.clone();
    let query = json!({"filter":"custom.stream_a=containsall=(tail-a);custom.stream_b=containsany=(tail-b)","fields":["custom.stream_a","custom.stream_b"]});
    let accepted = ok(
        &mut browser,
        &fixture.router,
        Method::POST,
        "/api/v1/device-queries",
        Some(request(0, query)),
    )
    .await?;
    let status_url = accepted["asset"]["statusUrl"].as_str().unwrap().to_owned();
    let task = Uuid::parse_str(status_url.rsplit('/').next().unwrap())?;
    // Execute one fenced worker chunk, then drop the service. The next process/service
    // must consume persisted typed progress, not an in-memory accumulator or object cursor.
    let planning = crate::planning::test_support::planning(tenant).await;
    let assets = crate::planning::test_support::assets(&planning).await;
    use rss_reconcile::{DurableStore, Reconciler};
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(crate::planning::test_support::options())
        .await?;
    let schedule = rss_reconcile_postgres::PgStore::new(pool, &control).await?;
    let worker =
        rss_mdm_inventory_service::assets::runtime::QueryWork::new(assets, schedule.clone());
    let scope = rss_reconcile::Scope::new(tenant, "mdm.asset-queries")?;
    let claims = worker
        .claim_due(&scope, 32, Duration::from_secs(30), &control)
        .await?;
    let mut advanced = false;
    for claim in claims {
        if claim.target().entity() == format!("task:{task}") {
            worker
                .apply(&claim, worker.observe(&claim, &control).await?, &control)
                .await?;
            advanced = true;
        }
        worker.release(&claim, &control).await?;
    }
    ensure!(advanced, "accepted query was not claimable");
    ensure!(matches!(
        schedule.close(&control).await,
        rss_reconcile_postgres::CloseOutcome::Drained
    ));
    ensure!(
        pg(&format!(
            "SELECT started AND NOT completed FROM mdm_assets.asset_query_runs WHERE id='{task}'"
        ))?
        .trim()
            == "t"
    );
    planning.close().await;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_assets.query_evaluation_arrays WHERE task='{task}'"
        ))?
        .trim()
            == "1"
    );
    ensure!(
        pg(&format!(
            "SELECT total FROM mdm_assets.asset_query_runs WHERE id='{task}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_assets.asset_query_results WHERE run='{task}'"
        ))?
        .trim()
            == "0"
    );
    let worker = start_automation(&fixture.base).await?;
    crate::test_support::http::await_task(&mut browser, &fixture.router, &status_url).await?;
    let results = ok(
        &mut browser,
        &fixture.router,
        Method::GET,
        &format!("{status_url}/items"),
        None,
    )
    .await?;
    ensure!(results["asset"]["summary"]["matched"] == 1, "{results}");
    ensure!(results["asset"]["items"][0]["lists"]["custom.stream_a"]["state"]["count"] == 201);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_assets.query_evaluations WHERE task='{task}'"
        ))?
        .trim()
            == "0"
    );
    let condition = json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"and","children":[
        {"kind":"predicate","field":"custom.stream_a","op":"contains_all","values":[{"kind":"string","value":"tail-a"}]},
        {"kind":"predicate","field":"custom.stream_b","op":"contains_any","values":[{"kind":"string","value":"tail-b"}]}
    ]}});
    let group = Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    let created=ok(&mut browser,&fixture.router,Method::POST,&group_path,Some(request(0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"stream","description":""},"criteria":condition.clone()})))).await?;
    crate::test_support::http::await_task(
        &mut browser,
        &fixture.router,
        created["statusUrl"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("group definition task URL: {created}"))?,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let group = ok(
                &mut browser,
                &fixture.router,
                Method::GET,
                &group_path,
                None,
            )
            .await?;
            if group["group"]["memberCount"] == 1 {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let mut compliance = definition(json!({"kind":"all"}));
    compliance["criteria"] = condition;
    ok(
        &mut browser,
        &fixture.router,
        Method::PUT,
        &format!("/api/v1/compliance-rules/{}", Uuid::new_v4()),
        Some(request(0, compliance)),
    )
    .await?;
    let assessed = status(&mut browser, &fixture.router, "compliance-a", "compliant").await?;
    ensure!(
        assessed["rules"][0]["current"]["evidence"]
            .as_array()
            .is_some_and(|v| v.len() == 2)
    );
    crate::test_support::runtime::stop_worker(worker).await?;
    fixture.close().await;
    Ok(())
}
