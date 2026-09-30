use crate::test_support::*;
const PATH: &str = "/api/v2/runtime/diagnostics";

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real host wiring, session, permission and audit"]
async fn runtime_diagnostics_requires_explicit_permission() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let reader = authority::reader(&fixture.base).await?;
    let router = app(&fixture.base, reader.clone()).await?;
    ensure!(
        Browser::default()
            .call(&router, Method::GET, PATH, None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let mut member = fixture.browser("other")?;
    let subject = browser_subject(&member, &router).await?;
    set_management_grants(&subject, json!(["authorization_read"])).await?;
    ensure!(member.call(&router, Method::GET, PATH, None).await?.0 == StatusCode::FORBIDDEN);
    set_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
    let (status, value) = member.call(&router, Method::GET, PATH, None).await?;
    ensure!(status == StatusCode::OK, "{status} {value}");
    ensure!(value.as_object().unwrap().len() == 3);
    ensure!(value["alive"] == true && value["ready"].is_boolean());
    ensure!(
        value["components"]
            .as_array()
            .is_some_and(|items| items.len() >= 4)
    );
    ensure!(audit_count(|r| r.action() == "runtime_diagnostics_read" && r.status() == 200)? > 0);
    set_management_grants(&subject, json!([])).await?;
    ensure!(member.call(&router, Method::GET, PATH, None).await?.0 == StatusCode::FORBIDDEN);
    reader.close().await;
    Ok(())
}

struct Fixture {
    authority: authority::Authority,
    source: Arc<crate::runtime_diagnostics::RuntimeDiagnostics>,
    flow: Arc<crate::flow::Flow>,
    resources: Vec<crate::flow::Resource>,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let authority = authority::Authority::open().await?;
        let config: Config = serde_json::from_value(authority.base.clone())?;
        let inventory = agent_runtime(&authority.base).await?;
        let mut resources = Vec::new();
        let flow = config
            .flow
            .open(
                authority.audit.clone(),
                authority.identity.tenant,
                Arc::new(crate::clock::SystemClock),
                |r| resources.push(r),
            )
            .await?;
        let source = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
            inventory,
            planning: flow.planning.clone(),
            identity_audit: authority.identity.audit_readiness.clone(),
            apple: None,
            clock: Arc::new(crate::clock::SystemClock),
            tenant: authority.identity.tenant,
            instance: INSTANCE.into(),
        });
        Ok(Self {
            authority,
            source,
            flow,
            resources,
        })
    }
    async fn query(&self) -> Result<Value> {
        Ok(serde_json::to_value(
            self.source
                .collect(monotonic().now() + Duration::from_secs(5), true)
                .await,
        )?)
    }
    async fn close(self) -> Result<()> {
        use rss_runtime::ManagedResource;
        self.source.inventory.close_fixture().await?;
        for resource in self.resources {
            resource.shutdown().await?;
        }
        Ok(())
    }
}
fn component(value: &Value, name: &str) -> Value {
    value["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
        .clone()
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real runtime pool failure, binding, authorization and deadline"]
async fn dependency_failure_preserves_partial_results_and_authority() -> Result<()> {
    use rss_mdm_management_http::runtime_diagnostics::Source;
    let fixture = Fixture::open().await?;
    let router = fixture.authority.router(
        fixture.authority.authorization().merge(
            Router::new().nest(
                "/api/v2",
                rss_mdm_management_http::runtime_diagnostics::routes()
                    .with_state(fixture.source.clone() as Arc<dyn Source>),
            ),
        ),
    )?;
    let mut browser = fixture.authority.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
    let healthy = fixture.query().await?;
    ensure!(component(&healthy, "automation")["dependencies"][0]["state"] == "available");
    fixture.flow.runtime.close().await;
    let (status, value) = browser.call(&router, Method::GET, PATH, None).await?;
    ensure!(status == StatusCode::OK);
    let automation = component(&value, "automation");
    ensure!(automation["dependencies"][0]["state"] == "unavailable");
    ensure!(automation["health"] == "degraded");
    ensure!(
        automation["queues"]
            .as_array()
            .unwrap()
            .iter()
            .all(|q| q["count"].is_null())
    );
    ensure!(component(&value, "inventory")["queues"][0]["count"] == 0);
    ensure!(value["ready"] == false);
    let past = monotonic().now() - Duration::from_secs(1);
    let expired = fixture.source.collect(past, true).await;
    let expired = serde_json::to_value(expired)?;
    ensure!(
        component(&expired, "inventory")["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["reason"] == "deadline")
    );
    ensure!(
        fixture
            .source
            .snapshot(
                rss_request_context::TenantId::parse(case::peer())?,
                INSTANCE,
                past
            )
            .await
            .is_err()
    );
    ensure!(
        fixture
            .source
            .snapshot(fixture.authority.identity.tenant, "wrong-instance", past)
            .await
            .is_err()
    );
    let text = value.to_string();
    for secret in [
        PASSWORD,
        "runtime-fixture",
        "postgres",
        fixture.authority.base["access_database"]["password_file"]
            .as_str()
            .unwrap(),
    ] {
        ensure!(!text.contains(secret), "diagnostics exposed an input");
    }
    fixture.close().await
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real retained jobs, bounded counting and tenant isolation"]
async fn durable_backlog_is_distinct_from_storage_failure_and_is_bounded() -> Result<()> {
    let fixture = Fixture::open().await?;
    let own = case_tenant();
    let peer = case::peer();
    pg_tenant(
        peer,
        &format!(
            "INSERT INTO mdm_automation.automation_jobs(tenant_id,id,kind,target,input,completed,forwarded) SELECT '{peer}',gen_random_uuid(),'group','secret-peer-task','{{}}',false,false FROM generate_series(1,17)"
        ),
    )?;
    pg(&format!(
        "INSERT INTO mdm_automation.automation_jobs(tenant_id,id,kind,target,input,completed,forwarded) SELECT '{own}',gen_random_uuid(),'group','secret-task-input','{{}}',true,true FROM generate_series(1,1001); INSERT INTO mdm_automation.automation_jobs(tenant_id,id,kind,target,input,completed,forwarded) VALUES('{own}',gen_random_uuid(),'group','secret-task-input','{{}}',false,false)"
    ))?;
    let value = fixture.query().await?;
    let state = component(&value, "automation");
    let queues = state["queues"].as_array().unwrap();
    ensure!(queues.iter().find(|q| q["name"] == "pending").unwrap()["count"] == 1);
    let completed = queues.iter().find(|q| q["name"] == "completed").unwrap();
    ensure!(completed["count"] == 1000 && completed["truncated"] == true);
    ensure!(state["dependencies"][0]["state"] == "available");
    ensure!(state["task"] == "unknown");
    ensure!(
        !value.to_string().contains("secret-task") && !value.to_string().contains("secret-peer")
    );
    pg(&format!(
        "UPDATE mdm_automation.automation_jobs SET completed=true WHERE tenant_id='{own}' AND NOT completed"
    ))?;
    ensure!(component(&fixture.query().await?, "automation")["queues"][0]["count"] == 0);
    fixture.close().await
}

#[tokio::test]
#[cfg(feature = "integration")]
#[ignore = "make t2 MODULE=diagnostics.http: actual workers, durable report, projection and stop"]
async fn actual_worker_progress_and_readiness_share_the_same_projection() -> Result<()> {
    use crate::device::{
        DeviceService,
        test_support::{admin, bind, proof},
    };
    use rss_mdm_inventory::Channel;
    use rss_runtime::ManagedResource;
    let fixture = Fixture::open().await?;
    let service = DeviceService::new(
        fixture.authority.access.registration(),
        case_tenant().into(),
        fixture.authority.audit.clone(),
    );
    let operator = admin(case_tenant(), "admin-a").await?;
    let credential = proof(case_tenant(), Channel::Mdm, 234);
    bind(&service, &operator, &credential, "diagnostic-device", 0).await?;
    let report = crate::inventory_runtime::test_support::report(
        &service,
        &fixture.authority.access,
        &credential,
        [Some("safe-name"), Some("10")],
    )
    .await?;
    let before = fixture.query().await?;
    ensure!(component(&before, "inventory")["queues"][0]["count"] == 1);
    ensure!(component(&before, "inventory")["progress"]["state"] == "unobserved");
    let reports = crate::collection::store::Delivery::new(
        fixture.authority.access.inventory(),
        fixture.authority.audit.clone(),
    )
    .pending_reports(case_tenant())
    .await?;
    let durable = reports
        .iter()
        .find(|r| r.batch().id().as_str() == report.id.to_string())
        .unwrap();
    fixture.source.inventory.fixture_deliver(durable).await?;
    let delayed = component(&fixture.query().await?, "inventory");
    ensure!(delayed["queues"][0]["count"] == 0 && delayed["progress"]["sourceHead"].is_number());
    ensure!(delayed["progress"]["state"] == "unobserved");
    ensure!(
        fixture.source.inventory.inspect(&report).await?.projection
            == crate::inventory_runtime::ProjectionStatus::Pending
    );
    let config: Config = serde_json::from_value(fixture.authority.base.clone())?;
    let wake = Arc::new(tokio::sync::Notify::new());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    let audit =
        crate::identity_audit::Worker::open(&config, fixture.source.identity_audit.clone(), |r| {
            startup.stage_resource(r)
        })
        .await?;
    let automation = crate::automation::Automation::connect(
        fixture.flow.planning.clone(),
        fixture.flow.assets.clone(),
        config.flow.storage.database.options()?,
    )
    .await?;
    let signals = Arc::new(rss_mdm_flow_service::worker_wake::Signals::default());
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(audit.registration().critical());
    launch.stage_deferred_task_with_token(automation.clone().registration(signals).critical());
    launch.stage_deferred_task_with_token(
        fixture
            .source
            .inventory
            .clone()
            .registration(wake.clone())
            .critical(),
    );
    launch.finish();
    let result = async {
        let projected = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let value = fixture.query().await?;
                if value["ready"] == true
                    && fixture.source.inventory.inspect(&report).await?.projection
                        == crate::inventory_runtime::ProjectionStatus::Projected
                {
                    break Ok::<_, anyhow::Error>(value);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        let inventory = component(&projected, "inventory");
        ensure!(
            inventory["task"] == "running"
                && inventory["progress"]["confirmedPosition"].is_number()
        );
        ensure!(inventory["queues"][0]["count"] == 0 && inventory["progress"]["lagging"] == false);
        ensure!(component(&projected,"automation")["lastRun"]["successful"] == true);
        pg(&format!("INSERT INTO mdm_planning.asset_dispatch(tenant_id,failure) VALUES('{}','automation_suspended') ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure",case_tenant()))?;
        let suspended = component(&fixture.query().await?,"automation");
        ensure!(suspended["task"] == "running" && suspended["lastRun"]["successful"] == true);
        ensure!(suspended["readiness"] == "not_ready" && suspended["health"] == "degraded");
        ensure!(suspended["reasons"].as_array().unwrap().contains(&json!("automation_suspended")));
        pg(&format!("UPDATE mdm_planning.asset_dispatch SET failure=NULL WHERE tenant_id='{}'",case_tenant()))?;
        let expired = serde_json::to_value(
            fixture
                .source
                .collect(monotonic().now() - Duration::from_secs(1), true)
                .await,
        )?;
        let expired_inventory = component(&expired, "inventory");
        ensure!(
            expired_inventory["readiness"] == "ready" && expired_inventory["health"] == "degraded"
        );
        let response = Router::new()
            .route(
                "/readyz",
                axum::routing::get(crate::api::ready)
                    .with_state((fixture.source.clone(), monotonic())),
            )
            .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
            .await?;
        ensure!(response.status() == StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024).await?;
        ensure!(serde_json::from_slice::<Value>(&body)?["ready"] == projected["ready"]);
        fixture
            .source
            .inventory
            .fixture_projection_fault(rss_projection_postgres::PgFault::CommitPending);
        wake.notify_one();
        let pending = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let inventory = component(&fixture.query().await?, "inventory");
                if inventory["progress"]["state"] == "pending" {
                    break Ok::<_, anyhow::Error>(inventory);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        ensure!(
            pending["progress"]["completedPassAgeMs"].is_number(),
            "new invocation discarded last completed pass"
        );
        ensure!(pending["health"] == "unknown" && pending["readiness"] == "ready");
        fixture.source.inventory.readiness.stop();
        ensure!(fixture.query().await?["ready"] == false);
        let exit = tokio::time::timeout(
            Duration::from_secs(10),
            fixture.source.inventory.fixture_wait_stopped(),
        )
        .await?;
        ensure!(matches!(exit, rss_runtime::TaskExit::Failed(_)));
        fixture.source.inventory.close_fixture().await?;
        let failed = component(&fixture.query().await?, "inventory");
        ensure!(failed["task"] == "failed" && failed["readiness"] == "not_ready");
        ensure!(failed["dependencies"][1]["state"] == "unavailable");
        ensure!(failed["health"] == "degraded");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    ensure!(!stack.shutdown().join().await?.is_clean());
    crate::automation::Resource(automation).shutdown().await?;
    ensure!(component(&fixture.query().await?, "inventory")["task"] == "failed");
    fixture.close().await?;
    result
}
