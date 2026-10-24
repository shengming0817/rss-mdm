use crate::audit_test_support::audit_count;
use crate::test_support::{agent::*, http::*, process::*, runtime::*, *};
use anyhow::Context;
const PATH: &str = "/api/v1/runtime/diagnostics";

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real host wiring, session, permission and audit"]
async fn runtime_diagnostics_requires_explicit_permission() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            let (router, app_resources) = app(&fixture.base).await?;
            app_resources
                .finish(async {
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
                    ensure!(
                        member.call(&router, Method::GET, PATH, None).await?.0
                            == StatusCode::FORBIDDEN
                    );
                    set_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
                    let before = audit_count(|r| {
                        r.action() == "runtime_diagnostics_read"
                            && r.status() == 200
                            && r.actor() == Some(subject.as_str())
                    })
                    .await?;
                    let (status, value) = member.call(&router, Method::GET, PATH, None).await?;
                    ensure!(status == StatusCode::OK, "{status} {value}");
                    ensure!(value.as_object().unwrap().len() == 4);
                    ensure!(value["alive"] == true && value["ready"].is_boolean());
                    names(
                        &value["components"],
                        &[
                            "inventory",
                            "audit_source",
                            "audit_projection",
                            "identity_audit",
                            "automation",
                            "execution_recovery",
                        ],
                    )?;
                    ensure!(
                        audit_count(|r| r.action() == "runtime_diagnostics_read"
                            && r.status() == 200
                            && r.actor() == Some(subject.as_str()))
                        .await?
                            == before + 1
                    );
                    set_management_grants(&subject, json!([])).await?;
                    ensure!(
                        member.call(&router, Method::GET, PATH, None).await?.0
                            == StatusCode::FORBIDDEN
                    );

                    Ok(())
                })
                .await
        })
        .await
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
                inventory.clone(),
                authority.audit.clone(),
                authority.identity.tenant,
                Arc::new(crate::clock::SystemClock),
                None,
                |r| resources.push(r),
            )
            .await?;
        let execution = crate::execution_assembly::open(
            &config,
            config.native_protector()?,
            authority.audit.clone(),
            None,
            Default::default(),
            rss_device_command_postgres::CommandClock::Postgres,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    authority.identity.authority.clone(),
                    authority.identity.tenant,
                ),
            ),
        )
        .await?;
        let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            authority.pool.clone(),
            authority.audit.clone(),
            vec![],
            execution.providers.clone(),
        ));
        let source = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
            audit_store: authority.audit.clone(),
            mdm_audit: Default::default(),
            management_tenant: authority.identity.management_tenant,
            channels: execution.channels.clone(),
            pki: pki.clone(),
            registration: Arc::new(crate::registration_channels::Channels {
                preparation: execution.channels.clone(),
                windows: None,
                agent: None,
                apple: None,
                pki: pki.clone(),
                clock: Arc::new(crate::clock::SystemClock),
            }),
            apple_store: Arc::new(rss_mdm_apple_channel::Store::from_pool(
                authority.pool.clone(),
                authority.registration.clone(),
                authority.authorization.clone(),
            )),
            access: authority.pool.clone(),
            telemetry: None,
            execution: execution.service,
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
        rss_mdm_execution_service::Resource(self.source.execution.clone())
            .shutdown()
            .await?;
        for resource in self.resources {
            resource.shutdown().await?;
        }
        self.authority.resources.finish(async { Ok(()) }).await
    }
}
fn names(value: &Value, expected: &[&str]) -> Result<()> {
    let items = value
        .as_array()
        .context("diagnostic collection must be an array")?;
    let actual: std::collections::BTreeSet<_> =
        items.iter().map(|item| item["name"].as_str()).collect();
    ensure!(items.len() == expected.len());
    ensure!(actual == expected.iter().map(|name| Some(*name)).collect());
    Ok(())
}
const AUTOMATION_QUEUES: &[&str] = &[
    "pending",
    "running",
    "completed",
    "failed",
    "superseded",
    "asset_changes_pending",
];

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
#[ignore = "make t2 MODULE=diagnostics.http: isolated execution connection failure and recovery"]
async fn execution_first_scan_failure_recovers_only_after_real_success() -> Result<()> {
    let fixture = Fixture::open().await?;
    let initial = component(&fixture.query().await?, "execution_recovery");
    ensure!(initial["readiness"] == "not_ready" && initial["task"] == "unknown");
    let signals = Arc::new(rss_mdm_execution_service::worker_wake::Signals::default());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    // This case has an exclusive fault instance, so connection capacity can be restricted without disturbing other cases.
    pg(
        "ALTER ROLE mdm_command_runtime CONNECTION LIMIT 0; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='mdm_command_runtime'",
    )?;
    let result = async {
        let mut launch = stack.startup()?.commit();
        launch.stage_deferred_task_with_token(
            fixture
                .source
                .execution
                .clone()
                .registration(signals.clone()),
        );
        launch.finish();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let state = fixture.source.execution.health();
                if matches!(
                    state.recovery,
                    rss_mdm_execution_service::health::Phase::Failed(_)
                ) {
                    ensure!(
                        state.task == Some(rss_runtime::TaskState::Running) && !state.is_ready()
                    );
                    let failed = component(&fixture.query().await?, "execution_recovery");
                    ensure!(failed["readiness"] == "not_ready" && failed["health"] == "degraded");
                    break Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("execution recovery did not report the first failed scan")??;
        pg("ALTER ROLE mdm_command_runtime CONNECTION LIMIT -1")?;
        signals.command_recovery().notify_one();
        signals.command_relay().notify_one();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let state = component(&fixture.query().await?, "execution_recovery");
                if state["readiness"] == "ready" {
                    ensure!(state["task"] == "running" && state["health"] == "healthy");
                    break Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("execution recovery did not become ready after restoring connections")??;
        use sqlx::Connection;
        let mut administrator =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let mut blocked = administrator.begin().await?;
        sqlx::query("LOCK TABLE rss_reconcile.targets IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocked)
            .await?;
        signals.command_recovery().notify_one();
        let failed = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let state = fixture.source.execution.health();
                // The timer can win (Deadline), or PostgreSQL can report its lock/statement
                // timeout first (Transient). Both are failed scans, never readiness evidence.
                if matches!(
                    state.recovery,
                    rss_mdm_execution_service::health::Phase::Failed(
                        rss_reconcile::ErrorKind::Deadline | rss_reconcile::ErrorKind::Transient
                    )
                ) {
                    ensure!(
                        state.task == Some(rss_runtime::TaskState::Running) && !state.is_ready()
                    );
                    let value = serde_json::to_value(
                        fixture
                            .source
                            .collect(monotonic().now() + Duration::from_secs(1), false)
                            .await,
                    )?;
                    let observed = component(&value, "execution_recovery");
                    ensure!(
                        observed["readiness"] == "not_ready" && observed["health"] == "degraded"
                    );
                    break Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        blocked.rollback().await?;
        failed.context("execution recovery did not report the blocked scan failure")??;
        signals.command_recovery().notify_one();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if fixture.source.execution.health().is_ready() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    pg("ALTER ROLE mdm_command_runtime CONNECTION LIMIT -1")?;
    let clean = stack.shutdown().join().await?.is_clean();
    ensure!(!fixture.source.execution.health().is_ready());
    fixture.close().await?;
    result?;
    ensure!(clean);
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: independent runner connection failure and recovery"]
async fn runner_failure_is_visible_while_bridge_and_queries_succeed() -> Result<()> {
    use rss_mdm_management_http::runtime_diagnostics::Source;
    use rss_runtime::ManagedResource;
    let fixture = Fixture::open().await?;
    let config: Config = serde_json::from_value(fixture.authority.base.clone())?;
    let role = format!("diag_runner_{}", Uuid::new_v4().simple());
    pg(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'diagnostic-fixture' IN ROLE mdm_flow_runtime"
    ))?;
    let automation = crate::automation::Automation::connect(
        fixture.flow.planning.clone(),
        fixture.flow.assets.clone(),
        fixture.flow.compliance.clone(),
        config
            .flow
            .storage
            .database
            .options()?
            .username(&role)
            .password("diagnostic-fixture")
            .application_name(&role),
    )
    .await?;
    let signals = Arc::new(rss_mdm_flow_service::worker_wake::Signals::default());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(
        automation.clone().registration(signals.clone()).critical(),
    );
    launch.finish();
    let router = fixture.authority.router(
        fixture.authority.authorization().merge(
            Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::runtime_diagnostics::routes()
                    .with_state(fixture.source.clone() as Arc<dyn Source>)
                    .into_axum(),
            ),
        ),
    )?;
    let mut browser = fixture.authority.browser("other")?;
    let subject = browser_subject(&browser, &router).await?;
    set_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
    let result = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if component(&fixture.query().await?, "automation")["bridge"]["successful"] == true {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        pg(&format!("ALTER ROLE {role} CONNECTION LIMIT 0; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='{role}'"))?;
        signals.automation().notify_one();
        let failed = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let component = component(&fixture.query().await?,"automation");
                if component["health"] == "degraded" {break Ok::<_,anyhow::Error>(component);}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        ensure!(failed["task"] == "running" && failed["bridge"]["successful"] == true);
        ensure!(failed["runner"]["scan"]["successful"] == false && failed["runner"]["scan"]["observedAt"].is_number());
        let (status, value) = browser.call(&router, Method::GET, PATH, None).await?;
        ensure!(status == StatusCode::OK && component(&value,"automation")["health"] == "degraded");
        let encoded = value.to_string();
        ensure!(!encoded.contains(&role) && !encoded.contains("diagnostic-fixture") && !encoded.contains("job:"));
        ensure!(failed["dependencies"][0]["state"] == "available");
        names(&failed["queues"], AUTOMATION_QUEUES)?;
        ensure!(failed["queues"].as_array().unwrap().iter().all(|q|q["count"].is_number()));
        pg(&format!("ALTER ROLE {role} CONNECTION LIMIT -1"))?;
        signals.automation().notify_one();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let recovered = component(&fixture.query().await?,"automation");
                if recovered["health"] == "healthy" {
                    ensure!(recovered["runner"]["scan"]["successful"] == true);
                    break Ok::<_,anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        pg("REVOKE INSERT ON mdm_assets.asset_query_results FROM mdm_flow_runtime")?;
        let job = crate::planning::test_support::query_job(&fixture.flow.planning, 1).await;
        signals.automation().notify_one();
        signals.automation_input().notify_one();
        let failed_attempt = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let value = component(&fixture.query().await?, "automation");
                if value["runner"]["unresolvedAttempts"] == 1 {
                    break Ok::<_, anyhow::Error>(value);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        ensure!(failed_attempt["task"] == "running" && failed_attempt["health"] == "degraded");
        ensure!(failed_attempt["runner"]["scan"]["successful"] == true);
        ensure!(failed_attempt["runner"]["latestFailure"]["stage"] == "apply");
        ensure!(failed_attempt["bridge"]["successful"] == true);
        pg("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_flow_runtime")?;
        signals.automation().notify_one();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let value = component(&fixture.query().await?, "automation");
                if value["health"] == "healthy" && value["runner"]["unresolvedAttempts"] == 0 {
                    ensure!(pg(&format!("SELECT completed FROM mdm_automation.automation_jobs WHERE id='{job}'"))?.trim() == "t");
                    ensure!(value["runner"]["latestFailure"].is_null());
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        Ok::<_,anyhow::Error>(())
    }.await;
    pg("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_flow_runtime")?;
    pg(&format!("ALTER ROLE {role} CONNECTION LIMIT -1"))?;
    let clean = stack.shutdown().join().await?.is_clean();
    crate::automation::Resource(automation).shutdown().await?;
    pg(&format!("DROP ROLE {role}"))?;
    fixture.close().await?;
    result?;
    ensure!(clean);
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real runtime pool failure, binding, authorization and deadline"]
async fn dependency_failure_preserves_partial_results_and_authority() -> Result<()> {
    use rss_mdm_management_http::runtime_diagnostics::Source;
    let fixture = Fixture::open().await?;
    let router = fixture.authority.router(
        fixture.authority.authorization().merge(
            Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::runtime_diagnostics::routes()
                    .with_state(fixture.source.clone() as Arc<dyn Source>)
                    .into_axum(),
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
    names(&automation["queues"], AUTOMATION_QUEUES)?;
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
    names(
        &component(&expired, "inventory")["dependencies"],
        &["inventory_delivery", "observation_journal"],
    )?;
    ensure!(
        component(&expired, "inventory")["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["reason"] == "deadline")
    );
    for (tenant, instance) in [
        (
            rss_request_context::TenantId::parse(case::peer())?,
            INSTANCE,
        ),
        (fixture.authority.identity.tenant, "wrong-instance"),
    ] {
        ensure!(matches!(
            fixture.source.snapshot(tenant, instance, past).await,
            Err(rss_mdm_management_http::Error::Forbidden)
        ));
    }
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
    ensure!(
        component(&fixture.query().await?, "automation")["queues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|q| q["name"] == "pending")
            .context("missing pending queue")?["count"]
            == 0
    );
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
        fixture.authority.registration.clone(),
        case_tenant().into(),
        fixture.authority.audit.clone(),
    );
    let operator = admin(case_tenant(), "admin-a").await?;
    let credential = proof(case_tenant(), Channel::Mdm, 234);
    bind(&service, &operator, &credential, "diagnostic-device", 0).await?;
    let report = crate::inventory_runtime::test_support::report(
        &service,
        &fixture.authority.audit,
        &credential,
        [Some("safe-name"), Some("10")],
    )
    .await?;
    let before = fixture.query().await?;
    ensure!(component(&before, "inventory")["queues"][0]["count"] == 1);
    ensure!(component(&before, "inventory")["progress"]["state"] == "unobserved");
    let reports = crate::collection::store::Delivery::new(
        Arc::new(rss_mdm_inventory_service::Store::from_pool(
            fixture.authority.pool.clone(),
        )),
        fixture.authority.audit.clone(),
    )
    .pending_reports(case_tenant())
    .await?;
    let durable = reports
        .iter()
        .find(|r| r.batch().id().as_str() == report.id.to_string())
        .unwrap();
    // Delivery worker is bypassed here; the inventory projection worker below remains real.
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
    let audit = crate::identity_audit::Worker::open(
        &config,
        fixture.source.identity_audit.clone(),
        Arc::default(),
        |r| startup.stage_resource(r),
    )
    .await?;
    let automation = crate::automation::Automation::connect(
        fixture.flow.planning.clone(),
        fixture.flow.assets.clone(),
        fixture.flow.compliance.clone(),
        config.flow.storage.database.options()?,
    )
    .await?;
    let signals = Arc::new(rss_mdm_flow_service::worker_wake::Signals::default());
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(audit.registration().critical());
    launch.stage_deferred_task_with_token(
        automation.clone().registration(signals.clone()).critical(),
    );
    launch.stage_deferred_task_with_token(
        fixture
            .source
            .execution
            .clone()
            .registration(Arc::new(
                rss_mdm_execution_service::worker_wake::Signals::default(),
            ))
            .critical(),
    );
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
        ensure!(component(&projected,"automation")["bridge"]["successful"] == true);
        let suspend = format!("INSERT INTO mdm_planning.asset_dispatch(tenant_id,failure) VALUES('{}','automation_suspended') ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure", case_tenant());
        tokio::task::spawn_blocking(move || pg(&suspend)).await??;
        let suspended = component(&fixture.query().await?,"automation");
        ensure!(suspended["task"] == "running" && suspended["bridge"]["successful"] == true);
        ensure!(suspended["readiness"] == "not_ready" && suspended["health"] == "degraded");
        ensure!(suspended["reasons"].as_array().unwrap().contains(&json!("automation_suspended")));
        let resume = format!("UPDATE mdm_planning.asset_dispatch SET failure=NULL WHERE tenant_id='{}'", case_tenant());
        tokio::task::spawn_blocking(move || pg(&resume)).await??;
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
                    .with_state((fixture.source.clone(), monotonic(), crate::setup::host::Observation::new(&serde_json::from_value(fixture.authority.base["runtime_binding"].clone())?,case_tenant().into(),fixture.source.instance.clone()))),
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

#[tokio::test]
#[ignore = "MODULE=diagnostics.http: management capacity affects host admission without exposing its counters"]
async fn management_audit_capacity_is_visible_without_cross_tenant_counts() -> Result<()> {
    use rss_mdm_audit_integration::{AuditStore, BacklogLimits, Fact, RequestAudit};
    use rss_request_context::TenantId;
    let mut fixture = Fixture::open().await?;
    let own = fixture.authority.identity.tenant;
    let management = TenantId::parse(crate::test_support::case::peer())?;
    let pool = fixture.authority.pool.clone();
    let runtime = crate::audit_test_support::source_runtime(&pool, own).await?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(20));
    let store = Arc::new(
        AuditStore::new(
            pool,
            rss_audit_postgres::Integrity::Plain,
            runtime.clone(),
            own,
            BacklogLimits::new(1, 1_000_000)?,
            &budget.control(),
        )
        .await?,
    );
    let source = Arc::get_mut(&mut fixture.source).expect("unshared diagnostics fixture");
    source.audit_store = store.clone();
    source.management_tenant = management;
    let request = RequestAudit::new(management.to_string(), "capacity_test");
    let fact = Fact::business(
        &request,
        "management-capacity",
        b"management",
        200,
        "success",
        None,
    )?;
    let attempt = store
        .write(
            management,
            &budget.source_control(),
            (&store, &fact),
            |(store, fact), tx| Box::pin(async move { store.append(tx, fact, false).await }),
        )
        .await;
    ensure!(attempt.fold(
        |_| true,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    let value = fixture.query().await?;
    let audit = component(&value, "audit_source");
    ensure!(audit["readiness"] == "not_ready" && audit["health"] == "degraded");
    ensure!(
        audit["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("audit_backpressure"))
    );
    ensure!(
        audit["auditBacklog"]["events"] == 0,
        "management counters leaked"
    );
    crate::audit_test_support::projection::drain(management, rss_audit_postgres::Integrity::Plain)
        .await?;
    let value = fixture.query().await?;
    ensure!(component(&value, "audit_source")["readiness"] == "ready");
    request.finalize(None);
    runtime.close().await;
    fixture.close().await?;
    Ok(())
}
