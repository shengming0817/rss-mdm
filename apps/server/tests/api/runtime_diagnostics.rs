use crate::audit_test_support::audit_count;
use crate::test_support::{agent::*, http::*, runtime::*, *};
use anyhow::Context;
use sqlx::Connection;
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
                    let subject = prepared_subject(&member)?;
                    seed_management_grants(&subject, json!(["authorization_read"])).await?;
                    ensure!(
                        member.call(&router, Method::GET, PATH, None).await?.0
                            == StatusCode::FORBIDDEN
                    );
                    change_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
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
                        &["inventory", "automation", "execution_recovery"],
                    )?;
                    ensure!(
                        audit_count(|r| r.action() == "runtime_diagnostics_read"
                            && r.status() == 200
                            && r.actor() == Some(subject.as_str()))
                        .await?
                            == before
                    );
                    change_management_grants(&subject, json!([])).await?;
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
    planning: Arc<crate::planning::test_support::OwnerFixture>,
    groups: Arc<rss_mdm_inventory_service::groups::Groups>,
    scope_group_health: Arc<crate::scope_group_changes::Health>,
    #[cfg(feature = "integration")]
    device_worker: Arc<rss_mdm_device_service::worker::DeviceWork>,
    resources: Resources,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let mut authority = authority::Authority::open().await?;
        let config: Config = serde_json::from_value(authority.base.clone())?;
        let inventory = agent_runtime(&authority).await?;
        let planning =
            Arc::new(crate::planning::test_support::planning(authority.identity.tenant).await);
        let inventory_services = crate::assembly::inventory::Services::new(
            inventory.clone(),
            planning.inventory.runtime.clone(),
            planning.inventory.audit.clone(),
            authority.identity.tenant,
            &planning.cursor_key,
            Arc::new(crate::clock::SystemClock),
        )
        .await?;
        let groups = inventory_services.groups.clone();
        let scope_group_health = Arc::new(crate::scope_group_changes::Health::default());
        let execution = crate::assembly::execution::open(
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
            vec![1; 32],
        )
        .await?;
        let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            authority.pool.clone(),
            authority.audit.clone(),
            vec![],
            execution.providers.clone(),
        ));
        let (device_pool, device_runtime, device_audit) =
            crate::audit_test_support::request_store().await?;
        let device_owner = crate::test_support::device_worker::DeviceOwner::new(
            device_audit,
            device_runtime.clone(),
            authority.identity.tenant,
        )
        .await?;
        let source = Arc::new(crate::runtime_diagnostics::RuntimeDiagnostics {
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
            planning: planning.policy.clone(),
            devices: device_owner.service.clone(),
            scopes: crate::planning::test_support::scopes(&planning).await,
            groups: groups.clone(),
            assets: inventory_services.assets,
            compliance: inventory_services.compliance,
            scope_group_health: scope_group_health.clone(),
            apple: None,
            clock: Arc::new(crate::clock::SystemClock),
            tenant: authority.identity.tenant,
            instance: INSTANCE.into(),
        });
        let mut cleanup = std::mem::take(&mut authority.resources);
        cleanup.resource(PoolResource(device_pool));
        cleanup.resource(SourceResource(device_runtime));
        cleanup.resource(device_owner.scheduler.clone());
        cleanup.resource(crate::planning::test_support::OwnerResource(
            planning.clone(),
        ));
        cleanup.resource(rss_mdm_execution_service::Resource(
            source.execution.clone(),
        ));
        cleanup.resource(InventoryFixtureResource(source.inventory.clone()));
        Ok(Self {
            authority,
            source,
            planning,
            groups,
            scope_group_health,
            #[cfg(feature = "integration")]
            device_worker: device_owner.work,
            resources: cleanup,
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
        self.finish(Ok(())).await
    }
    async fn finish(self, result: Result<()>) -> Result<()> {
        self.resources.finish(async { result }).await
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
    "execution_inputs_pending",
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
    let mut fixture = Fixture::open().await?;
    let administrator_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    fixture
        .resources
        .resource(PoolResource(administrator_pool.clone()));
    let initial = component(&fixture.query().await?, "execution_recovery");
    ensure!(initial["readiness"] == "not_ready" && initial["task"] == "unknown");
    let signals = Arc::new(rss_mdm_execution_service::worker_wake::Signals::default());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    // This case has an exclusive fault instance, so connection capacity can be restricted without disturbing other cases.
    sqlx::raw_sql("ALTER ROLE mdm_command_runtime CONNECTION LIMIT 0; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='mdm_command_runtime'").execute(&administrator_pool).await?;
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
        sqlx::raw_sql("ALTER ROLE mdm_command_runtime CONNECTION LIMIT -1")
            .execute(&administrator_pool)
            .await?;
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
    let restored = sqlx::raw_sql("ALTER ROLE mdm_command_runtime CONNECTION LIMIT -1")
        .execute(&administrator_pool)
        .await;
    let receipt = stack.shutdown().join().await;
    let result = (|| {
        result.with_context(|| {
            format!("execution scenario failed; restore={restored:?}; drain={receipt:?}")
        })?;
        restored?;
        ensure!(receipt?.is_clean());
        ensure!(!fixture.source.execution.health().is_ready());
        Ok(())
    })();
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: independent runner connection failure and recovery"]
async fn runner_failure_is_visible_while_queries_succeed() -> Result<()> {
    use rss_mdm_management_http::runtime_diagnostics::Source;
    use rss_runtime::ManagedResource;
    let mut fixture = Fixture::open().await?;
    let administrator_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    fixture
        .resources
        .resource(PoolResource(administrator_pool.clone()));
    let config: Config = serde_json::from_value(fixture.authority.base.clone())?;
    // The registry gives this role-fault case exclusive ownership of its PG instance.
    let role = "diag_runner_fixture".to_owned();
    sqlx::raw_sql("CREATE ROLE diag_runner_fixture LOGIN PASSWORD 'diagnostic-fixture' IN ROLE mdm_scheduler_runtime")
    .execute(&administrator_pool)
    .await?;
    let automation = crate::test_support::workers::Workers::open(
        fixture.planning.policy.clone(),
        None,
        config
            .business_databases
            .scheduler
            .options()?
            .username(&role)
            .password("diagnostic-fixture")
            .application_name(&role),
    )
    .await?;
    fixture.resources.resource(automation.scheduler.clone());
    let scope_work = Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
        fixture.source.scopes.clone(),
        automation.scheduler.store.clone(),
    ));
    let group_work = Arc::new(rss_mdm_inventory_service::groups::runtime::GroupWork::new(
        fixture.groups.clone(),
        automation.scheduler.store.clone(),
    ));
    let scope_delivery = crate::scope_group_changes::Delivery::open(
        &config,
        config.native_protector()?,
        fixture.scope_group_health.clone(),
    )
    .await?;
    fixture
        .resources
        .resource(crate::scope_group_changes::Resource(scope_delivery.clone()));
    let signals = Arc::new(crate::worker_wake::Signals::default());
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    automation.register(&signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.stage_deferred_task_with_token(
        Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
            fixture.source.assets.clone(),
            automation.scheduler.store.clone(),
        ))
        .registration(Arc::new(tokio::sync::Notify::new()))
        .critical(),
    );
    launch.stage_deferred_task_with_token(
        Arc::new(
            rss_mdm_inventory_service::compliance::runtime::ComplianceWork::new(
                fixture.source.compliance.clone(),
                automation.scheduler.store.clone(),
            ),
        )
        .registration(Arc::new(tokio::sync::Notify::new()))
        .critical(),
    );
    launch.stage_deferred_task_with_token(
        group_work
            .registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        scope_work
            .registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
    #[cfg(feature = "integration")]
    launch.stage_deferred_task_with_token(
        fixture
            .device_worker
            .clone()
            .registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.finish();
    let router = fixture.authority.router(
        {
 rss_mdm_http_contract::route_module! { struct RunnerFailureIsVisibleWhileBridgeAndQueriesSucceedModule301 for [Browser] { base, module } }
 RunnerFailureIsVisibleWhileBridgeAndQueriesSucceedModule301 { base: fixture.authority.authorization(),
module: {
 rss_mdm_http_contract::route_module! { struct RunnerFailureIsVisibleWhileBridgeAndQueriesSucceedModule1 for [Browser] { api_v1 at "/api/v1" } }
 RunnerFailureIsVisibleWhileBridgeAndQueriesSucceedModule1 { api_v1: rss_mdm_management_http::runtime_diagnostics::routes()
                    .with_state(fixture.source.clone() as Arc<dyn Source>) }.assemble()
} }.assemble()
},
    )?;
    let mut browser = fixture.authority.browser("other")?;
    let subject = prepared_subject(&browser)?;
    seed_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
    let result = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if component(&fixture.query().await?, "automation")["runner"]["scan"]["successful"] == true {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("initial runner observation timed out")??;
        sqlx::raw_sql("ALTER ROLE diag_runner_fixture CONNECTION LIMIT 0; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='diag_runner_fixture'").execute(&administrator_pool).await?;
        signals.policy().automation().notify_one();
        signals.handle(crate::worker_wake::Work::CommandRecovery).notify_one();
        let failed = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let component = component(&fixture.query().await?,"automation");
                if component["health"] == "degraded" && component["runner"]["scan"]["successful"] == false {break Ok::<_,anyhow::Error>(component);}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("runner failure observation timed out")??;
        ensure!(failed["task"] == "running");
        ensure!(failed["runner"]["scan"]["successful"] == false && failed["runner"]["scan"]["observedAt"].is_number());
        let (status, value) = browser.call(&router, Method::GET, PATH, None).await?;
        ensure!(status == StatusCode::OK && component(&value,"automation")["health"] == "degraded");
        let encoded = value.to_string();
        ensure!(!encoded.contains(&role) && !encoded.contains("diagnostic-fixture") && !encoded.contains("job:"));
        ensure!(failed["dependencies"][0]["state"] == "available");
        names(&failed["queues"], AUTOMATION_QUEUES)?;
        ensure!(failed["queues"].as_array().unwrap().iter().all(|q|q["count"].is_number()));
        sqlx::raw_sql("ALTER ROLE diag_runner_fixture CONNECTION LIMIT -1").execute(&administrator_pool).await?;
        signals.policy().automation().notify_one();
        signals.handle(crate::worker_wake::Work::CommandRecovery).notify_one();
        // Terminating the pool can also lose a Finish acknowledgement. Recovery must
        // cover the 30s attempt lease, 6s work budget and 5s recovery scan interval.
        let mut last_recovery = Value::Null;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let recovered = component(&fixture.query().await?,"automation");
                last_recovery = recovered.clone();
                if recovered["health"] == "healthy" {
                    ensure!(recovered["runner"]["scan"]["successful"] == true);
                    break Ok::<_,anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.with_context(|| format!("runner recovery observation timed out: {last_recovery}"))??;
        sqlx::raw_sql("REVOKE INSERT ON mdm_assets.asset_query_results FROM mdm_inventory_runtime").execute(&administrator_pool).await?;
        let job=crate::planning::test_support::query_job(&fixture.planning,1).await;
        signals.policy().automation().notify_one();
        signals.handle(crate::worker_wake::Work::CommandRecovery).notify_one();
        signals.policy().automation().notify_one();
        signals.handle(crate::worker_wake::Work::Groups).notify_one();
        let failed_attempt = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let value = component(&fixture.query().await?, "automation");
                if value["runner"]["unresolvedAttempts"] == 1 {
                    break Ok::<_, anyhow::Error>(value);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("apply failure observation timed out")??;
        ensure!(failed_attempt["task"] == "running" && failed_attempt["health"] == "degraded");

        ensure!(failed_attempt["runner"]["latestFailure"]["stage"] == "apply");

        sqlx::raw_sql("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_inventory_runtime").execute(&administrator_pool).await?;
        signals.policy().automation().notify_one();
        signals.handle(crate::worker_wake::Work::CommandRecovery).notify_one();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let value = component(&fixture.query().await?, "automation");
                if value["health"] == "healthy" && value["runner"]["unresolvedAttempts"] == 0 {
                    ensure!(sqlx::query_scalar::<_,bool>("SELECT completed FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(job).fetch_one(&administrator_pool).await?);
                    ensure!(value["runner"]["latestFailure"].is_null());
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("apply recovery observation timed out")??;
        Ok::<_,anyhow::Error>(())
    }.await;
    let restored =
        sqlx::raw_sql("GRANT INSERT ON mdm_assets.asset_query_results TO mdm_inventory_runtime")
            .execute(&administrator_pool)
            .await;
    let connections = sqlx::raw_sql("ALTER ROLE diag_runner_fixture CONNECTION LIMIT -1")
        .execute(&administrator_pool)
        .await;
    let receipt = stack.shutdown().join().await;
    let closed = automation.scheduler.clone().shutdown().await;
    let dropped = sqlx::raw_sql("DROP ROLE diag_runner_fixture")
        .execute(&administrator_pool)
        .await;
    let result = (|| {
        result.with_context(|| format!("runner scenario failed; restore={restored:?}; connections={connections:?}; drain={receipt:?}; close={closed:?}; role={dropped:?}"))?;
        restored?;
        connections?;
        closed?;
        dropped?;
        ensure!(receipt?.is_clean());
        Ok(())
    })();
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=diagnostics.http: real runtime pool failure, binding, authorization and deadline"]
async fn dependency_failure_preserves_partial_results_and_authority() -> Result<()> {
    use rss_mdm_management_http::runtime_diagnostics::Source;
    let fixture = Fixture::open().await?;
    let router = fixture.authority.router(
        {
 rss_mdm_http_contract::route_module! { struct DependencyFailurePreservesPartialResultsAndAuthorityModule301 for [Browser] { base, module } }
 DependencyFailurePreservesPartialResultsAndAuthorityModule301 { base: fixture.authority.authorization(),
module: {
 rss_mdm_http_contract::route_module! { struct DependencyFailurePreservesPartialResultsAndAuthorityModule1 for [Browser] { api_v1 at "/api/v1" } }
 DependencyFailurePreservesPartialResultsAndAuthorityModule1 { api_v1: rss_mdm_management_http::runtime_diagnostics::routes()
                    .with_state(fixture.source.clone() as Arc<dyn Source>) }.assemble()
} }.assemble()
},
    )?;
    let mut browser = fixture.authority.browser("other")?;
    let subject = prepared_subject(&browser)?;
    seed_management_grants(&subject, json!(["runtime_diagnostics_read"])).await?;
    let healthy = fixture.query().await?;
    ensure!(component(&healthy, "automation")["dependencies"][0]["state"] == "available");
    fixture.planning.policy.runtime.close().await;
    let (status, value) = browser.call(&router, Method::GET, PATH, None).await?;
    ensure!(status == StatusCode::OK);
    let automation = component(&value, "automation");
    let dependencies = automation["dependencies"]
        .as_array()
        .context("automation dependencies")?;
    ensure!(
        dependencies
            .iter()
            .any(|d| d["name"] == "business_queues" && d["state"] == "unavailable")
    );
    ensure!(
        dependencies
            .iter()
            .any(|d| d["name"] == "command_storage" && d["state"] == "available"),
        "Policy failure must not change the independent Command probe"
    );
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
    let mut fixture = Fixture::open().await?;
    let administrator_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    fixture
        .resources
        .resource(PoolResource(administrator_pool.clone()));
    let own = case_tenant();
    let peer = case::peer();
    for (tenant, target, completed, count) in [
        (peer, "secret-peer-task", false, 17),
        (own, "secret-task-input", true, 1001),
        (own, "secret-task-input", false, 1),
    ] {
        sqlx::query("INSERT INTO mdm_policy.work(tenant_id,id,kind,target,input,completed,forwarded) SELECT $1::uuid,gen_random_uuid(),'policy_reconcile',$2,'{}',$3,$3 FROM generate_series(1,$4)")
            .bind(tenant).bind(target).bind(completed).bind(count).execute(&administrator_pool).await?;
    }
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
    sqlx::query(
        "UPDATE mdm_policy.work SET completed=true WHERE tenant_id=$1::uuid AND NOT completed",
    )
    .bind(own)
    .execute(&administrator_pool)
    .await?;
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
    let mut fixture = Fixture::open().await?;
    let administrator_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    fixture
        .resources
        .resource(PoolResource(administrator_pool.clone()));
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
        &rss_mdm_inventory_service::Store::from_pool(fixture.authority.pool.clone()),
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
    let startup = stack.startup()?;
    let automation = crate::test_support::workers::Workers::open(
        fixture.planning.policy.clone(),
        None,
        config.business_databases.scheduler.options()?,
    )
    .await?;
    fixture.resources.resource(automation.scheduler.clone());
    let scope_work = Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
        fixture.source.scopes.clone(),
        automation.scheduler.store.clone(),
    ));
    let group_work = Arc::new(rss_mdm_inventory_service::groups::runtime::GroupWork::new(
        fixture.groups.clone(),
        automation.scheduler.store.clone(),
    ));
    let scope_delivery = crate::scope_group_changes::Delivery::open(
        &config,
        config.native_protector()?,
        fixture.scope_group_health.clone(),
    )
    .await?;
    fixture
        .resources
        .resource(crate::scope_group_changes::Resource(scope_delivery.clone()));
    let signals = Arc::new(crate::worker_wake::Signals::default());
    let mut launch = startup.commit();
    launch.stage_deferred_task_with_token(
        fixture
            .device_worker
            .clone()
            .registration(Arc::new(tokio::sync::Notify::new())),
    );
    automation.register(&signals, |task| {
        launch.stage_deferred_task_with_token(task.critical());
    });
    launch.stage_deferred_task_with_token(
        Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
            fixture.source.assets.clone(),
            automation.scheduler.store.clone(),
        ))
        .registration(Arc::new(tokio::sync::Notify::new()))
        .critical(),
    );
    launch.stage_deferred_task_with_token(
        Arc::new(
            rss_mdm_inventory_service::compliance::runtime::ComplianceWork::new(
                fixture.source.compliance.clone(),
                automation.scheduler.store.clone(),
            ),
        )
        .registration(Arc::new(tokio::sync::Notify::new()))
        .critical(),
    );
    launch.stage_deferred_task_with_token(
        group_work
            .registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.stage_deferred_task_with_token(
        scope_work
            .registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.stage_deferred_task_with_token(scope_delivery.registration().critical());
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
        .await.context("initial inventory projection timed out")??;
        let inventory = component(&projected, "inventory");
        ensure!(
            inventory["task"] == "running"
                && inventory["progress"]["confirmedPosition"].is_number()
        );
        ensure!(inventory["queues"][0]["count"] == 0 && inventory["progress"]["lagging"] == false);
        ensure!(component(&projected,"automation")["runner"]["scan"]["successful"] == true);
        sqlx::query("INSERT INTO mdm_commands.device_source_dispatch(tenant_id,failure) VALUES($1::uuid,'automation_suspended') ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure")
            .bind(case_tenant()).execute(&administrator_pool).await?;
        let suspended = component(&fixture.query().await?,"automation");
        ensure!(suspended["task"] == "running" && suspended["runner"]["scan"]["successful"] == true);
        ensure!(suspended["readiness"] == "not_ready" && suspended["health"] == "degraded");
        ensure!(suspended["reasons"].as_array().unwrap().contains(&json!("automation_suspended")));
        sqlx::query("UPDATE mdm_commands.device_source_dispatch SET failure=NULL WHERE tenant_id=$1::uuid")
            .bind(case_tenant()).execute(&administrator_pool).await?;
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
                axum::routing::get(crate::assembly::http::ready)
                    .with_state((fixture.source.clone(), monotonic(), crate::installation::host::Observation::new(&serde_json::from_value(fixture.authority.base["runtime_binding"].clone())?,case_tenant().into(),fixture.source.instance.clone()))),
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
        .await.context("injected inventory pending phase not observed")??;
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
    let receipt = stack.shutdown().join().await;
    let terminal = fixture.query().await;
    let result = (|| {
        result.with_context(|| {
            format!("inventory scenario failed; drain={receipt:?}; terminal={terminal:?}")
        })?;
        let receipt = receipt?;
        ensure!(
            !receipt.is_clean()
                && receipt.failures().len() == 1
                && receipt.failures()[0].name == "mdm-inventory",
            "unexpected worker drain: {receipt:?}"
        );
        ensure!(component(&terminal?, "inventory")["task"] == "failed");
        Ok(())
    })();
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "MODULE=diagnostics.http: Group apply failure while ingress and scans succeed"]
async fn group_apply_failure_remains_visible_until_its_successful_settlement() -> Result<()> {
    use crate::planning::test_support::{GroupChange, GroupCommand, execute, group_operation};
    let mut fixture = Fixture::open().await?;
    let config: Config = serde_json::from_value(fixture.authority.base.clone())?;
    let planning = fixture.planning.clone();
    let group = uuid::Uuid::new_v4();
    let accepted = execute(
        &planning,
        &GroupCommand::Group {
            id: group,
            change: Box::new(group_operation(
                0,
                GroupChange::Create {
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                    presentation: json!({"name":"runner-health","description":""})
                        .as_object()
                        .unwrap()
                        .clone(),
                    criteria: Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"health-test"}}}))?),
                },
            )),
        },
    )
    .await?;
    let task = accepted["task"]
        .as_str()
        .context("Group calculation task")?
        .to_owned();
    let automation = crate::test_support::workers::Workers::open(
        planning.policy.clone(),
        None,
        config.business_databases.scheduler.options()?,
    )
    .await?;
    fixture.resources.resource(automation.scheduler.clone());
    let work = Arc::new(rss_mdm_inventory_service::groups::runtime::GroupWork::new(
        fixture.groups.clone(),
        automation.scheduler.store.clone(),
    ));
    let mut holder =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::query("BEGIN").execute(&mut holder).await?;
    sqlx::query(
        "SELECT id FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE",
    )
    .bind(case_tenant())
    .bind(&task)
    .fetch_one(&mut holder)
    .await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(
        work.registration(Arc::new(tokio::sync::Notify::new()))
            .critical(),
    );
    launch.finish();
    let failed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let health = fixture.groups.runner_health();
            if health.unresolved_attempts > 0
                && fixture.groups.input_observed()
                && !fixture.groups.input_failed()
            {
                let state = component(&fixture.query().await?, "automation");
                ensure!(
                    state["health"] == "degraded"
                        && state["runner"]["unresolvedAttempts"].as_u64().unwrap_or(0) > 0,
                    "Group failure missing: {state}"
                );
                ensure!(
                    health.scan.is_some_and(|s| s.failure.is_none()),
                    "successful scans must not clear an attempt failure"
                );
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    sqlx::query("ROLLBACK").execute(&mut holder).await?;
    holder.close().await?;
    let result = async {
        failed.context("Group attempt failure was not observed")??;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if fixture.groups.runner_health().unresolved_attempts == 0 {
                    let state = component(&fixture.query().await?, "automation");
                    ensure!(
                        state["runner"]["unresolvedAttempts"] == 0,
                        "settled Group failure remained: {state}"
                    );
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("Group recovery was not observed")??;
        Ok(())
    }
    .await;
    crate::test_support::runtime::stop_worker(Some(stack)).await?;
    fixture.finish(result).await
}
