use crate::test_support::{http::*, process::*, runtime::*, *};
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}

fn definition(target: Value) -> Value {
    json!({"presentation":{"name":"loaner policy"},"severity":"high","enabled":true,"platform":"all","target":target,"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}}})
}

async fn ok(b: &mut Browser, r: &Router, m: Method, p: &str, v: Option<Value>) -> Result<Value> {
    let (s, v) = b.call(r, m, p, v).await?;
    ensure!(
        s == StatusCode::OK || s == StatusCode::ACCEPTED,
        "{p}: {s} {v}"
    );
    Ok(v)
}

async fn status(b: &mut Browser, r: &Router, device: &str, expected: &str) -> Result<Value> {
    // Allow one production 30-second claim lease to expire after an unknown commit.
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let v = ok(
                b,
                r,
                Method::GET,
                &format!("/api/v1/devices/{device}/compliance"),
                None,
            )
            .await?;
            if v["status"] == expected {
                return Ok::<_, anyhow::Error>(v);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| {
        let jobs=pg("SELECT json_agg(json_build_object('completed',completed,'failure',failure,'cursor',cursor,'started',started,'watermark',input->'watermark')) FROM mdm_compliance.runs");
        let reconcile=pg("SELECT json_agg(json_build_object('entity',entity,'result',result,'wake',wake_version,'failures',failures,'lease',lease_until,'next',next_run)) FROM rss_reconcile.targets");
        let heads=pg("SELECT json_agg(row_to_json(r)) FROM mdm_compliance.rules r");
        let changes=pg("SELECT json_agg(json_build_object('revision',revision,'forwarded',forwarded)) FROM mdm.asset_changes");
        let checkpoint=pg("SELECT json_agg(row_to_json(d)) FROM mdm_planning.asset_dispatch d");
        let locks=pg("SELECT json_agg(json_build_object('wait',wait_event,'state',state,'query',left(query,160))) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'");
        anyhow::anyhow!("compliance {device} did not converge to {expected}; jobs={jobs:?}; waits={locks:?}; reconcile={reconcile:?}; checkpoint={checkpoint:?}; heads={heads:?}; changes={changes:?}")
    })?
}

async fn assign(
    b: &mut Browser,
    r: &Router,
    device: &str,
    revision: u64,
    value: bool,
) -> Result<Value> {
    ok(
        b,
        r,
        Method::PUT,
        &format!("/api/v1/devices/{device}/manual-fields/custom.is_loaner"),
        Some(request(
            revision,
            json!({"action":"set","value":{"kind":"boolean","value":value}}),
        )),
    )
    .await
}

fn grants(device: Option<&str>) -> Result<Vec<crate::authorization::Grant>> {
    let mut grants = crate::test_support::identity::device_grants(
        device,
        &["compliance_read", "inventory_read", "inventory_assign"],
    )?;
    if device.is_none() {
        for operation in [
            crate::authorization::Permission::ComplianceRuleRead,
            crate::authorization::Permission::ComplianceWrite,
            crate::authorization::Permission::ComplianceRecompute,
            crate::authorization::Permission::GroupRead,
            crate::authorization::Permission::GroupWrite,
            crate::authorization::Permission::GroupRecompute,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
    }
    Ok(grants)
}

async fn task_phase(b: &mut Browser, router: &Router, path: &str, phase: &str) -> Result<Value> {
    // Commit-unknown keeps the 30s claim lease; the recovery scan can add up to 5s.
    // Leave execution time after that legitimate recovery window, as status() already does.
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let value = ok(b, router, Method::GET, path, None).await?;
            if value["phase"] == phase {
                return Ok::<_, anyhow::Error>(value);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
struct Fixture {
    resources: crate::test_support::runtime::Resources,
    base: Value,
    router: Router,
    browser: Browser,
    subject: String,
    reader: Arc<InventoryReader>,
    plan_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let config: Config = serde_json::from_value(base.clone())?;
        let reader = Arc::new(
            InventoryReader::connect(
                config
                    .access_database
                    .options()?
                    .username("mdm_api")
                    .password("api-fixture"),
            )
            .await?,
        );
        let mut authority = authority::Authority::from_config(base.clone()).await?;
        let mut resources = std::mem::take(&mut authority.resources);
        let tenant = authority.identity.tenant;
        let plan_runtime = crate::planning::test_support::runtime(tenant).await;
        resources.resource(SourceResource(plan_runtime.clone()));
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let plan_audit = Arc::new(
            authority
                .audit
                .on_runtime(plan_runtime.clone(), tenant, &budget.control())
                .await?,
        );
        let key = crate::cursor_keys::load(&plan_runtime, tenant).await?;
        let clock = Arc::new(crate::clock::SystemClock);
        let planning = Arc::new(
            crate::planning::Planning::new(
                plan_audit.clone(),
                plan_runtime.clone(),
                tenant,
                clock.clone(),
                &key,
                Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
                    plan_audit.clone(),
                )),
            )
            .await?,
        );
        let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
        let compliance = crate::planning::test_support::compliance(&planning).await;
        let inventory = crate::inventory_runtime::InventoryRuntime::fixture(
            config.runtime_database.options()?,
            Arc::new(rss_mdm_inventory_service::Store::from_pool(
                authority.pool.clone(),
            )),
            tenant,
            monotonic(),
            authority.audit.clone(),
        )
        .await?;
        resources.resource(InventoryFixtureResource(inventory.clone()));
        let assets = Arc::new(crate::assets::AssetService::new(
            inventory,
            plan_audit.clone(),
            plan_runtime.clone(),
            tenant,
            Arc::new(crate::clock::InventoryClock(clock.clone())),
            &key,
            rss_reconcile_postgres::PgMessagingStore::new(
                plan_runtime.clone(),
                tenant,
                rss_mdm_inventory_service::transaction::deadline(),
            )
            .await
            .unwrap(),
        ));
        let router = authority.router(
            rss_mdm_http_contract::Router::new()
                .nest(
                    "/api/v1",
                    rss_mdm_management_http::compliance::http::routes()
                        .with_state(compliance)
                        .merge(
                            rss_mdm_management_http::assets::routes().with_state(Arc::new(
                                rss_mdm_management_http::assets::http::HttpState { assets },
                            )),
                        )
                        .merge(
                            rss_mdm_management_http::planning::http::routes().with_state(Arc::new(
                                rss_mdm_management_http::planning::http::HttpState {
                                    planning,
                                    groups,
                                },
                            )),
                        ),
                )
                .merge(authority.authorization()),
        )?;
        let browser = authority::Authority::prepared_browser("admin")?;
        let subject = prepared_subject(&browser)?;
        identity::seed_grants(case_tenant(), &subject, grants(None)?).await?;
        pg(&format!(
            "INSERT INTO mdm_access.devices VALUES('{TENANT}','compliance-a'),('{TENANT}','compliance-b')",
            TENANT = case_tenant()
        ))?;
        Ok(Self {
            resources,
            base,
            router,
            browser,
            subject,
            reader,
            plan_runtime,
            audit: plan_audit,
        })
    }
    async fn rule(&self) -> Result<(Uuid, String, Value)> {
        let id = Uuid::new_v4();
        let path = format!("/api/v1/compliance-rules/{id}");
        let written = ok(
            &mut self.browser.clone(),
            &self.router,
            Method::PUT,
            &path,
            Some(request(0, definition(json!({"kind":"all"})))),
        )
        .await?;
        Ok((id, path, written))
    }
    async fn close(self) {
        self.resources
            .finish(async { Ok(()) })
            .await
            .expect("application resources closed");
        self.reader.close().await;
    }
}
mod evaluation;
mod group_input;
mod http;
mod recovery;
