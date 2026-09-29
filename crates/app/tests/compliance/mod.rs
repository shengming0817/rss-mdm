use crate::test_support::*;
use uuid::Uuid;
fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}

fn definition(target: Value) -> Value {
    json!({"name":"loaner policy","severity":"high","enabled":true,"platform":"all","target":target,"criteria":{"kind":"predicate","field":"custom.is_loaner","op":"eq","value":{"kind":"boolean","value":false}}})
}

async fn ok(b: &mut Browser, r: &Router, m: Method, p: &str, v: Option<Value>) -> Result<Value> {
    let (s, v) = b.call(r, m, p, v).await?;
    ensure!(s == StatusCode::OK, "{p}: {s} {v}");
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
                &format!("/api/v2/devices/{device}/compliance"),
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
        let jobs=pg("SELECT json_agg(json_build_object('kind',kind,'completed',completed,'failure',failure,'cursor',cursor,'forwarded',forwarded,'watermark',input->'input'->'watermark')) FROM mdm_automation.automation_jobs");
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
        &format!("/api/v2/devices/{device}/manual-fields/custom.is_loaner"),
        Some(request(
            revision,
            json!({"action":"set","value":{"kind":"boolean","value":value}}),
        )),
    )
    .await
}

async fn grants(subject: &str, device: Option<&str>) -> Result<()> {
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
    crate::test_support::identity::set_grants(case_tenant(), subject, grants).await
}

async fn task_phase(b: &mut Browser, router: &Router, path: &str, phase: &str) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(30), async {
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
    base: Value,
    router: Router,
    browser: Browser,
    subject: String,
    reader: Arc<InventoryReader>,
    plan_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
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
        let access = database(&base).await?;
        let audit = access.audit_store(&config.audit).await?;
        let (router, _, plan_runtime) = crate::api::application_fixture(
            config,
            Arc::new(crate::clock::SystemClock),
            monotonic(),
            access,
            None,
            audit,
        )
        .await?;
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        let browser = authority::Authority::open().await?.browser("admin")?;
        let subject = browser_subject(&browser, &router).await?;
        grants(&subject, None).await?;
        pg(&format!(
            "INSERT INTO mdm_access.devices VALUES('{TENANT}','compliance-a'),('{TENANT}','compliance-b')",
            TENANT = case_tenant()
        ))?;
        Ok(Self {
            base,
            router,
            browser,
            subject,
            reader,
            plan_runtime,
        })
    }
    async fn rule(&self) -> Result<(Uuid, String, Value)> {
        let id = Uuid::new_v4();
        let path = format!("/api/v2/compliance-rules/{id}");
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
        self.reader.close().await;
    }
}
mod evaluation;
mod group_input;
mod http;
mod recovery;
