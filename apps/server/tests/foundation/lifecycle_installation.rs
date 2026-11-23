//! Ordinary installer output is consumed by the real running App before another tenant exists.
use super::*;
use anyhow::{Context as _, ensure};
use reqwest::Method;
use serde_json::json;
use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::Path};

#[path = "lifecycle_maintenance.rs"]
mod maintenance;

#[path = "lifecycle_telemetry.rs"]
mod telemetry;

struct Browser {
    address: SocketAddr,
    client: reqwest::Client,
    cookie: String,
    csrf: String,
}
impl Browser {
    fn new(address: SocketAddr) -> Result<Self> {
        Ok(Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(12))
                .build()?,
            cookie: String::new(),
            csrf: String::new(),
        })
    }
    async fn call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
        operation: Option<Uuid>,
    ) -> Result<(u16, Value)> {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.address))
            .header("host", "mdm.example.test")
            .header("x-rss-public-origin", "https://mdm.example.test")
            .header("x-forwarded-for", "127.0.0.1")
            .header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1");
        if !self.cookie.is_empty() {
            request = request.header("cookie", &self.cookie);
        }
        if !self.csrf.is_empty() {
            request = request.header("x-csrf-token", &self.csrf);
        }
        if let Some(id) = operation {
            request = request.header("idempotency-key", id.to_string());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        for value in response.headers().get_all("set-cookie") {
            let value = value.to_str()?;
            if value.starts_with("__Host-identity-session=") {
                self.cookie = value.split(';').next().context("session cookie")?.into();
            }
        }
        let bytes = response.bytes().await?;
        let value: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        if let Some(csrf) = value["csrfToken"].as_str() {
            self.csrf = csrf.into();
        }
        Ok((status, value))
    }
    async fn login(&mut self, tenant: &str, login: &str, password: &str) -> Result<()> {
        let (status, value) = self
            .call(
                Method::POST,
                &format!("/api/v1/identity/tenants/{tenant}/login"),
                Some(json!({"login":login,"password":password})),
                None,
            )
            .await?;
        ensure!(status == 200, "real login rejected: {status}: {value}");
        Ok(())
    }
    async fn configured(&mut self, operation: Uuid) -> Result<Value> {
        let end = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_secs(120);
        loop {
            let (status, receipt) = self
                .call(
                    Method::GET,
                    &format!("/api/v1/tenant-administration/provisionings/{operation}"),
                    None,
                    None,
                )
                .await?;
            ensure!(
                status == 200,
                "original operation read: {status}: {receipt}"
            );
            if receipt["result"]["phase"] == "configured" {
                return Ok(receipt);
            }
            ensure!(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < end,
                "initialization did not recover: {receipt}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    async fn ready(&mut self, tenant: &str) -> Result<Value> {
        let end = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_secs(30);
        loop {
            let (status, value) = self.call(Method::GET, "/readyz", None, None).await?;
            if status == 200 && value["ready"] == true {
                return Ok(value);
            }
            if rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) >= end {
                let diagnostic = self
                    .call(
                        Method::GET,
                        &format!("/api/v1/tenants/{tenant}/runtime/diagnostics"),
                        None,
                        None,
                    )
                    .await?;
                anyhow::bail!("installed host remained unready: {diagnostic:?}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    async fn defaults(&mut self, tenant: &str) -> Result<()> {
        for path in ["authorization", "resources", "asset-fields"] {
            let (status, value) = self
                .call(
                    Method::GET,
                    &format!("/api/v1/tenants/{tenant}/{path}"),
                    None,
                    None,
                )
                .await?;
            ensure!(status == 200, "default {path}: {status}: {value}");
            if path != "authorization" {
                let items = if path == "asset-fields" {
                    &value["asset"]["items"]
                } else {
                    &value["items"]
                };
                ensure!(
                    !items
                        .as_array()
                        .context("default directory items")?
                        .is_empty(),
                    "missing default {path}"
                );
            }
        }
        Ok(())
    }
}
fn private(path: &Path, value: impl AsRef<[u8]>) -> Result<()> {
    std::fs::write(path, value)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

const FIRST_PASSWORD: &str = "Installation-first-admin!42";
const PLATFORM_PASSWORD: &str = "Installation-platform-admin!42";

struct Installed {
    source: Value,
    first: crate::installation::install::Receipt,
    management: String,
    address: SocketAddr,
    gateway: maintenance::Gateway,
}
async fn fresh(root: &Path, administrator: &crate::config::Database) -> Result<Installed> {
    use crate::installation::install::{Input, install};

    let pg_root = administrator
        .ca_file
        .parent()
        .context("PG input directory")?;

    private(&root.join("administrator-password"), FIRST_PASSWORD)?;
    private(&root.join("platform-password"), PLATFORM_PASSWORD)?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let gateway = maintenance::Gateway::open(
        address,
        &pg_root.join("server.crt"),
        &pg_root.join("server.key"),
    )
    .await?;
    // Deserialize the same current input contract used by the ordinary install command.
    let installation_input = json!({
        "directory":root.join("installation"),
        "deployment":{"directory":root.join("runtime"),"gateway_directory":root.join("gateway"),"probe_address":gateway.address.to_string(),
            "probe_addresses":{"https://mdm.example.test:8443":gateway.address.to_string()},
            "certificate_file":pg_root.join("server.crt"),"private_key_file":pg_root.join("server.key"),
            "trust_file":administrator.ca_file,"content_volume":root.join("content")},
        "database":{"name":"mdm_installation_proof","administrator":administrator},
        "external_calls":{"apns":{"total":8,"per_credential":7},"wns":{"total":8,"per_credential":7},"ade":8,"publication":{"total":8,"per_source":7}},"device_concurrency":8,"planning_concurrency":8,"organization_name":"First organization","platform_login":"platform","administrator_login":"administrator",
        "platform_password_file":root.join("platform-password"),"administrator_password_file":root.join("administrator-password"),
        "origin":"https://mdm.example.test","listen":address,"trusted_gateway":"127.0.0.1"
    });
    private(
        &root.join("install.json"),
        serde_json::to_vec(&installation_input)?,
    )?;
    let input: Input = crate::config::load(&root.join("install.json"))?;
    let mut rejected = installation_input.clone();
    rejected["planning_concurrency"] = json!(1_000_000);
    ensure!(matches!(
        install(serde_json::from_value(rejected)?).await,
        Err(crate::installation::Error::Input)
    ));
    ensure!(
        !root.join("installation/installation.json").exists(),
        "an invalid pool budget cannot bind the installation"
    );
    let first = Box::pin(install(input))
        .await
        .context("initialize fresh installation")?;
    let public: Value = serde_json::from_slice(&std::fs::read(
        root.join("gateway")
            .join(first.host_id.simple().to_string())
            .join("mdm.json"),
    )?)?;
    let management = public["managementTenant"]
        .as_str()
        .context("installation management tenant")?;
    drop(reservation);
    Ok(Installed {
        source: installation_input,
        first,
        management: management.into(),
        address,
        gateway,
    })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "T2: fresh installer, real App and workers, post-start tenant login/defaults and replay"]
#[allow(
    clippy::disallowed_methods,
    reason = "integration observes production monotonic time and bounded shutdown"
)]
async fn installed_service_creates_another_tenant_without_reassembly() -> Result<()> {
    use crate::installation::install::install;
    let administrator = Inputs::load()?.database("installation", "postgres");
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let Installed {
        source: installation_input,
        first,
        management,
        address,
        gateway,
    } = fresh(&root, &administrator).await?;
    let management = management.as_str();
    let runtime_path = root.join("installation/runtime.json");
    let runtime_before = std::fs::read(&runtime_path)?;
    let mut db = administrator.clone();
    db.name = "mdm_installation_proof".into();
    let operator = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect_with(db.options()?)
        .await?;
    let resource_count = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT (SELECT count(*) FROM pg_roles)+(SELECT count(*) FROM pg_database)",
        )
        .fetch_one(&operator)
    };
    let count_before = resource_count().await?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(crate::serve(
        crate::config::load(&runtime_path)?,
        async move {
            stopped
                .await
                .map_err(|_| std::io::Error::other("test stop sender closed"))
        },
        Arc::new(crate::Monotonic(std::time::Instant::now)),
    ));
    let readiness_client = reqwest::Client::builder().no_proxy().build()?;
    let readiness_url = format!("http://{address}/readyz");
    let mut joined = false;
    let exercise = async {
        tokio::select! {
            result = &mut server => { joined = true; bail!("installed service exited: {result:?}"); },
            response = tokio::time::timeout(Duration::from_secs(90), super::ready(&readiness_client, &readiness_url)) => { response??; }
        }
        let mut platform = Browser::new(address)?;
        platform.login(management, "platform", PLATFORM_PASSWORD).await?;
        platform.configured(first.operation_id).await?;
        let mut business = Browser::new(address)?;
        business.login(&first.tenant_id.to_string(), "administrator", FIRST_PASSWORD).await?;
        business.defaults(&first.tenant_id.to_string()).await?;
        let (status, before) = business.call(Method::GET, "/readyz", None, None).await?;
        ensure!(matches!(status, 200 | 503) && before["observation"].is_object(), "original process observation unavailable: {status}: {before}");
        let operation = Uuid::new_v4();
        let request = json!({"name":"Second organization","administratorLogin":"administrator","administratorPassword":"Installation-second-admin!42"});
        let (status, created) = platform.call(Method::POST, "/api/v1/tenant-administration/provisionings", Some(request.clone()), Some(operation)).await?;
        ensure!(matches!(status, 200 | 202) || (status == 503 && created["code"] == "operation_unknown"), "running service tenant creation: {status}: {created}");
        let receipt = platform.configured(operation).await?;
        let tenant = receipt["result"]["tenantId"].as_str().context("new tenant")?;
        let mut peer = Browser::new(address)?;
        peer.login(tenant, "administrator", "Installation-second-admin!42").await?;
        peer.defaults(tenant).await?;
        ensure!(matches!(business.call(Method::GET, &format!("/api/v1/tenants/{tenant}/resources"), None, None).await?.0, 401 | 403), "first session crossed tenants");
        let (status, replay) = platform.call(Method::POST, "/api/v1/tenant-administration/provisionings", Some(request), Some(operation)).await?;
        ensure!(status == 200 && replay == receipt, "original operation replay changed: {status}: {replay}");
        baseline_isolation(&operator, (first.tenant_id, first.operation_id), (Uuid::parse_str(tenant)?, operation)).await?;
        let after = peer.ready(tenant).await?;
        ensure!(before["observation"] == after["observation"], "new tenant changed running process");
        ensure!(count_before == resource_count().await? && runtime_before == std::fs::read(&runtime_path)?, "new tenant changed installation resources");
        let replayed = install(serde_json::from_value(installation_input.clone())?).await.context("replay original installation")?;
        ensure!(replayed.operation_id == first.operation_id && replayed.tenant_id == first.tenant_id, "installer replay changed original identities");
        gateway.probe(&administrator.ca_file).await?;
        crate::installation::runtime_files::observe_installation(serde_json::from_value(installation_input.clone())?).await.context("observe initial installation")?;
        Ok::<_, anyhow::Error>(())
    }.await;
    if exercise.is_err() {
        let progress = sqlx::query_scalar::<_, Value>("SELECT coalesce(jsonb_agg(jsonb_build_object('phase',phase,'blocked',blocked,'completed',(SELECT count(*) FROM jsonb_object_keys(completed)),'remaining',ARRAY(SELECT s->>'key' FROM jsonb_array_elements(manifest->'steps') s WHERE NOT completed ? (s->>'key') LIMIT 8))),'[]'::jsonb) FROM mdm_initialization.baselines").fetch_one(&operator).await;
        eprintln!("installation progress at failure: {progress:?}");
    }
    let _ = stop.send(());
    let shutdown = if joined {
        None
    } else {
        Some(tokio::time::timeout(Duration::from_secs(70), &mut server).await)
    };
    operator.close().await;
    exercise?;
    if let Some(result) = shutdown {
        result???;
    }
    ensure!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "installed listener leaked"
    );
    // Keep the full maintenance journey off the test thread stack.
    Box::pin(maintenance::exercise(
        &root,
        &installation_input,
        &first,
        management,
    ))
    .await?;
    Ok(())
}

pub(in crate::foundation_t2) async fn shared_telemetry() -> Result<()> {
    let inputs = Inputs::load()?;
    let admin = inputs.database("shared_telemetry", "postgres");
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let installed = Box::pin(fresh(&root, &admin)).await?;
    let original = maintenance::desired(&root, installed.first.host_id)?;
    let running = maintenance::Running::open(&original).await?;
    crate::installation::runtime_files::observe_installation(serde_json::from_value(
        installed.source.clone(),
    )?)
    .await?;
    running.close().await?;
    Box::pin(telemetry::exercise(
        &root,
        &installed.source,
        &installed.first,
        &installed.management,
        &admin,
        &inputs.directory,
    ))
    .await
}

/// Resume two existing durable intents and observe their original operation IDs.
async fn baseline_isolation(pool: &sqlx::PgPool, a: (Uuid, Uuid), b: (Uuid, Uuid)) -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    let reopen = |(tenant, operation)| async move {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.storage_target',encode(s.target,'hex'),true),set_config('rss.storage_lineage',encode(s.lineage,'hex'),true),set_config('rss.tenant_id',e.tenant_id::text,true),set_config('rss.execution_epoch',e.epoch::text,true) FROM rss_transactional_messaging.storage_lineage s CROSS JOIN rss_transactional_messaging.tenant_epoch e WHERE s.singleton AND e.tenant_id=$1")
            .bind(tenant).execute(&mut *tx).await?;
        ensure!(sqlx::query("UPDATE mdm_initialization.baselines SET phase='pending' WHERE tenant_id=$1 AND phase='configured'")
            .bind(tenant).execute(&mut *tx).await?.rows_affected()==1);
        ensure!(sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=jsonb_set(receipt,'{result,phase}',to_jsonb('pending'::text)) WHERE operation_id=$1 AND tenant_id=$2 AND action='provision'")
            .bind(operation).bind(tenant).execute(&mut *tx).await?.rows_affected()==1);
        sqlx::query("SELECT pg_notify('mdm_work','baseline')")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    };
    // Hold the normal tenant lock until the business-row lock is established.
    let mut gate = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2863))")
        .bind(a.0.to_string())
        .execute(&mut *gate)
        .await?;
    reopen(a).await?;
    let mut held = pool.begin().await?;
    let pid = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM mdm_initialization.baselines WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(a.0)
    .fetch_one(&mut *held)
    .await?;
    gate.rollback().await?;
    sqlx::query("SELECT pg_notify('mdm_work','baseline')")
        .execute(pool)
        .await?;
    let update = "UPDATE mdm_initialization.baselines SET phase";
    let attempt = wait_for_blocked_attempt(pool, pid, update).await?;
    reopen(b).await?;
    tokio::time::timeout(Duration::from_secs(8),async {
        loop {
            let done:bool=sqlx::query_scalar("SELECT b.phase='configured' AND o.receipt->'result'->>'phase'='configured' FROM mdm_initialization.baselines b JOIN public.mdm_tenant_operations o USING(tenant_id) WHERE b.tenant_id=$1 AND o.operation_id=$2")
                .bind(b.0).bind(b.1).fetch_one(pool).await?;
            if done { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    ensure!(blocked_attempt(pool, pid, update).await? == Some(attempt));
    held.rollback().await?;
    Ok(())
}
