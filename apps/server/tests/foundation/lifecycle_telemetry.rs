//! Live optional providers on the installed host, through operator and tenant entrances.
use super::*;
#[path = "lifecycle_telemetry_data.rs"]
mod data;
use crate::installation::{configure, install, providers::telemetry, runtime_files};

async fn resources(
    root: &Path,
    first: &install::Receipt,
    pg: &crate::config::Database,
    inputs: &Path,
) -> Result<Vec<Value>> {
    let providers: Value =
        serde_json::from_slice(&std::fs::read(inputs.join("telemetry-providers.json"))?)?;
    let base = maintenance::desired(root, first.host_id)?["telemetry"][0].clone();
    let area = std::path::PathBuf::from(
        providers["area"]
            .as_str()
            .context("ClickHouse fixture directory")?,
    );
    let password = root.join("metric-password");
    private(&password, Uuid::new_v4().simple().to_string())?;
    let key = root.join("metric-cursor");
    private(&key, [5u8; 32])?;
    let mut requests = Vec::new();
    for kind in ["click_house", "timescale_shared"] {
        let administrator = if kind == "click_house" {
            let mut admin = pg.clone();
            admin.name = "ch_control".into();
            admin
        } else {
            serde_json::from_value(providers["timescale"].clone())?
        };
        let mut db = administrator.clone();
        db.user = format!("metrics_{kind}");
        db.password_file = password.clone();
        let mut config = base.clone();
        config["connections"] = json!(1);
        config["resource_id"] = json!(Uuid::new_v4());
        let mut ch = Value::Null;
        if kind == "click_house" {
            config.as_object_mut().unwrap().remove("cursor_key_file");
            config["backend"] = json!({"kind":kind,"control":db,"endpoint":providers["endpoint"],"ca_file":providers["ca"],
                "writer":{"user":"metric_writer","password_file":password},"maintenance":{"user":"metric_maint","password_file":password},
                "max_scan_rows":100000,"max_scan_bytes":16777216,"max_memory_bytes":67108864});
            ch = json!({"installer":{"user":"installer","password_file":area.join("installer-password")},"guard":{"user":"ch_guard","password_file":area.join("guard-password")},"backup_directory":area.join("backup"),"server_configuration_files":[area.join("telemetry.xml"),area.join("users.xml")]});
        } else {
            config["cursor_key_file"] = json!(key);
            config["backend"] = json!({"kind":kind,"database":db,"chunk_micros":86400000000u64});
        }
        let request = json!({"operationId":Uuid::new_v4(),"directory":root.join(kind),"configuration":config,
            "administrator":administrator,"owner":format!("metrics_owner_{kind}"),"partitions":[],"clickhouse":ch});
        telemetry::prepare(serde_json::from_value(request.clone())?)
            .await
            .with_context(|| format!("install {kind}"))?;
        requests.push(request);
    }
    Ok(requests)
}
async fn attach(
    source: &Value,
    resource: &Value,
    tenant: Uuid,
    rev: i64,
    action: Value,
) -> Result<Value> {
    let request = json!({"product":source,"installation":resource,"operationId":Uuid::new_v4(),"tenant":tenant,"expectedRevision":rev,"action":action});
    let receipt = serde_json::to_value(
        telemetry::prepare_tenant(serde_json::from_value(request.clone())?).await?,
    )?;
    let replay =
        serde_json::to_value(telemetry::prepare_tenant(serde_json::from_value(request)?).await?)?;
    ensure!(
        receipt == replay
            && receipt["materialRevision"] == rev + 1
            && receipt["installationId"] == resource["configuration"]["resource_id"],
        "selection receipt and replay"
    );
    Ok(receipt)
}
async fn available(browser: &mut Browser, tenant: Uuid, expected: bool) -> Result<()> {
    let (status, value) = browser
        .call(
            Method::GET,
            &format!("/api/v1/tenants/{tenant}/runtime/diagnostics"),
            None,
            None,
        )
        .await?;
    ensure!(status == 200, "runtime diagnostics returned {status}");
    let telemetry = value["components"]
        .as_array()
        .context("diagnostic components")?
        .iter()
        .find(|c| c["name"] == "telemetry")
        .context("mounted telemetry")?;
    let storage = telemetry["dependencies"]
        .as_array()
        .context("telemetry dependencies")?
        .iter()
        .find(|d| d["name"] == "telemetry_storage")
        .context("telemetry backend probe")?;
    ensure!(
        storage["state"] == if expected { "available" } else { "unavailable" },
        "real backend qualification: {storage}"
    );
    Ok(())
}
async fn provision(platform: &mut Browser) -> Result<(Uuid, Browser)> {
    let operation = Uuid::new_v4();
    let (status,value)=platform.call(Method::POST,"/api/v1/tenant-administration/provisionings",Some(json!({"name":format!("Metrics {operation}"),"administratorLogin":"administrator","administratorPassword":"Telemetry-admin-password!42"})),Some(operation)).await?;
    ensure!(
        matches!(status, 200 | 202) || status == 503 && value["code"] == "operation_unknown",
        "provision live tenant: {status}: {value}"
    );
    let receipt = platform.configured(operation).await?;
    let tenant = Uuid::parse_str(
        receipt["result"]["tenantId"]
            .as_str()
            .context("tenant identity")?,
    )?;
    let mut browser = Browser::new(platform.address)?;
    browser
        .login(
            &tenant.to_string(),
            "administrator",
            "Telemetry-admin-password!42",
        )
        .await?;
    Ok((tenant, browser))
}
pub(super) async fn exercise(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    management: &str,
    pg: &crate::config::Database,
    inputs: &Path,
) -> Result<()> {
    let resources = resources(root, first, pg, inputs).await?;
    let mut runtime = maintenance::desired(root, first.host_id)?;
    for resource in &resources {
        let request = json!({"installation":source,"operation_id":Uuid::new_v4(),"tenant":null,"expected_revision":runtime["runtime_binding"]["revision"],"change":{"kind":"telemetry","settings":resource["configuration"]}});
        let receipt = configure::run(serde_json::from_value(request)?).await?;
        ensure!(receipt.deployment_required);
        runtime = maintenance::desired(root, first.host_id)?;
    }
    let running = maintenance::Running::open(&runtime).await?;
    runtime_files::observe_installation(serde_json::from_value(source.clone())?).await?;
    let address = source["listen"]
        .as_str()
        .context("host listener")?
        .parse()?;
    let mut platform = Browser::new(address)?;
    platform
        .login(management, "platform", "Installation-platform-admin!42")
        .await?;
    let (a, mut first_browser) = provision(&mut platform).await?;
    let reader = |name: &str| -> Result<Value> {
        let password = root.join(format!("{name}-password"));
        private(&password, Uuid::new_v4().simple().to_string())?;
        let key = root.join(format!("{name}-cursor"));
        private(&key, [if name == "a" { 3 } else { 4 }; 32])?;
        Ok(json!({"kind":"reader","password_file":password,"cursor_key_file":key}))
    };
    attach(source, &resources[0], a, 0, reader("a")?).await?;
    available(&mut first_browser, a, true).await?;
    let (_, before) = platform.call(Method::GET, "/readyz", None, None).await?;
    let mut control = pg.clone();
    control.name = "ch_control".into();
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(control.options()?)
        .await?;
    let sessions = || {
        sqlx::query_scalar::<_,i32>("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='metrics_click_house' ORDER BY pid").fetch_all(&observer)
    };
    let original = sessions().await?;
    ensure!(original.len() == 1, "one admitted control pool session");
    let (b, mut peer) = provision(&mut platform).await?;
    let b_reader = reader("b")?;
    attach(source, &resources[0], b, 0, b_reader.clone()).await?;
    available(&mut peer, b, true).await?;
    let (_, after) = platform.call(Method::GET, "/readyz", None, None).await?;
    ensure!(
        before["observation"].is_object()
            && before["observation"] == after["observation"]
            && runtime == maintenance::desired(root, first.host_id)?,
        "tenant access changed host generation or runtime resources"
    );
    ensure!(
        sessions().await? == original,
        "tenant B must reuse the live A control connection"
    );
    let mut rotation = b_reader.clone();
    let password = root.join("b-next-password");
    private(&password, Uuid::new_v4().simple().to_string())?;
    rotation["password_file"] = json!(password);
    attach(source, &resources[0], b, 1, rotation).await?;
    available(&mut first_browser, a, true).await?;
    available(&mut peer, b, true).await?;
    let (t, mut shared) = provision(&mut platform).await?;
    attach(source, &resources[1], t, 0, json!({"kind":"select"})).await?;
    available(&mut shared, t, true).await?;
    ensure!(
        sessions().await? == original,
        "reader rotation must retain the shared control session"
    );
    observer.close().await;
    running.close().await?;
    // With the App stopped, open exactly one owner on the installed resource and
    // exercise the reader material committed by the live maintenance operation.
    let mut primary = pg.clone();
    primary.name = source["database"]["name"]
        .as_str()
        .context("product database")?
        .to_owned();
    data::exercise(&runtime, &primary, a, b).await?;
    let restarted = maintenance::Running::open(&runtime).await?;
    available(&mut peer, b, true).await?;
    available(&mut shared, t, true).await?;
    attach(source, &resources[0], b, 2, json!({"kind":"retire"})).await?;
    available(&mut peer, b, false).await?;
    available(&mut first_browser, a, true).await?;
    restarted.close().await?;
    Ok(())
}
