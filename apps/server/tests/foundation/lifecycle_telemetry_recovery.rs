//! Recover an installation with two live readers from the fixed cold archive.
use super::*;
use crate::installation::backup;
use sqlx::Connection;

pub(super) async fn cold(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    management: &str,
    primary: &crate::config::Database,
    admin: &crate::config::Database,
    profiles: &[Value],
    attached: [Uuid; 3],
) -> Result<()> {
    let ordinary: Value = serde_json::from_slice(&std::fs::read(
        root.join("installation/telemetry-request.json"),
    )?)?;
    let mut installations = vec![ordinary.clone()];
    installations.extend_from_slice(profiles);
    let bundle = root.join("shared-telemetry-backup");
    let capture=backup::capture(serde_json::from_value(json!({"directory":bundle,"installation":source,"operation_id":Uuid::new_v4(),"authorities":[],"telemetry":installations}))?).await.context("capture shared telemetry")?;
    let mut connection = sqlx::PgConnection::connect_with(&primary.options()?).await?;
    let mut accounts = vec![
        json!({"tenant_id":management,"account":{"principal_id":first.platform_principal_id,"login":"platform","password_file":root.join("platform-password")}}),
        json!({"tenant_id":first.tenant_id,"account":{"principal_id":first.administrator_id,"login":"administrator","password_file":root.join("administrator-password")}}),
    ];
    private(&root.join("metrics-admin"), "Telemetry-admin-password!42")?;
    let users:Vec<(Uuid,String,String)>=sqlx::query_as("SELECT t.tenant_id,t.name,o.receipt->'result'->>'principalId' FROM public.mdm_tenant_operations o JOIN public.mdm_tenants t USING(tenant_id) WHERE o.action='administrator_create'").fetch_all(&mut connection).await?;
    for (tenant, name, principal) in users {
        let file = if attached.contains(&tenant) {
            "metrics-admin"
        } else if name == "Second organization" {
            "second-password"
        } else {
            "pending-password"
        };
        accounts.push(json!({"tenant_id":tenant,"account":{"principal_id":principal,"login":"administrator","password_file":root.join(file)}}));
    }
    connection.close().await?;
    let mut control = sqlx::PgConnection::connect_with(&admin.options()?).await?;
    for name in [
        &primary.name,
        ordinary["administrator"]["name"]
            .as_str()
            .context("default installation")?,
        "ch_control",
    ] {
        maintenance::reset_fixture_database(&mut control, name).await?;
    }
    control.close().await?;
    let mut ts: crate::config::Database =
        serde_json::from_value(profiles[1]["administrator"].clone())?;
    ts.name = "postgres".into();
    let mut connection = sqlx::PgConnection::connect_with(&ts.options()?).await?;
    maintenance::reset_fixture_database(&mut connection, "shared_metrics").await?;
    connection.close().await?;
    let ch = &profiles[0];
    let endpoint = ch["configuration"]["backend"]["endpoint"]
        .as_str()
        .context("fixture endpoint")?;
    let ca = std::fs::read(
        ch["configuration"]["backend"]["ca_file"]
            .as_str()
            .context("fixture CA")?,
    )?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .build()?;
    let password = crate::config::secret(Path::new(
        ch["clickhouse"]["installer"]["password_file"]
            .as_str()
            .context("fixture installer")?,
    ))?;
    let physical = Uuid::parse_str(
        ch["configuration"]["resource_id"]
            .as_str()
            .context("physical fixture UUID")?,
    )?;
    let mut ddl = vec!["DROP DATABASE rss_ts_ch SYNC".to_owned()];
    for tenant in &attached[..2] {
        let login = format!(
            "mdm_reader_{}",
            Uuid::new_v5(&physical, tenant.as_bytes()).simple()
        );
        ddl.push(format!("DROP USER {login}"));
        for table in ["raw", "summaries"] {
            ddl.push(format!(
                "DROP ROW POLICY IF EXISTS telemetry_reader_{login}_{table} ON rss_ts_ch.{table}"
            ));
        }
    }
    for statement in ddl {
        client
            .post(endpoint)
            .basic_auth("installer", Some(password.as_str()))
            .body(statement)
            .send()
            .await?
            .error_for_status()?;
    }
    for dir in [
        "installation",
        "runtime",
        "gateway",
        "content",
        "click_house",
        "timescale_shared",
    ] {
        std::fs::remove_dir_all(root.join(dir))?;
    }
    // Reader inputs live outside the deployment tree and are absent on the recovered host.
    for file in [
        "a-password",
        "a-cursor",
        "b-password",
        "b-next-password",
        "b-cursor",
    ] {
        std::fs::remove_file(root.join(file))?;
    }
    let restore = serde_json::from_value(
        json!({"directory":bundle,"operation_id":Uuid::new_v4(),"backup_manifest_sha256":capture.manifest_sha256,"administrator":primary,"accounts":accounts}),
    )?;
    let result = tokio::spawn(backup::restore(restore)).await??;
    ensure!(
        result.stage == backup::Stage::Complete,
        "restore original domain readers"
    );
    Ok(())
}
