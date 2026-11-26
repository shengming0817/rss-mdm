//! Recover an installation with two live readers from the fixed cold archive.
use super::*;
use crate::installation::backup;
use sqlx::Connection;

fn clickhouse_client(ch: &Value) -> Result<(reqwest::Client, &str)> {
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
    Ok((client, endpoint))
}
pub(super) fn reader(ch: &Value, tenant: Uuid) -> Result<String> {
    let physical = Uuid::parse_str(
        ch["configuration"]["resource_id"]
            .as_str()
            .context("physical fixture UUID")?,
    )?;
    Ok(format!(
        "mdm_reader_{}",
        Uuid::new_v5(&physical, tenant.as_bytes()).simple()
    ))
}
pub(super) async fn login(
    root: &Path,
    ch: &Value,
    tenant: Uuid,
    file: &str,
    expected: bool,
) -> Result<()> {
    let (client, endpoint) = clickhouse_client(ch)?;
    let password = crate::config::secret(&root.join(file))?;
    let status = client
        .post(endpoint)
        .basic_auth(reader(ch, tenant)?, Some(password.as_str()))
        .body("SELECT currentUser()")
        .send()
        .await?
        .status();
    ensure!(
        if expected {
            status.is_success()
        } else {
            matches!(status.as_u16(), 401 | 403)
        },
        "reader authentication {status}"
    );
    Ok(())
}
pub(super) async fn interrupt_retirement(ch: &Value, tenant: Uuid) -> Result<()> {
    let (client, endpoint) = clickhouse_client(ch)?;
    let password = crate::config::secret(Path::new(
        ch["clickhouse"]["installer"]["password_file"]
            .as_str()
            .context("installer password")?,
    ))?;
    client
        .post(endpoint)
        .basic_auth("installer", Some(password.as_str()))
        .body(format!("DROP USER {}", reader(ch, tenant)?))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
pub(super) async fn admin_sql(ch: &Value, sql: &str) -> Result<String> {
    let (client, url) = clickhouse_client(ch)?;
    let secret = crate::config::secret(Path::new(
        ch["clickhouse"]["installer"]["password_file"]
            .as_str()
            .context("installer")?,
    ))?;
    Ok(client
        .post(url)
        .basic_auth("installer", Some(secret.as_str()))
        .body(sql.to_owned())
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}
pub(super) async fn unrelated_rotation(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    ch: &Value,
) -> Result<()> {
    use crate::installation::protection;
    let ch_id: Uuid = serde_json::from_value(ch["configuration"]["resource_id"].clone())?;
    admin_sql(ch, "REVOKE INSERT ON rss_ts_ch.raw FROM metric_writer").await?;
    let operation = Uuid::new_v4();
    let checked = async {
        for _ in 0..5 {
            let running =
                maintenance::Running::open(&maintenance::desired(root, first.host_id)?).await?;
            let observation =
                runtime_files::observe_installation(serde_json::from_value(source.clone())?)
                    .await?;
            ensure!(
                observation.unavailable_telemetry.contains(&ch_id),
                "actual host observed optional ClickHouse outage"
            );
            let receipt = protection::rotate(protection::Request {
                installation: serde_json::from_value(source.clone())?,
                purpose: protection::Purpose::Native,
                operation_id: operation,
            })
            .await?;
            running.close().await?;
            if receipt.phase == protection::Phase::Complete {
                return Ok::<_, anyhow::Error>(());
            }
        }
        anyhow::bail!("host rotation must complete during an unrelated optional outage")
    }
    .await;
    admin_sql(ch, "GRANT INSERT ON rss_ts_ch.raw TO metric_writer").await?;
    checked
}
async fn restart_clickhouse(ch: &Value, container: &str) -> Result<()> {
    let status = tokio::process::Command::new("docker")
        .args(["restart", "--time", "10", container])
        .stdout(std::process::Stdio::null())
        .status()
        .await?;
    ensure!(status.success(), "restart isolated ClickHouse");
    let (client, endpoint) = clickhouse_client(ch)?;
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if client
                .get(format!("{endpoint}/ping"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("restarted ClickHouse HTTPS endpoint")?;
    Ok(())
}
pub(super) async fn password_policy(inputs: &Path, ch: &Value, strict: bool) -> Result<()> {
    let file = Path::new(
        ch["clickhouse"]["server_configuration_files"][0]
            .as_str()
            .context("fixture configuration")?,
    );
    let providers: Value =
        serde_json::from_slice(&std::fs::read(inputs.join("telemetry-providers.json"))?)?;
    let container = providers["container"]
        .as_str()
        .context("isolated ClickHouse container")?;
    let policy = file.with_file_name("password-policy.xml");
    if strict {
        let temporary = policy.with_extension("tmp");
        let rule = "<password_complexity><rule><pattern>.{80,}</pattern><message>minimum 80 characters</message></rule></password_complexity>";
        std::fs::write(&temporary, format!("<clickhouse>{rule}</clickhouse>"))?;
        std::fs::rename(temporary, &policy)?;
    } else {
        std::fs::remove_file(policy)?;
    }
    restart_clickhouse(ch, container)
        .await
        .context("load fixture password policy")
}
pub(super) async fn rejected_rotation(
    root: &Path,
    source: &Value,
    ch: &Value,
    tenant: Uuid,
    reader: &Value,
) -> Result<()> {
    let secret = root.join("policy-rejected-password");
    private(&secret, Uuid::new_v4().simple().to_string())?;
    let mut action = reader.clone();
    action["password_file"] = json!(secret);
    let op = Uuid::new_v4();
    let rejected = json!({"product":source,"installation":ch,"operationId":op,"tenant":tenant,"expectedRevision":1,"action":action});
    ensure!(
        telemetry::prepare_tenant(serde_json::from_value(rejected)?)
            .await
            .is_err(),
        "provider rejected the new password"
    );
    let result = telemetry::cancel(serde_json::from_value(
        json!({"product":source,"installation":ch,"tenant":tenant,"operationId":op}),
    )?)
    .await?;
    ensure!(serde_json::to_value(result)?["state"] == "cancelled");
    login(root, ch, tenant, "a-password", true).await
}
pub(super) async fn retained(
    primary: &crate::config::Database,
    settled: Uuid,
    unresolved: Uuid,
    expired: Uuid,
) -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(primary.options()?)
        .await?;
    let durable: String = sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND message_id=$2")
        .bind(unresolved).bind(expired.to_string()).fetch_one(&pool).await?;
    ensure!(
        durable == "dead_letter",
        "reader retirement preserves the original recovery record"
    );
    for tenant in [settled, unresolved] {
        let count = sqlx::query("UPDATE mdm_telemetry.retention_targets SET result=NULL,phase=0,next_check=0,due_at=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE tenant_id=$1")
            .bind(tenant).execute(&pool).await?.rows_affected();
        ensure!(count > 0, "real retained series");
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let settled_done: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.retention_targets WHERE tenant_id=$1 AND result->>'state'='complete')")
                .bind(settled).fetch_one(&pool).await?;
            let barrier: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.retention_targets WHERE tenant_id=$1 AND result->>'reason'='accepted_batches_pending')")
                .bind(unresolved).fetch_one(&pool).await?;
            if settled_done && barrier {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }).await.context("retention completed for settled data and protected the unresolved batch after both readers retired")??;
    pool.close().await;
    Ok(())
}
pub(super) async fn reader_isolation(root: &Path, ch: &Value, a: Uuid, b: Uuid) -> Result<()> {
    let (client, endpoint) = clickhouse_client(ch)?;
    let a_password = crate::config::secret(&root.join("a-password"))?;
    let query = format!(
        "SELECT countIf(tenant='{a}'),countIf(tenant='{b}') FROM rss_ts_ch.raw FORMAT TabSeparated"
    );
    let response = client
        .post(endpoint)
        .basic_auth(reader(ch, a)?, Some(a_password.as_str()))
        .body(query)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    ensure!(
        response.trim() == "2\t0",
        "A's actual reader must see only A's two samples"
    );
    let status = client
        .post(endpoint)
        .basic_auth(reader(ch, b)?, Some(a_password.as_str()))
        .body("SELECT currentUser()")
        .send()
        .await?
        .status();
    ensure!(
        matches!(status.as_u16(), 401 | 403),
        "B rejects A's credential: {status}"
    );
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "this cold restore removes each owned backend and starts from the original archive"
)]
pub(super) async fn cold(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    management: &str,
    primary: &crate::config::Database,
    profiles: &[Value],
    attached: [Uuid; 3],
) -> Result<()> {
    let ordinary: Value = serde_json::from_slice(&std::fs::read(
        root.join("installation/telemetry-request.json"),
    )?)?;
    let mut installations = vec![ordinary.clone()];
    installations.extend_from_slice(profiles);
    let bundle = root.join("shared-telemetry-backup");
    let request = serde_json::from_value(
        json!({"directory":bundle,"installation":source,"operation_id":Uuid::new_v4(),"authorities":[],"telemetry":installations}),
    )?;
    let capture = tokio::spawn(backup::capture(request))
        .await?
        .context("capture shared telemetry")?;
    let mut connection = sqlx::PgConnection::connect_with(&primary.options()?).await?;
    let mut accounts = vec![
        json!({"tenant_id":management,"account":{"principal_id":first.platform_principal_id,"login":"platform","password_file":root.join("platform-password")}}),
        json!({"tenant_id":first.tenant_id,"account":{"principal_id":first.administrator_id,"login":"administrator","password_file":root.join("administrator-password")}}),
    ];
    private(&root.join("metrics-admin"), "Telemetry-admin-password!42")?;
    let users:Vec<(Uuid,String)>=sqlx::query_as("SELECT tenant_id,receipt->'result'->>'principalId' FROM public.mdm_tenant_operations WHERE action='administrator_create'").fetch_all(&mut connection).await?;
    for (tenant, principal) in users {
        ensure!(
            attached.contains(&tenant),
            "unexpected fixture administrator"
        );
        accounts.push(json!({"tenant_id":tenant,"account":{"principal_id":principal,"login":"administrator","password_file":root.join("metrics-admin")}}));
    }
    connection.close().await?;
    let mut admin = primary.clone();
    admin.name = "postgres".into();
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
    let disk = Path::new(
        ch["clickhouse"]["backup_directory"]
            .as_str()
            .context("isolated backup disk")?,
    );
    let mut source_zips = 0;
    for entry in std::fs::read_dir(disk)? {
        let archive = entry?.path().join("snapshot.zip");
        if archive.is_file() {
            std::fs::remove_file(archive)?;
            source_zips += 1;
        }
    }
    ensure!(
        source_zips == 1,
        "one physical source ZIP discarded before archive restore"
    );
    let (client, endpoint) = clickhouse_client(ch)?;
    let password = crate::config::secret(Path::new(
        ch["clickhouse"]["installer"]["password_file"]
            .as_str()
            .context("fixture installer")?,
    ))?;
    let mut ddl = Vec::new();
    for tenant in &attached[..2] {
        let external = reader(ch, *tenant)?;
        for login in [
            external.clone(),
            external.replacen("mdm_reader_", "mdm_work_", 1),
        ] {
            ddl.push(format!("DROP USER {login}"));
            for table in ["raw", "summaries"] {
                ddl.push(format!(
                "DROP ROW POLICY IF EXISTS telemetry_reader_{login}_{table} ON rss_ts_ch.{table}"
            ));
            }
        }
    }
    ddl.push("DROP DATABASE rss_ts_ch SYNC".to_owned());
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
        "a-worker-password",
        "a-cursor",
        "b-password",
        "b-worker-password",
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
