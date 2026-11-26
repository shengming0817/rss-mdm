//! Fixed-origin deployment operations; runtime readers and writers never receive installer credentials.
//! ref: ClickHouse/ClickHouse src/Interpreters/executeQuery.cpp@v25.8.12.129-lts.
use super::*;
use reqwest::Client;
fn configuration(input: &Request) -> Result<(&str, &std::path::Path, &ClickHouse)> {
    let Storage::ClickHouse {
        endpoint, ca_file, ..
    } = &input.configuration.backend
    else {
        return Err(Error::Input);
    };
    Ok((
        endpoint,
        ca_file,
        input.clickhouse.as_ref().ok_or(Error::Input)?,
    ))
}
pub(in crate::installation) async fn execute(
    input: &Request,
    label: &str,
    statement: &str,
) -> Result<String> {
    let (_, _, credentials) = configuration(input)?;
    let password =
        crate::config::secret(&credentials.installer.password_file).map_err(|_| Error::Input)?;
    execute_as(
        input,
        label,
        statement,
        &credentials.installer.user,
        &password,
    )
    .await
}
async fn execute_as(
    input: &Request,
    label: &str,
    statement: &str,
    login: &str,
    password: &str,
) -> Result<String> {
    let (endpoint, ca, _) = configuration(input)?;
    let url = url::Url::parse(endpoint).map_err(|_| Error::Input)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Input);
    }
    let ca = reqwest::Certificate::from_pem(
        &crate::config::read(ca, 1024 * 1024, false).map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let client = Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(6))
        .timeout(std::time::Duration::from_secs(65))
        .build()
        .map_err(|_| Error::Input)?;
    let id = Uuid::new_v5(&input.operation_id, label.as_bytes()).to_string();
    let mut response = client
        .post(url)
        .basic_auth(login, Some(password))
        .query(&[
            ("query_id", id.as_str()),
            ("wait_end_of_query", "1"),
            ("max_execution_time", "60"),
            ("log_queries", "0"),
            ("log_query_threads", "0"),
        ])
        .body(statement.to_owned())
        .send()
        .await
        .map_err(|_| Error::Storage)?;
    if !response.status().is_success() {
        return Err(Error::Storage);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(Error::Storage);
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| Error::Corrupt)
}
pub(super) async fn check_version(input: &Request) -> Result<()> {
    if execute(input, "version", "SELECT version() FORMAT TabSeparated")
        .await?
        .trim()
        != "25.8.12.129"
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}
fn user(value: &str) -> Result<String> {
    identifier(value)?;
    Ok(format!("`{value}`"))
}
pub(super) async fn install(input: &Request, journal: &Journal) -> Result<()> {
    let Storage::ClickHouse {
        writer,
        maintenance,
        ..
    } = &input.configuration.backend
    else {
        return Err(Error::Input);
    };
    let (_, _, bootstrap) = configuration(input)?;
    let mut names = std::collections::BTreeSet::new();
    for name in [&writer.user, &maintenance.user, &bootstrap.installer.user] {
        user(name)?;
        if !names.insert(name) {
            return Err(Error::Input);
        }
    }
    let mut pg =
        PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    let instance: String = sqlx::query_scalar("SELECT id::text FROM rss_ts_ch.installation")
        .fetch_one(&mut pg)
        .await
        .map_err(|_| Error::Storage)?;
    pg.close().await.map_err(|_| Error::Storage)?;
    if !journal
        .load::<bool>("clickhouse-reserved.json")?
        .unwrap_or(false)
    {
        if execute(
            input,
            "reserve-database",
            "SELECT count() FROM system.databases WHERE name='rss_ts_ch' FORMAT TabSeparated",
        )
        .await?
        .trim()
            != "0"
        {
            return Err(Error::Conflict);
        }
        for credential in [writer, maintenance] {
            if execute(
                input,
                &format!("reserve-user-{}", credential.user),
                &format!(
                    "SELECT count() FROM system.users WHERE name={} FORMAT TabSeparated",
                    literal(&credential.user)
                ),
            )
            .await?
            .trim()
                != "0"
            {
                return Err(Error::Conflict);
            }
        }
        journal.save("clickhouse-reserved.json", &true)?;
    }
    let statements =
        rss_timeseries_clickhouse::installation_sql(&instance).map_err(|_| Error::Input)?;
    for (index, statement) in statements.iter().enumerate() {
        let writes_identity = statement.starts_with("INSERT INTO rss_ts_ch.installation ");
        let step = if writes_identity {
            format!(
                "INSERT INTO rss_ts_ch.installation SELECT {} WHERE NOT EXISTS(SELECT 1 FROM rss_ts_ch.installation)",
                literal(&instance)
            )
        } else if let Some(definition) =
            statement.strip_prefix("ALTER TABLE rss_ts_ch.raw ADD INDEX ")
        {
            format!("ALTER TABLE rss_ts_ch.raw ADD INDEX IF NOT EXISTS {definition}")
        } else {
            statement
                .replacen("CREATE DATABASE ", "CREATE DATABASE IF NOT EXISTS ", 1)
                .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        };
        execute(input, &format!("install-{index}"), &step).await?;
        if writes_identity
            && execute(
                input,
                "installation-identity",
                "SELECT id FROM rss_ts_ch.installation FORMAT TabSeparated",
            )
            .await?
            .trim()
                != instance
        {
            return Err(Error::Conflict);
        }
    }
    provision_users(input, true).await
}
pub(in crate::installation) async fn provision_users(input: &Request, writes: bool) -> Result<()> {
    let Storage::ClickHouse {
        writer,
        maintenance,
        ..
    } = &input.configuration.backend
    else {
        return Err(Error::Input);
    };
    let (_, _, bootstrap) = configuration(input)?;
    for credential in [writer, maintenance] {
        let password =
            crate::config::secret(&credential.password_file).map_err(|_| Error::Input)?;
        execute(
            input,
            &format!("create-user-{}", credential.user),
            &format!(
                "CREATE USER IF NOT EXISTS {} IDENTIFIED WITH sha256_password BY {}",
                user(&credential.user)?,
                literal(&password)
            ),
        )
        .await?;
    }
    let maintenance_policy = maintenance.user.clone();
    let writer = user(&writer.user)?;
    let maintenance = user(&maintenance.user)?;
    let installer = user(&bootstrap.installer.user)?;
    let mut grants = vec![
        format!("GRANT SELECT ON rss_ts_ch.installation TO {writer},{maintenance}"),
        format!("GRANT CREATE TEMPORARY TABLE ON *.* TO {writer}"),
        format!("GRANT SELECT ON rss_ts_ch.active_attempts TO {writer}"),
        format!("GRANT SELECT ON rss_ts_ch.guard_identity TO {writer}"),
        format!("GRANT SELECT ON system.* TO {maintenance}"),
        format!("GRANT SHOW ACCESS ON *.* TO {maintenance}"),
        format!("GRANT SHOW COLUMNS ON rss_ts_ch.* TO {maintenance}"),
        format!("GRANT KILL QUERY ON *.* TO {maintenance}"),
    ];
    for table in ["raw", "summaries"] {
        grants.push(format!(
            "GRANT SELECT ON rss_ts_ch.{table} TO {maintenance}"
        ));
        if writes {
            grants.push(format!("GRANT INSERT ON rss_ts_ch.{table} TO {writer}"));
            grants.push(format!(
                "GRANT ALTER DELETE ON rss_ts_ch.{table} TO {maintenance}"
            ));
        }
        grants.push(format!("CREATE ROW POLICY IF NOT EXISTS telemetry_maintenance_{maintenance_policy}_{table} ON rss_ts_ch.{table} USING 1 TO {maintenance},{installer}"));
    }
    for (index, grant) in grants.iter().enumerate() {
        execute(input, &format!("grant-{index}"), grant).await?;
    }
    Ok(())
}

pub(super) async fn reader_exists(input: &Request, name: &str) -> Result<bool> {
    let sql = format!(
        "SELECT count() FROM system.users WHERE name={} FORMAT TabSeparated",
        literal(name)
    );
    match execute(input, "reader-exists", &sql).await?.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Error::Corrupt),
    }
}
/// Never adopt an account with unrelated roles, grants or row policies. Partial
/// grants are possible only while recovering this same reserved operation.
async fn verify_reader_catalog(
    input: &Request,
    tenant: rss_request_context::TenantId,
    name: &str,
    detached: bool,
) -> Result<()> {
    user(name)?;
    let login = literal(name);
    let grants = format!(
        "SELECT count() FROM system.grants WHERE user_name={login} AND NOT (access_type='SELECT' AND ifNull(database,'')='rss_ts_ch' AND ifNull(table,'') IN ('installation','raw','summaries') AND column IS NULL AND NOT grant_option AND NOT is_partial_revoke) FORMAT TabSeparated"
    );
    let roles = format!(
        "SELECT count() FROM system.role_grants WHERE user_name={login} FORMAT TabSeparated"
    );
    let targets = if detached {
        format!("(apply_to_list=[{login}] OR empty(apply_to_list))")
    } else {
        format!("apply_to_list=[{login}]")
    };
    let mut expected = Vec::new();
    for table in ["raw", "summaries"] {
        expected.push(format!("(table={table} AND short_name={policy} AND replaceRegexpAll(ifNull(select_filter,''),'[[:space:]]','')={filter} AND NOT is_restrictive AND NOT apply_to_all AND {targets} AND empty(apply_to_except))",table=literal(table),policy=literal(&format!("telemetry_reader_{name}_{table}")),filter=literal(&format!("tenant='{}'",tenant))));
    }
    let policies = format!(
        "SELECT count() FROM system.row_policies WHERE database='rss_ts_ch' AND (apply_to_all OR has(apply_to_list,{login}) OR short_name IN ({},{})) AND NOT ({}) FORMAT TabSeparated",
        literal(&format!("telemetry_reader_{name}_raw")),
        literal(&format!("telemetry_reader_{name}_summaries")),
        expected.join(" OR ")
    );
    for (label, statement) in [
        ("reader-roles", roles),
        ("reader-grants", grants),
        ("reader-policies", policies),
    ] {
        if execute(input, label, &statement).await?.trim() != "0" {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
async fn authenticates(input: &Request, name: &str, secret: &str) -> bool {
    execute_as(
        input,
        "reader-login",
        "SELECT currentUser() FORMAT TabSeparated",
        name,
        secret,
    )
    .await
    .is_ok_and(|v| v.trim() == name)
}
/// An existing verifier can remain valid across provider password policy changes.
async fn current_login(
    input: &Request,
    material: &rss_mdm_telemetry_service::selection::Reader,
    previous: Option<&rss_mdm_telemetry_service::selection::Reader>,
) -> Result<bool> {
    if let Some(secret) = material.password.as_deref()
        && authenticates(input, &material.user, secret).await
    {
        return Ok(true);
    }
    if let Some(secret) = previous.and_then(|r| r.password.as_deref())
        && authenticates(input, &material.user, secret).await
    {
        return Ok(false);
    }
    Err(Error::Conflict)
}
async fn drop_reader_policies(input: &Request, name: &str) -> Result<()> {
    for table in ["raw", "summaries"] {
        execute(
            input,
            &format!("remove-reader-policy-{table}"),
            &format!(
                "DROP ROW POLICY IF EXISTS telemetry_reader_{name}_{table} ON rss_ts_ch.{table}"
            ),
        )
        .await?;
    }
    Ok(())
}
use rss_mdm_telemetry_service::selection::Reader;
/// The worker's tenant-scoped login survives external password rotation and retirement while work exists.
pub(in crate::installation) async fn reconcile(
    input: &Request,
    tenant: rss_request_context::TenantId,
    previous: Option<&Reader>,
    desired: Option<&Reader>,
) -> Result<()> {
    let before = previous.and_then(Reader::background);
    let after = desired.and_then(Reader::background);
    if previous.and_then(|r| r.worker.as_ref()) != desired.and_then(|r| r.worker.as_ref()) {
        reconcile_login(input, tenant, before.as_ref(), after.as_ref()).await?;
    }
    reconcile_login(input, tenant, previous, desired).await
}
async fn reconcile_login(
    input: &Request,
    tenant: rss_request_context::TenantId,
    previous: Option<&Reader>,
    desired: Option<&Reader>,
) -> Result<()> {
    match (previous, desired) {
        (_, Some(next)) => provision_reader(input, tenant, next, previous).await,
        (Some(old), None) => provision_reader(input, tenant, &old.inactive(), Some(old)).await,
        (None, None) => Ok(()),
    }
}
/// Establish policies before granting table access. The caller reserves a new login
/// or verifies its durable ownership before replay, rotation and restore.
pub(in crate::installation) async fn provision_reader(
    input: &Request,
    tenant: rss_request_context::TenantId,
    material: &rss_mdm_telemetry_service::selection::Reader,
    previous: Option<&rss_mdm_telemetry_service::selection::Reader>,
) -> Result<()> {
    let name = user(&material.user)?;
    let exists = reader_exists(input, &material.user).await?;
    verify_reader_catalog(input, tenant, &material.user, !exists).await?;
    let current = if exists {
        current_login(input, material, previous).await?
    } else {
        false
    };
    let Some(password) = material.password.as_ref() else {
        execute(
            input,
            "retire-reader",
            &format!("DROP USER IF EXISTS {name}"),
        )
        .await?;
        return drop_reader_policies(input, &material.user).await;
    };
    if !exists {
        drop_reader_policies(input, &material.user).await?;
        execute(
            input,
            "create-reader",
            &format!(
                "CREATE USER {name} IDENTIFIED WITH sha256_password BY {}",
                literal(password)
            ),
        )
        .await?;
    } else if !current {
        execute(
            input,
            "reader-password",
            &format!(
                "ALTER USER {name} IDENTIFIED WITH sha256_password BY {}",
                literal(password)
            ),
        )
        .await?;
    }
    for table in ["raw", "summaries"] {
        execute(input,&format!("reader-policy-{table}"),&format!("CREATE ROW POLICY IF NOT EXISTS telemetry_reader_{}_{table} ON rss_ts_ch.{table} USING tenant={} TO {name}",material.user,literal(&tenant.to_string()))).await?;
    }
    for table in ["installation", "raw", "summaries"] {
        execute(
            input,
            &format!("reader-select-{table}"),
            &format!("GRANT SELECT ON rss_ts_ch.{table} TO {name}"),
        )
        .await?;
    }
    Ok(())
}
