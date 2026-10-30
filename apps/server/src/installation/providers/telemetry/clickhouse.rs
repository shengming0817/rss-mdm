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
    let (endpoint, ca, credentials) = configuration(input)?;
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
    let password =
        crate::config::secret(&credentials.installer.password_file).map_err(|_| Error::Input)?;
    let id = Uuid::new_v5(&input.operation_id, label.as_bytes()).to_string();
    let mut response = client
        .post(url)
        .basic_auth(&credentials.installer.user, Some(password.as_str()))
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
        reader,
        writer,
        maintenance,
        ..
    } = &input.configuration.backend
    else {
        return Err(Error::Input);
    };
    let (_, _, bootstrap) = configuration(input)?;
    let mut names = std::collections::BTreeSet::new();
    for name in [
        &reader.user,
        &writer.user,
        &maintenance.user,
        &bootstrap.installer.user,
    ] {
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
        for credential in [reader, writer, maintenance] {
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
        let step = if statement.starts_with("INSERT INTO rss_ts_ch.installation") {
            format!(
                "INSERT INTO rss_ts_ch.installation SELECT {} WHERE NOT EXISTS(SELECT 1 FROM rss_ts_ch.installation)",
                literal(&instance)
            )
        } else {
            statement
                .replacen("CREATE DATABASE ", "CREATE DATABASE IF NOT EXISTS ", 1)
                .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        };
        execute(input, &format!("install-{index}"), &step).await?;
        if index == 2
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
    provision_users(input).await
}
pub(in crate::installation) async fn provision_users(input: &Request) -> Result<()> {
    let Storage::ClickHouse {
        reader,
        writer,
        maintenance,
        ..
    } = &input.configuration.backend
    else {
        return Err(Error::Input);
    };
    let (_, _, bootstrap) = configuration(input)?;
    for credential in [reader, writer, maintenance] {
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
    let reader_policy = reader.user.clone();
    let maintenance_policy = maintenance.user.clone();
    let reader = user(&reader.user)?;
    let writer = user(&writer.user)?;
    let maintenance = user(&maintenance.user)?;
    let installer = user(&bootstrap.installer.user)?;
    let mut grants = vec![
        format!("GRANT SELECT ON rss_ts_ch.installation TO {reader},{writer},{maintenance}"),
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
            "GRANT SELECT ON rss_ts_ch.{table} TO {reader},{maintenance}"
        ));
        grants.push(format!("GRANT INSERT ON rss_ts_ch.{table} TO {writer}"));
        grants.push(format!(
            "GRANT ALTER DELETE ON rss_ts_ch.{table} TO {maintenance}"
        ));
        grants.push(format!("CREATE ROW POLICY IF NOT EXISTS telemetry_reader_{reader_policy}_{table} ON rss_ts_ch.{table} USING tenant={} TO {reader}",literal(&input.tenant)));
        grants.push(format!("CREATE ROW POLICY IF NOT EXISTS telemetry_maintenance_{maintenance_policy}_{table} ON rss_ts_ch.{table} USING 1 TO {maintenance},{installer}"));
    }
    for (index, grant) in grants.iter().enumerate() {
        execute(input, &format!("grant-{index}"), grant).await?;
    }
    Ok(())
}
