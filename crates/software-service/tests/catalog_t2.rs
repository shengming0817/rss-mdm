//! Component catalog tests use real tenant transactions; no App dependency.
use anyhow::{Result, ensure};
use rss_mdm_software_service::catalog;
use serde_json::Value;
use sqlx::{
    Connection, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};

async fn connection(admin: bool) -> Result<PgConnection> {
    let mut options: PgConnectOptions = std::env::var(if admin {
        "MDM_ADMIN_URL"
    } else {
        "DATABASE_URL"
    })?
    .parse()?;
    if !admin {
        options = options
            .username("mdm_flow_runtime")
            .password("runtime-fixture");
    }
    Ok(PgConnection::connect_with(
        &options
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?),
    )
    .await?)
}
async fn admitted(connection: &mut PgConnection) -> Result<bool> {
    let valid: bool = sqlx::query_scalar(catalog::ADMISSION_SQL)
        .fetch_one(&mut *connection)
        .await?;
    let actual: String = sqlx::query_scalar(catalog::CATALOG_SQL)
        .fetch_one(connection)
        .await?;
    Ok(valid
        && serde_json::from_str::<Value>(&actual)?
            == serde_json::from_str::<Value>(catalog::CATALOG_JSON)?)
}
#[tokio::test]
#[ignore = "MODULE=software.catalog: schema and effective privilege admission"]
async fn schema_and_effective_privileges_are_exact() -> Result<()> {
    let mut root = connection(true).await?;
    let mut runtime = connection(false).await?;
    ensure!(admitted(&mut runtime).await?);
    for (change, restore) in [
        (
            "ALTER TABLE mdm_software.sources DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_software.sources ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE mdm_software.sources NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_software.sources FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON mdm_software.sources USING (true) WITH CHECK (true)",
            "ALTER POLICY tenant ON mdm_software.sources USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE TABLE mdm_software.unexpected(id integer)",
            "DROP TABLE mdm_software.unexpected",
        ),
        (
            "GRANT DELETE ON mdm_software.sources TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_software.sources FROM mdm_flow_runtime",
        ),
        (
            "GRANT UPDATE(definition) ON mdm_software.sources TO mdm_flow_runtime",
            "REVOKE UPDATE(definition) ON mdm_software.sources FROM mdm_flow_runtime",
        ),
        (
            "CREATE ROLE mdm_software_drift; GRANT USAGE ON SCHEMA mdm_software TO mdm_software_drift; GRANT UPDATE(definition) ON mdm_software.sources TO mdm_software_drift; GRANT mdm_software_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE mdm_software_drift FROM mdm_flow_runtime; DROP OWNED BY mdm_software_drift; DROP ROLE mdm_software_drift",
        ),
    ] {
        sqlx::raw_sql(change).execute(&mut root).await?;
        let valid = admitted(&mut runtime).await;
        sqlx::raw_sql(restore).execute(&mut root).await?;
        ensure!(!valid?, "accepted privilege drift: {change}");
        ensure!(admitted(&mut runtime).await?);
    }
    sqlx::raw_sql("CREATE ROLE mdm_software_dormant; GRANT UPDATE(definition) ON mdm_software.sources TO mdm_software_dormant; GRANT mdm_software_dormant TO mdm_flow_runtime WITH INHERIT FALSE, SET FALSE").execute(&mut root).await?;
    let dormant = admitted(&mut runtime).await;
    sqlx::raw_sql("REVOKE mdm_software_dormant FROM mdm_flow_runtime; DROP OWNED BY mdm_software_dormant; DROP ROLE mdm_software_dormant").execute(&mut root).await?;
    ensure!(dormant?, "non-executable role was treated as authority");
    root.close().await?;
    runtime.close().await?;
    Ok(())
}

#[path = "../../../tests/support/software/mod.rs"]
mod materials;
#[path = "catalog/transactions.rs"]
mod transactions;

#[path = "support/imports.rs"]
mod imported_fixture;
