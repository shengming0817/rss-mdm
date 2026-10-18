use super::*;
use anyhow::{Result, ensure};
#[tokio::test]
#[ignore = "MODULE=installation.backup: real CONNECT fence and grant-option-preserving recovery"]
async fn database_connection_fence_replays_and_restores_original_grants() -> Result<()> {
    let options = std::env::var("MDM_OWNER_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    sqlx::raw_sql("DO $test$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO mdm_runtime WITH GRANT OPTION',current_database()); END $test$;").execute(&mut owner).await?;
    let runtime = options
        .clone()
        .username("mdm_runtime")
        .password("runtime-fixture");
    sqlx::PgConnection::connect_with(&runtime)
        .await?
        .close()
        .await?;
    let temp = tempfile::tempdir()?;
    let journal = Journal::open(&temp.path().canonicalize()?.join("backup"))?;
    connection_fence(&mut owner, &journal, true).await?;
    ensure!(sqlx::PgConnection::connect_with(&runtime).await.is_err());
    connection_fence(&mut owner, &journal, true).await?;
    connection_fence(&mut owner, &journal, false).await?;
    sqlx::PgConnection::connect_with(&runtime)
        .await?
        .close()
        .await?;
    let grantable:bool=sqlx::query_scalar("SELECT bool_or(a.is_grantable) FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a WHERE d.datname=current_database() AND a.grantee='mdm_runtime'::regrole AND a.privilege_type='CONNECT'").fetch_one(&mut owner).await?;
    ensure!(grantable);
    connection_fence(&mut owner, &journal, false).await?;
    owner.close().await?;
    Ok(())
}
