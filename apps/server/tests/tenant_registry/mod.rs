use super::*;

mod business;

async fn owner() -> anyhow::Result<PgConnection> {
    use std::str::FromStr;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    Ok(PgConnection::connect_with(&options).await?)
}
async fn profile(role: &str, password: &str) -> anyhow::Result<PgConnection> {
    use std::str::FromStr;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .username(role)
        .password(password)
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    Ok(PgConnection::connect_with(&options).await?)
}

#[tokio::test]
#[ignore = "MODULE=installation.migration: failed rollback retains primary reason and cleanup evidence"]
async fn rollback_failure_preserves_primary_reason_and_cleanup_evidence() -> anyhow::Result<()> {
    use anyhow::ensure;
    let mut conn = owner().await?;
    let mut admin = profile("postgres", "local-fixture").await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut conn)
        .await?;
    let tx = conn.begin().await?;
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&mut admin)
        .await?;
    ensure!(terminated);
    let operation = Some(Uuid::new_v4());
    let result: RegistryResult<()> = rollback(tx, Err(Reason::Conflict), operation).await;
    let failure = settle(conn, operation, result).await.unwrap_err();
    ensure!(
        failure.reason == Reason::Conflict
            && failure.cleanup_failed
            && failure.operation_id == operation
    );
    admin.close().await?;
    Ok(())
}
