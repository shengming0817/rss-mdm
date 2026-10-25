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
    let operation = Uuid::new_v4();
    let manifest = "a".repeat(64);
    reserve_restore(&mut owner, operation, &manifest).await?;
    reserve_restore(&mut owner, operation, &manifest).await?;
    ensure!(matches!(
        reserve_restore(&mut owner, Uuid::new_v4(), &manifest).await,
        Err(Error::Conflict)
    ));
    ensure!(matches!(
        reserve_restore(&mut owner, operation, &"b".repeat(64)).await,
        Err(Error::Conflict)
    ));
    let retained: (Uuid, String) = sqlx::query_as(
        "SELECT operation,manifest FROM public.mdm_restore_operation WHERE singleton",
    )
    .fetch_one(&mut owner)
    .await?;
    ensure!(retained == (operation, manifest));
    owner.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=installation.backup: default installation and the shared capture/restore verifier"]
async fn plain_backup_verification_has_no_ledger_dependency() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let options = std::env::var("MDM_OWNER_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    crate::migration::migrate(
        &options,
        &crate::migration::Installation {
            instance_id: crate::test_support::identity::INSTANCE.into(),
            target: [1; 16],
            lineage: [2; 16],
            audit_mode: crate::migration::AuditMode::Plain,
        },
    )
    .await?;
    let mut owner = sqlx::PgConnection::connect_with(&options).await?;
    let absent: bool = sqlx::query_scalar("SELECT to_regnamespace('rss_ledger') IS NULL")
        .fetch_one(&mut owner)
        .await?;
    ensure!(absent);
    let tenant: String =
        sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation")
            .fetch_one(&mut owner)
            .await?;
    owner.close().await?;
    let admin = url::Url::parse(&std::env::var("MDM_ADMIN_URL")?)?;
    let root = tempfile::tempdir()?;
    let password = root.path().join("operator-password");
    std::fs::write(
        &password,
        admin
            .password()
            .ok_or_else(|| anyhow::anyhow!("fixture password"))?,
    )?;
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600))?;
    let database = crate::config::Database {
        host: options.get_host().into(),
        port: options.get_port(),
        name: options
            .get_database()
            .ok_or_else(|| anyhow::anyhow!("fixture database"))?
            .into(),
        user: admin.username().into(),
        password_file: password,
        ca_file: std::env::var("PG_CA_FILE")?.into(),
    };
    let heads = ledger::verify_operator(
        &serde_json::json!({"audit":{"mode":"plain"}}),
        std::slice::from_ref(&tenant),
        &database,
    )
    .await?;
    ensure!(
        heads.len() == 1
            && heads[0].tenant == tenant
            && heads[0].key_id.is_none()
            && heads[0].sequence.is_none()
            && heads[0].tag.is_none()
            && heads[0].verified_records.is_none()
    );
    Ok(())
}
