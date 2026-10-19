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
#[ignore = "MODULE=installation.restart: original container policy survives quiescence and actually restarts after failure"]
async fn original_restart_policy_is_restored_after_quiescence() -> Result<()> {
    let providers: Value =
        serde_json::from_str(include_str!("../../../../deployment/providers.lock.json"))?;
    let image = providers["nginx"].as_str().unwrap();
    let name = format!("mdm-restart-{}", Uuid::new_v4().simple());
    let id = super::super::deployment::docker(&[
        "run",
        "--detach",
        "--name",
        &name,
        "--restart=on-failure:3",
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        "trap 'exit 0' TERM; while [ ! -e /tmp/fail ]; do sleep 1; done; rm /tmp/fail; exit 42",
    ])
    .await?;
    let name = String::from_utf8(id)?.trim().to_owned();
    let result = async {
        let saved = inspect(&name).await?;
        stop(std::slice::from_ref(&name)).await?;
        ensure!(inspect(&name).await?["HostConfig"]["RestartPolicy"]["Name"] == "no");
        start_with_policy(&name, &saved).await?;
        ensure!(
            inspect(&name).await?["HostConfig"]["RestartPolicy"]
                == saved["HostConfig"]["RestartPolicy"]
        );
        tokio::time::sleep(std::time::Duration::from_secs(11)).await;
        // PID 1 exits itself: namespace peers cannot SIGKILL it, and docker kill is a manual stop.
        super::super::deployment::docker(&["exec", &name, "touch", "/tmp/fail"]).await?;
        for _ in 0..30 {
            let actual = inspect(&name).await?;
            if actual["RestartCount"].as_u64().unwrap_or(0) > 0
                && actual["State"]["Running"] == true
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        anyhow::bail!("restored restart policy did not restart the failed process")
    }
    .await;
    let cleanup = super::super::deployment::docker(&["rm", "--force", &name]).await;
    result?;
    cleanup?;
    Ok(())
}
