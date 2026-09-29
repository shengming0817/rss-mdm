use super::*;
#[tokio::test]
#[ignore = "MODULE=inventory.process: real PostgreSQL"]
async fn process_death() -> Result<()> {
    let executable = &std::env::var("MDM_FIXTURE_BIN")?;
    let a = app(scope(3, "crash")).await?;
    a.ingest(batch("crash", 0, Body::Snapshot(facts("AfterRestart"))))
        .await?;
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    sqlx::raw_sql("CREATE FUNCTION mdm.pause_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2346001); PERFORM pg_sleep(25); RETURN NEW; END $$; CREATE TRIGGER pause_write AFTER INSERT ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.pause_write();").execute(&owner).await?;
    let dir = std::env::temp_dir().join(format!("mdm-scope-{}.json", std::process::id()));
    std::fs::write(&dir, scope(3, "crash").encode()?)?;
    let mut child = std::process::Command::new(executable)
        .arg("project")
        .env("MDM_SCOPE_FILE", &dir)
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let admin = storage::pool(&url("MDM_ADMIN_URL")?).await?;
    let reached=tokio::time::timeout(Duration::from_secs(15),async {
        loop {
            let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=2346001 AND granted)").fetch_one(&admin).await?;
            if staged {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await;
    child.kill()?;
    child.wait()?;
    std::fs::remove_file(dir)?;
    reached??;
    // Kill backend too: the client vanished during server pg_sleep; wait for rollback.
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND objid=2346001 AND granted").execute(&admin).await?;
    sqlx::raw_sql("DROP TRIGGER pause_write ON mdm.inventory; DROP FUNCTION mdm.pause_write();")
        .execute(&owner)
        .await?;
    let view = inspect(&a, "crash").await?;
    assert!(view["assets"].as_array().unwrap().is_empty());
    assert!(view["checkpoint"].is_null());
    a.close().await?;
    let restart = app(scope(3, "crash")).await?;
    assert_eq!(
        restart.project(&CancellationToken::new()).await?["applied"],
        1
    );
    restart.close().await?;
    storage::close_pool(&admin).await?;
    storage::close_pool(&owner).await?;
    Ok(())
}
