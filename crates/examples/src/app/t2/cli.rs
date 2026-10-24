use super::*;
#[tokio::test]
#[ignore = "MODULE=examples.cli: real PostgreSQL"]
async fn cli_roundtrip() -> Result<()> {
    let executable = &std::env::var("MDM_FIXTURE_BIN")?;
    let dir = std::env::temp_dir().join(format!("mdm-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("scope.json"), scope(5, "cli").encode()?)?;
    std::fs::write(
        dir.join("batch.json"),
        batch("cli", 0, Body::Snapshot(facts("CLI"))).encode(),
    )?;
    let call = |args: Vec<String>| -> Result<serde_json::Value> {
        let output = std::process::Command::new(executable)
            .args(args)
            .env("MDM_SCOPE_FILE", dir.join("scope.json"))
            .output()?;
        ensure!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    assert_eq!(
        call(vec![
            "ingest-fixture".into(),
            dir.join("batch.json").to_string_lossy().into_owned()
        ])?["receipt"],
        "accepted"
    );
    assert_eq!(call(vec!["project".into()])?["applied"], 1);
    assert_eq!(
        call(vec!["inspect".into(), "cli".into()])?["assets"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    std::fs::write(
        dir.join("failure.json"),
        batch("cli-failure", 1, Body::Snapshot(facts("Recovery"))).encode(),
    )?;
    let owner = storage::pool(&url("MDM_OWNER_URL")?).await?;
    sqlx::raw_sql("CREATE FUNCTION mdm.cli_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.run='cli-failure' THEN RAISE EXCEPTION 'SECRET-provider'; END IF; RETURN NEW; END $$; CREATE TRIGGER cli_failure BEFORE INSERT ON mdm.collection_results FOR EACH ROW EXECUTE FUNCTION mdm.cli_failure();").execute(&owner).await?;
    let bad = std::process::Command::new(executable)
        .arg("ingest-fixture")
        .arg(dir.join("failure.json"))
        .env("MDM_SCOPE_FILE", dir.join("scope.json"))
        .output();
    sqlx::raw_sql(
        "DROP TRIGGER cli_failure ON mdm.collection_results; DROP FUNCTION mdm.cli_failure();",
    )
    .execute(&owner)
    .await?;
    storage::close_pool(&owner).await?;
    let bad = bad?;
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&bad.stderr)?;
    assert_eq!(
        report["problems"][0],
        serde_json::json!({"stage":"ingest","component":"database","kind":"UnavailableOrRejected"})
    );
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("SECRET"));
    assert_eq!(
        call(vec![
            "ingest-fixture".into(),
            dir.join("failure.json").to_string_lossy().into_owned()
        ])?["receipt"],
        "accepted"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
