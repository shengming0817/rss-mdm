use super::*;
#[tokio::test]
#[ignore = "MODULE=examples.cli: real PostgreSQL"]
async fn cli_roundtrip() -> Result<()> {
    let executable = &std::env::var("MDM_FIXTURE_BIN")?;
    let dir = std::env::temp_dir().join(format!("mdm-cli-{}", std::process::id()));
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
    let bad = std::process::Command::new(executable)
        .arg("inspect")
        .arg("cli")
        .env("MDM_SCOPE_FILE", dir.join("scope.json"))
        .env(
            "DATABASE_URL",
            "postgres://invalid:SECRET@localhost:1/missing",
        )
        .output()?;
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("SECRET"));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
