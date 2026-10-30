//! Capture process diagnostics in the Rust owner test, without a Python test-name roster.
use super::{runtime::*, *};

pub(crate) async fn captured_test(
    name: &str,
    budget: Duration,
) -> Result<Option<std::process::Output>> {
    const CHILD: &str = "_MDM_TEST_SUBPROCESS";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return Ok(None);
    }
    let (_, test) = name
        .split_once("::")
        .ok_or_else(|| anyhow::anyhow!("test module path"))?;
    let child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", test, "--nocapture"])
        .env(CHILD, name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = tokio::time::timeout(budget, child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "test subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "test subprocess did not run exactly one case"
    );
    Ok(Some(output))
}

pub(crate) fn command(args: &[&str], input: Option<&str>) -> Result<String> {
    let mut c = Command::new("docker");
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn()?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let result = child.wait_with_output()?;
    ensure!(
        result.status.success(),
        "owned fixture command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

pub(crate) fn pg(sql: &str) -> Result<String> {
    pg_tenant(case_tenant(), sql)
}

pub(crate) fn pg_tenant(tenant: &str, sql: &str) -> Result<String> {
    uuid::Uuid::parse_str(tenant)?;
    let config: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
    command(
        &[
            "exec",
            "-i",
            config["container"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("PG container"))?,
            "psql",
            "-X",
            "-U",
            "postgres",
            "-d",
            config["database"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("PG database"))?,
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        Some(&format!(
            "BEGIN; SET LOCAL rss.tenant_id='{tenant}'; {sql}; COMMIT;"
        )),
    )
}
