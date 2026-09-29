//! Capture process diagnostics in the Rust owner test, without a Python test-name roster.
use super::*;

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
