use rss_contract::Timepoint;
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{sync::Arc, time::Duration};
pub fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
pub fn foreign() -> TenantId {
    TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap()
}
pub fn at(n: i64) -> Timepoint {
    Timepoint::try_from(n).unwrap()
}
pub struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep_until(d.instant().into()).await;
    }
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(20)).unwrap(),
        &Timer,
    )
}
pub fn config() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG").unwrap()).unwrap())
        .unwrap()
}
pub async fn runtime() -> Arc<PgRuntime> {
    runtime_at(None).await
}
pub async fn runtime_at(port: Option<u16>) -> Arc<PgRuntime> {
    let c = config();
    let config = PgConfig::new(
        "localhost",
        port.unwrap_or(c["port"].as_u64().unwrap() as u16),
        "backend",
        "mdm_software_release_runtime",
        PgPassword::new("backend-fixture"),
        PgPrivateCa::from_pem(std::fs::read(c["ca"].as_str().unwrap()).unwrap()).unwrap(),
    );
    Arc::new(
        PgRuntime::connect_producer(
            config,
            Timer,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                vec![
                    (tenant(), Epoch::new(1).unwrap()),
                    (foreign(), Epoch::new(1).unwrap()),
                ],
            )
            .unwrap(),
        )
        .await
        .unwrap(),
    )
}
pub fn sql(statement: &str) -> String {
    use std::io::Write;
    let c = config();
    let mut child = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            c["container"].as_str().unwrap(),
            "psql",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "backend",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(statement.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "PG fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
pub fn unique() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "p{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}
