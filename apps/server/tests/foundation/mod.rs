//! Product consumer proofs. No test is a prerequisite or seed for another test.
mod audit;
mod authorization;
mod lifecycle;
mod tenants;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "T2: shared installation, tenant readers, real relay and cold recovery"]
async fn shared_telemetry_on_a_running_installation() -> anyhow::Result<()> {
    lifecycle::shared_telemetry().await
}
