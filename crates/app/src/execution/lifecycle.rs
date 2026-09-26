use super::*;
pub(crate) struct Resource(pub(crate) Arc<ExecutionService>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "command-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let outcome = self.0.reconcile.close(&control).await;
        self.0.runtime.close().await;
        match outcome {
            rss_reconcile_postgres::CloseOutcome::Drained => Ok(()),
            _ => Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                "command storage close incomplete",
            ))),
        }
    }
}
