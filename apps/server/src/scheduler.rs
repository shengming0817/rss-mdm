//! One host-owned scheduling pool shared by independently registered business workers.
use rss_mdm_work_page::scheduler::Scheduler;
use rss_reconcile_postgres::CloseOutcome;
use rss_runtime::ShutdownError;
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
pub(crate) struct SchedulerStorage {
    name: &'static str,
    pool: sqlx::PgPool,
    admitted: Arc<OnceLock<Scheduler>>,
}
impl SchedulerStorage {
    pub(crate) async fn open(
        name: &'static str,
        options: sqlx::postgres::PgConnectOptions,
        register: impl FnOnce(Self),
    ) -> Result<Scheduler, crate::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(crate::background::SCHEDULER_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?;
        // Startup can be cancelled while the provider probes this pool.
        let admitted = Arc::new(OnceLock::new());
        register(Self {
            name,
            pool: pool.clone(),
            admitted: admitted.clone(),
        });
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let scheduler = Scheduler::new(pool, &control)
            .await
            .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?;
        Ok(admitted.get_or_init(|| scheduler).clone())
    }
}
impl rss_runtime::ManagedResource for SchedulerStorage {
    fn name(&self) -> &str {
        self.name
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let Some(store) = self.admitted.get() else {
            self.pool.close().await;
            return Ok(());
        };
        match store.close(&control).await {
            CloseOutcome::Drained => Ok(()),
            CloseOutcome::Deadline => Err(ShutdownError::deadline_exceeded(std::io::Error::other(
                "scheduler drain deadline",
            ))),
            CloseOutcome::Cancelled => Err(ShutdownError::new(std::io::Error::other(
                "scheduler drain cancelled",
            ))),
        }
    }
}
