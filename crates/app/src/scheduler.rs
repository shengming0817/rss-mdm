//! One host-owned scheduling pool shared by independently registered business workers.
use rss_reconcile_postgres::PgStore;
use std::time::Duration;
#[derive(Clone)]
pub(crate) struct SchedulerStorage {
    pub(crate) store: PgStore,
}
impl SchedulerStorage {
    pub(crate) async fn open(
        options: sqlx::postgres::PgConnectOptions,
    ) -> Result<Self, crate::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| crate::Error::Unavailable(crate::Failure::FlowConnection))?;
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        match PgStore::new(pool.clone(), &control).await {
            Ok(store) => Ok(Self { store }),
            Err(_) => {
                pool.close().await;
                Err(crate::Error::Unavailable(crate::Failure::FlowAdmission))
            }
        }
    }
}
impl rss_runtime::ManagedResource for SchedulerStorage {
    fn name(&self) -> &str {
        "mdm-scheduler-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        match self.store.close(&control).await {
            rss_reconcile_postgres::CloseOutcome::Drained => Ok(()),
            _ => Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                "scheduler did not drain",
            ))),
        }
    }
}
