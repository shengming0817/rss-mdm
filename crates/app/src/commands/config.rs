use super::*;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::DeliveryBudget,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
impl Commands {
    pub(crate) async fn open(
        config: &crate::config::Config,
    ) -> std::result::Result<Arc<Self>, Error> {
        let bad = || Error::Configuration(crate::ConfigIssue::Commands);
        let database = &config.command_database;
        let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| bad())?;
        let binding = ExecutionBinding::new(
            StorageIdentity::new(config.management.target, config.management.lineage)
                .map_err(|_| bad())?,
            vec![(
                tenant,
                Epoch::new(config.management.epoch).map_err(|_| bad())?,
            )],
        )
        .map_err(|_| bad())?;
        let pg = PgConfig::new(
            &database.host,
            database.port,
            &database.name,
            &database.user,
            PgPassword::new(crate::config::secret(&database.password_file)?.as_str()),
            PgPrivateCa::from_pem(
                crate::config::read(&database.ca_file, 1024 * 1024, false)?.to_vec(),
            )
            .map_err(|_| bad())?,
        );
        let runtime = Arc::new(
            PgRuntime::connect(pg, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| Error::Unavailable(Failure::CommandStorage))?,
        );
        let result = async {
            let outbox = Arc::new(
                PgOutboxStore::new(
                    runtime.clone(),
                    messaging_domain(),
                    DeliveryBudget::new(
                        Duration::from_secs(60),
                        Duration::from_secs(6),
                        Duration::from_secs(6),
                        Duration::from_secs(6),
                    )
                    .map_err(|_| bad())?,
                )
                .map_err(|_| bad())?,
            );
            let copy = outbox.clone();
            let store = runtime
                .local_tx(tenant, deadline(), move |tx| {
                    Box::pin(async move {
                        storage::admit(tx).await.map_err(|_| {
                            PgError::from(sqlx::Error::Protocol("command admission".into()))
                        })?;
                        rss_device_command_postgres::PgStore::new(tx, copy).await
                    })
                })
                .await
                .fold(
                    Ok,
                    |_| Err(bad()),
                    |_| Err(bad()),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(bad()),
                )?;
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(5))
                .connect_with(database.options()?)
                .await
                .map_err(|_| bad())?;
            let timer = recovery::Timer::new();
            let cancel = tokio_util::sync::CancellationToken::new();
            let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
            let reconcile = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await
            {
                Ok(s) => s,
                Err(_) => {
                    pool.close().await;
                    return Err(bad());
                }
            };
            Ok(Arc::new(Self {
                runtime: runtime.clone(),
                outbox,
                store,
                reconcile,
                tenant,
                instance: config.identity.instance_id.clone(),
            }))
        }
        .await;
        if result.is_err() {
            runtime.close().await;
        }
        result
    }
}
pub(crate) struct Resource(pub(crate) Arc<Commands>);
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
