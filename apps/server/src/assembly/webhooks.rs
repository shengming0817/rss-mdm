//! Host resource assembly for the Webhook owner.
use rss_mdm_webhook_service::{
    self as webhooks,
    management::{Dependencies, Service},
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{
    PgConfig, PgPassword, PgPrivateCa, PgRecoveryStore, PgRuntime,
};
use std::{sync::Arc, time::Duration};
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open(
    config: crate::config::webhooks::Config,
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    clock: Arc<dyn crate::clock::Clock>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Result<Arc<Service>, crate::Error> {
    let source_tenant =
        uuid::Uuid::parse_str(&tenant.to_string()).map_err(|_| crate::Error::Malformed)?;
    let policies = config.compile().map_err(crate::Error::from)?;
    let db = &config.recovery_database;
    let pg = PgConfig::new(
        &db.host,
        db.port,
        &db.name,
        &db.user,
        PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
        PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())
            .map_err(|_| crate::Error::Malformed)?,
    )
    .with_pool_limits(0, crate::background::AUXILIARY_CONNECTIONS);
    let recovery = Arc::new(
        PgRecoveryStore::connect(
            pg,
            crate::lifecycle::RuntimeTimer,
            binding,
            protection.clone(),
        )
        .await
        .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?,
    );
    let result = Service::open(
        Dependencies {
            runtime,
            tenant,
            audit,
            clock: Arc::new(Clock(clock)),
            protection,
            cursor,
            recovery: recovery.clone(),
            policies,
            sources: Arc::new(crate::adapters::webhooks::Sources {
                tenant: source_tenant,
            }),
        },
        crate::lifecycle::RuntimeTimer,
    )
    .await;
    if result.is_err() {
        recovery.close().await;
    }
    result.map_err(crate::Error::from)
}
struct Clock(Arc<dyn crate::clock::Clock>);
impl webhooks::management::Clock for Clock {
    fn unix_seconds(&self) -> Result<i64, webhooks::Error> {
        self.0.unix_seconds().map_err(|_| webhooks::Error::Storage)
    }
}
pub(crate) struct Resource(pub Arc<Service>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "webhook-recovery"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close_recovery().await;
        Ok(())
    }
}
pub(crate) fn registration(service: Arc<Service>) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("webhook-relays", Duration::from_secs(20));
    task.into_registration(move |token| async move {
        service
            .run(token)
            .await
            .map_err(rss_runtime::ShutdownError::new)
    })
}
