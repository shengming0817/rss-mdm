//! Product-owned lifetime for Identity's sole audit projection.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (await the original settlement owner).
use crate::{ConfigIssue, Error, Failure, config::Config};
use rss_identity_postgres::audit::{AuditDelivery, AuditDeliveryError, verify_worker};
use rss_runtime::{
    DynManagedResource, ManagedResource, ManagedTask, ManagedTaskRegistration, ShutdownError,
    TaskStatus,
};
use rss_transactional_messaging::policy::DeliveryBudget;
use rss_transactional_messaging_postgres::PgRuntime;
use rss_transactional_messaging_runtime::relay::RelayBatchLimit;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(crate) const ROLE: &str = "mdm_identity_audit";
#[derive(Default)]
pub(crate) struct Readiness {
    healthy: AtomicBool,
    task: OnceLock<TaskStatus>,
}
impl Readiness {
    pub(crate) fn ready(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && self.task.get().is_some_and(TaskStatus::is_running)
    }
}
pub(crate) struct Worker {
    delivery: AuditDelivery,
    readiness: Arc<Readiness>,
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::IdentityStorage)
}
impl Worker {
    pub(crate) async fn open(
        config: &Config,
        readiness: Arc<Readiness>,
        mut acquire: impl FnMut(Box<DynManagedResource<'static>>),
    ) -> Result<Arc<Self>, Error> {
        let database = &config.identity.audit_worker;
        // Register lazy pool ownership before any cancellable connection/admission operation.
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy_with(database.options()?);
        acquire(DynManagedResource::new_box(PoolResource(pool.clone())));
        let budget = crate::audit_budget::AuditBudget::new(Duration::from_secs(5));
        let control = budget.control();
        tokio::time::timeout(control.remaining(), async {
            let mut connection = pool.acquire().await.map_err(|_| unavailable())?;
            verify_worker(&mut connection, ROLE)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())??;
        let audit = Arc::new(
            rss_audit_postgres::PgAudit::new(pool, config.audit.integrity()?, &control)
                .await
                .map_err(|_| unavailable())?,
        );
        let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Tenant))?;
        if matches!(config.audit, crate::config::AuditConfig::Ledger { .. }) {
            audit
                .read_verified(
                    tenant,
                    rss_ledger::Sequence::new(0),
                    rss_ledger_postgres::ReadLimit::new(1, 262144).map_err(|_| unavailable())?,
                    &control,
                )
                .await
                .fold(
                    |_| Ok(()),
                    |_| Err(unavailable()),
                    |_| Err(unavailable()),
                    |_| Err(Error::RollbackFailed),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(unavailable()),
                )?;
        }
        let runtime = crate::identity::open_consumer_runtime(
            database,
            &config.flow.storage.target,
            &config.flow.storage.lineage,
            config.flow.storage.epoch,
            tenant,
        )
        .await?;
        acquire(DynManagedResource::new_box(RuntimeResource(
            runtime.clone(),
        )));
        let instance = rss_identity_core::InstanceId::parse(&config.identity.instance_id)
            .map_err(|_| Error::Configuration(ConfigIssue::Instance))?;
        let budget = DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .map_err(|_| Error::Configuration(ConfigIssue::Budget))?;
        let delivery = AuditDelivery::new(runtime, audit, instance, vec![tenant], budget)
            .await
            .map_err(|error| {
                diagnose(error);
                unavailable()
            })?;
        Ok(Arc::new(Self {
            delivery,
            readiness,
        }))
    }
    pub(crate) fn registration(self: Arc<Self>) -> ManagedTaskRegistration {
        let (task, status) = ManagedTask::prepare("identity-audit", Duration::from_secs(15));
        self.readiness
            .task
            .set(status)
            .expect("one identity audit task");
        task.into_registration(move |token| async move {
            let result = self.work(&token).await;
            self.readiness.healthy.store(false, Ordering::Release);
            result.map_err(|error| {
                diagnose(error);
                ShutdownError::new(error)
            })
        })
    }
    async fn work(&self, stop: &CancellationToken) -> Result<(), AuditDeliveryError> {
        while !stop.is_cancelled() {
            // Do not race this call with cancellation: the component owns commit/rollback.
            let retry = match self
                .delivery
                .run_once(RelayBatchLimit::new(NonZeroUsize::MIN).expect("one event"))
                .await
            {
                Ok(report) => {
                    let retry = should_wait(report.claimed(), report.retried(), report.fenced())?;
                    self.readiness
                        .healthy
                        .store(report.retried() == 0, Ordering::Release);
                    retry
                }
                Err(error) if error.is_retryable() => {
                    self.readiness.healthy.store(false, Ordering::Release);
                    diagnose(error);
                    true
                }
                Err(error) => return Err(error),
            };
            if retry {
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
            }
        }
        Ok(())
    }
}
fn should_wait(claimed: usize, retried: usize, fenced: usize) -> Result<bool, AuditDeliveryError> {
    if fenced > 0 {
        return Err(AuditDeliveryError::OwnershipLost);
    }
    Ok(claimed == 0 || retried > 0)
}
fn diagnose(error: AuditDeliveryError) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_identity_audit_failure","kind":error.as_label()})
    );
}
struct PoolResource(PgPool);
impl ManagedResource for PoolResource {
    fn name(&self) -> &str {
        "identity-audit-pool"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
struct RuntimeResource(Arc<PgRuntime>);
impl ManagedResource for RuntimeResource {
    fn name(&self) -> &str {
        "identity-audit-runtime"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
