//! Host lifetime for MDM's sole same-database audit projector.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (await original settlement).
use crate::{
    Error, Failure,
    audit_health::{AuditPhase, Readiness},
    config::Config,
};
use rss_mdm_audit_integration::{AuditProjection, AuditProjectionError};
use rss_request_context::Clock;
use rss_runtime::{
    DynManagedResource, ManagedResource, ManagedTask, ManagedTaskRegistration, ShutdownError,
};
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgRuntime;
use sqlx::PgPool;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
pub(crate) const ROLE: &str = "mdm_audit_worker";
pub(crate) struct Worker {
    delivery: AuditProjection<rss_mdm_native_protection::Protector>,
    pub(crate) health: Arc<Readiness>,
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Audit)
}
impl Worker {
    pub(crate) async fn open(
        config: &Config,
        mut acquire: impl FnMut(Box<DynManagedResource<'static>>),
    ) -> Result<Arc<Self>, Error> {
        let database = &config.audit_projection.database;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy_with(database.options()?);
        acquire(DynManagedResource::new_box(PoolResource(pool.clone())));
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let control = budget.control();
        tokio::time::timeout(control.total_remaining(), async {
            let mut connection = pool.acquire().await.map_err(|_| unavailable())?;
            verify_profile(&mut connection, config.audit.mode())
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
            .map_err(|_| unavailable())?;
        let instance = rss_identity_core::InstanceId::parse(&config.identity.instance_id)
            .map_err(|_| unavailable())?;
        let management =
            crate::identity::management_tenant(&config.identity.database, instance).await?;
        let runtime = crate::identity::open_consumer_runtime(
            database,
            &config.flow.storage.target,
            &config.flow.storage.lineage,
            &[
                (tenant, config.flow.storage.epoch),
                (
                    management,
                    rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH,
                ),
            ],
        )
        .await?;
        acquire(DynManagedResource::new_box(RuntimeResource(
            runtime.clone(),
        )));
        let budget = DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .map_err(|_| unavailable())?;
        let delivery = AuditProjection::new(
            runtime,
            audit,
            vec![tenant, management],
            config.audit_projection.recovery_keys.load()?,
            budget,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
        )
        .await
        .map_err(|error| {
            diagnose(error);
            unavailable()
        })?;
        Ok(Arc::new(Self {
            delivery,
            health: Arc::default(),
        }))
    }
    pub(crate) fn registration(self: Arc<Self>) -> ManagedTaskRegistration {
        let (task, status) = ManagedTask::prepare("mdm-audit", Duration::from_secs(15));
        self.health.task.set(status).expect("one MDM audit task");
        task.into_registration(move |token| async move {
            let result = self.work(&token).await;
            *self.health.phase.lock().expect("audit health") = AuditPhase::Stopped;
            result.map_err(|error| {
                diagnose(error);
                ShutdownError::new(error)
            })
        })
    }
    async fn work(&self, stop: &CancellationToken) -> Result<(), AuditProjectionError> {
        while !stop.is_cancelled() {
            // Cancellation ends the next batch; it never abandons the original COMMIT owner.
            let result = self
                .delivery
                .run_once(
                    NonZeroUsize::new(16).expect("bounded batch"),
                    OperationDeadline::from_remaining(Duration::from_secs(6)),
                )
                .await;
            let delay = match result {
                Ok(report) => {
                    self.health.progress(report.projected, report.deferred);
                    if report.projected > 0 && report.deferred == 0 {
                        continue;
                    }
                    match self
                        .delivery
                        .next_wakeup(OperationDeadline::from_remaining(Duration::from_secs(1)))
                        .await
                    {
                        Ok(wakeup) => wakeup
                            .next_deadline()
                            .and_then(|d| d.remaining(crate::lifecycle::RuntimeTimer.now()))
                            .unwrap_or(Duration::from_secs(1))
                            .clamp(Duration::from_millis(100), Duration::from_secs(1)),
                        Err(error) if error.is_retryable() => {
                            self.health.transient_failure();
                            diagnose(error);
                            Duration::from_secs(1)
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) if error.is_retryable() => {
                    self.health.transient_failure();
                    diagnose(error);
                    Duration::from_secs(1)
                }
                Err(error) => return Err(error),
            };
            tokio::select! { biased;
                () = stop.cancelled() => {},
                () = tokio::time::sleep(delay) => {},
            }
        }
        Ok(())
    }
}
fn diagnose(error: AuditProjectionError) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_audit_projection_failure","kind":error.as_label()})
    );
}
struct PoolResource(PgPool);
impl ManagedResource for PoolResource {
    fn name(&self) -> &str {
        "mdm-audit-pool"
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
        "mdm-audit-runtime"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
/// Product effect permissions plus the provider's immutable domain/group scope.
pub(crate) async fn verify_profile(
    c: &mut sqlx::PgConnection,
    mode: crate::migration::AuditMode,
) -> Result<(), sqlx::Error> {
    let safe: bool = sqlx::query_scalar(include_str!("../schema/audit-worker-probe.sql"))
        .bind(ROLE)
        .fetch_one(&mut *c)
        .await?;
    let ledger: bool =
        sqlx::query_scalar(include_str!("../schema/identity-audit-ledger-probe.sql"))
            .bind(ROLE)
            .bind(mode == crate::migration::AuditMode::Ledger)
            .fetch_one(&mut *c)
            .await?;
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *c)
        .await?;
    let scoped: bool = if current == ROLE {
        sqlx::query_scalar("SELECT rss_transactional_messaging.projection_scope_matches('mdm.audit','mdm.audit.v1')").fetch_one(c).await?
    } else {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_transactional_messaging.consumer_scope WHERE login_role=$1::name AND domain='mdm.audit' AND consumer_group='mdm.audit.v1')").bind(ROLE).fetch_one(c).await?
    };
    if safe && ledger && scoped {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "MDM audit worker profile rejected".into(),
        ))
    }
}
