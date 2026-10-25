//! Host lifetime for MDM's sole same-database audit projector.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (await original settlement).
use crate::{
    Error, Failure,
    audit_health::{AuditPhase, Readiness},
    config::Config,
};
use futures::{StreamExt, stream::FuturesUnordered};
use rss_mdm_audit_integration::{AuditProjection, AuditProjectionError};
use rss_request_context::Clock;
use rss_runtime::{
    DynManagedResource, ManagedResource, ManagedTask, ManagedTaskRegistration, ShutdownError,
};
use rss_transactional_messaging::policy::RetryPolicy;
use rss_transactional_messaging::policy::{DeliveryBudget, OperationDeadline};
use rss_transactional_messaging_postgres::PgProjectionRecovery;
use rss_transactional_messaging_postgres::PgRuntime;
use sqlx::PgPool;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{sync::Notify, time::Instant};
use tokio_util::sync::CancellationToken;
pub(crate) const ROLE: &str = "mdm_audit_worker";
pub(crate) struct Worker {
    delivery: AuditProjection<rss_mdm_native_protection::Protector>,
    pub(crate) health: Arc<Readiness>,
    capacity: NonZeroUsize,
    wake: Arc<Notify>,
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Audit)
}
impl Worker {
    pub(crate) async fn open(
        config: &Config,
        wake: Arc<Notify>,
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
        let capacity = NonZeroUsize::new(config.audit_projection.max_inflight as usize)
            .ok_or_else(unavailable)?;
        let connections = config
            .audit_projection
            .max_inflight
            .checked_add(1)
            .ok_or_else(unavailable)?;
        let (pg, binding) = crate::identity::runtime_inputs(
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
        )?;
        let runtime = Arc::new(
            PgRuntime::connect_consumer(
                pg.with_pool_limits(0, connections),
                crate::lifecycle::RuntimeTimer,
                binding,
            )
            .await
            .map_err(|_| unavailable())?,
        );
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
            capacity,
            wake,
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
        let mut pending: Vec<Pending> = Vec::new();
        let mut claim_after = Instant::now();
        let mut failures = 0_u32;
        let mut last_claim_error = None;
        let mut last_progress = None;
        let mut uncertain_total = 0_u64;
        let mut resolved_total = 0_u64;
        let mut projected_total = 0_u64;
        let mut last_diagnostic = Instant::now();
        while !stop.is_cancelled() {
            let started = Instant::now();
            let free = self.capacity.get().saturating_sub(pending.len());
            let (ready, waiting): (Vec<_>, Vec<_>) =
                pending.into_iter().partition(|p| p.after <= started);
            pending = waiting;
            let recover = ready
                .into_iter()
                .map(|mut item| async move {
                    let result = self.delivery.resolve(&item.identity, operation()).await;
                    if result.as_ref().is_err_and(|error| error.is_retryable()) {
                        item.failures = item.failures.saturating_add(1);
                        item.error = result.as_ref().err().copied();
                        item.after = Instant::now() + retry_delay(item.failures);
                    }
                    (item, result)
                })
                .collect::<FuturesUnordered<_>>()
                .collect::<Vec<_>>();
            let claim = async {
                if started < claim_after {
                    return None;
                }
                let limit = NonZeroUsize::new(free)?;
                Some(
                    self.delivery
                        .project_batch(limit, operation(), ACTION_BUDGET)
                        .await,
                )
            };
            // Both branches retain their original settlement owners. Cancellation only ends
            // the next iteration; no select! drops an in-flight COMMIT or sibling identity.
            let (resolved, batch) = tokio::join!(recover, claim);
            let mut progressed = 0;
            let mut deferred = 0;
            let mut failure = None;
            let mut claim_failed = false;
            for (item, result) in resolved {
                match result {
                    Ok(true) => {
                        progressed += 1;
                        resolved_total += 1;
                    }
                    // Release temporary identity; only a new durable claim may execute again.
                    Ok(false) => deferred += 1,
                    Err(error) => {
                        if error.is_retryable() {
                            pending.push(item);
                        }
                        retain_failure(&mut failure, error);
                    }
                }
            }
            if let Some(batch) = batch {
                match batch {
                    Ok(report) => {
                        last_claim_error = report.failure;
                        progressed += report.projected;
                        projected_total += report.projected as u64;
                        uncertain_total += report.recoveries.len() as u64;
                        deferred += report.deferred;
                        pending.extend(report.recoveries.into_iter().map(|identity| Pending {
                            identity,
                            after: Instant::now(),
                            failures: 0,
                            error: None,
                        }));
                        if let Some(error) = report.failure {
                            claim_failed = error.is_retryable();
                            retain_failure(&mut failure, error);
                        }
                    }
                    Err(error) => {
                        claim_failed = error.is_retryable();
                        last_claim_error = Some(error);
                        retain_failure(&mut failure, error);
                    }
                }
            }
            if progressed > 0 {
                if !claim_failed {
                    failures = 0;
                }
                last_progress = Some(Instant::now());
                self.health.progress(progressed, deferred + pending.len());
            }
            if let Some(error) = failure {
                self.health.transient_failure();
                if !error.is_retryable() {
                    return Err(error);
                }
            }
            if claim_failed {
                failures = failures.saturating_add(1);
                claim_after = Instant::now() + retry_delay(failures);
            } else if started >= claim_after {
                claim_after = Instant::now();
            }
            let immediate = progressed > 0 && !claim_failed && pending.len() < self.capacity.get();
            let now = Instant::now();
            let mut delay = if claim_after > now {
                claim_after - now
            } else {
                RESCAN
            };
            if !immediate
                && !stop.is_cancelled()
                && claim_after <= now
                && pending.len() < self.capacity.get()
            {
                match self.delivery.next_wakeup(operation()).await {
                    Ok(wakeup) => {
                        if let Some(remaining) = wakeup
                            .next_deadline()
                            .and_then(|d| d.remaining(crate::lifecycle::RuntimeTimer.now()))
                            .filter(|d| !d.is_zero())
                        {
                            delay = delay.min(remaining);
                        }
                        if !claim_failed {
                            last_claim_error = None;
                        }
                        if failure.is_none() {
                            self.health.progress(0, deferred + pending.len());
                        }
                    }
                    Err(error) if error.is_retryable() => {
                        failures = failures.saturating_add(1);
                        delay = retry_delay(failures);
                        claim_after = Instant::now() + delay;
                        self.health.transient_failure();
                        last_claim_error = Some(error);
                        retain_failure(&mut failure, error);
                    }
                    Err(error) => return Err(error),
                }
            }
            if let Some(at) = pending.iter().map(|p| p.after).min() {
                delay = delay.min(at.saturating_duration_since(Instant::now()));
            }
            let recovery_failures = pending.iter().map(|p| u64::from(p.failures)).sum::<u64>();
            let active_failure = failure
                .or(last_claim_error)
                .or_else(|| pending.iter().find_map(|p| p.error));
            if active_failure.is_some() {
                self.health.transient_failure();
            }
            let observation = serde_json::json!({
                "event":"mdm_audit_projection_progress", "phase":"batch_and_recovery",
                "elapsed_ms":started.elapsed().as_millis(), "projected":progressed,
                "deferred":deferred, "capacity":self.capacity.get(),
                "pending_recovery":pending.len(), "claim_failures":failures,
                "recovery_failures":recovery_failures, "projected_total":projected_total,
                "uncertain_total":uncertain_total, "resolved_total":resolved_total,
                "retry_ms":claim_after.saturating_duration_since(Instant::now()).as_millis(),
                "last_progress_age_ms":last_progress.map(|at: Instant| at.elapsed().as_millis()),
                "failure":active_failure.map(AuditProjectionError::as_label),
            });
            *self.health.projection.lock().expect("projection health") = Some(observation.clone());
            if failure.is_some() || last_diagnostic.elapsed() >= RESCAN {
                eprintln!("{observation}");
                last_diagnostic = Instant::now();
            }
            if stop.is_cancelled() {
                break;
            }
            if immediate {
                continue;
            }
            // A notification cannot bypass infrastructure backoff. Recovery deadlines remain
            // independent, and a stored Notify permit survives the scan/wait race.
            tokio::select! { biased;
                () = stop.cancelled() => {},
                () = self.wake.notified(), if claim_after <= Instant::now() => {},
                () = tokio::time::sleep(delay) => {},
            }
        }
        Ok(())
    }
}
const ACTION_BUDGET: Duration = Duration::from_secs(6);
const RESCAN: Duration = Duration::from_secs(30);
fn operation() -> OperationDeadline {
    OperationDeadline::from_remaining(ACTION_BUDGET)
}
fn retry_delay(failures: u32) -> Duration {
    RetryPolicy::STANDARD
        .delay_after(std::num::NonZeroU32::new(failures).unwrap_or(std::num::NonZeroU32::MIN))
}
struct Pending {
    identity: PgProjectionRecovery,
    after: Instant,
    failures: u32,
    error: Option<AuditProjectionError>,
}
fn retain_failure(current: &mut Option<AuditProjectionError>, error: AuditProjectionError) {
    if current.is_none_or(AuditProjectionError::is_retryable) {
        *current = Some(error);
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

#[cfg(all(test, feature = "integration"))]
#[path = "../tests/audit/worker.rs"]
mod tests;
