//! Host lifetime for MDM's sole same-database audit projector.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (await original settlement).
use crate::{
    Error, Failure,
    audit_health::{AuditPhase, Readiness},
    config::Config,
};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
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
use std::time::Instant;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
pub(crate) const ROLE: &str = "mdm_audit_worker";
pub(crate) struct Worker {
    delivery: AuditProjection<rss_mdm_native_protection::Protector>,
    pub(crate) health: Arc<Readiness>,
    capacity: NonZeroUsize,
    wake: Arc<Notify>,
    #[cfg(feature = "integration")]
    recovery_fault: std::sync::atomic::AtomicBool,
    #[cfg(feature = "integration")]
    recovery_started: Notify,
    #[cfg(feature = "integration")]
    recovery_release: Notify,
    #[cfg(feature = "integration")]
    stop_observed: Notify,
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
            #[cfg(feature = "integration")]
            recovery_fault: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "integration")]
            recovery_started: Notify::new(),
            #[cfg(feature = "integration")]
            recovery_release: Notify::new(),
            #[cfg(feature = "integration")]
            stop_observed: Notify::new(),
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
    async fn resolve_pending(
        &self,
        identity: &PgProjectionRecovery,
    ) -> Result<bool, AuditProjectionError> {
        #[cfg(feature = "integration")]
        if self
            .recovery_fault
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.recovery_started.notify_one();
            self.recovery_release.notified().await;
            return Err(AuditProjectionError::Unavailable);
        }
        self.delivery.resolve(identity, operation()).await
    }
    async fn recover(&self, mut item: Pending) -> (Pending, Result<bool, AuditProjectionError>) {
        let result = self.resolve_pending(&item.identity).await;
        if result.as_ref().is_err_and(|error| error.is_retryable()) {
            item.failures = item.failures.saturating_add(1);
            item.error = result.as_ref().err().copied();
            item.after = crate::lifecycle::RuntimeTimer.now() + retry_delay(item.failures);
        }
        (item, result)
    }
    async fn work(&self, stop: &CancellationToken) -> Result<(), AuditProjectionError> {
        Work::new(self).run(stop).await
    }
}
// All identities and original futures are owned by this one local worker state.
// A batch reserves its free capacity until its complete report returns; no second batch
// starts meanwhile. Recovery ownership is counted both while waiting and while running.
type BatchResult = Result<rss_mdm_audit_integration::AuditProjectionReport, AuditProjectionError>;
type RecoveryResult = (Pending, Result<bool, AuditProjectionError>);
type HintResult = Result<rss_transactional_messaging_postgres::OutboxWakeup, AuditProjectionError>;
struct Timed<T> {
    started: Instant,
    value: T,
}
type Flight<'a, T> = futures::future::BoxFuture<'a, Timed<T>>;
async fn timed<T>(future: impl std::future::Future<Output = T>) -> Timed<T> {
    let started = crate::lifecycle::RuntimeTimer.now();
    Timed {
        started,
        value: future.await,
    }
}
struct Work<'a> {
    worker: &'a Worker,
    pending: Vec<Pending>,
    recovering: FuturesUnordered<Flight<'a, RecoveryResult>>,
    batch: Option<Flight<'a, BatchResult>>,
    hint: Option<Flight<'a, HintResult>>,
    schedule: Schedule,
    diagnostics: Diagnostics,
    scan_after: Instant,
    draining: bool,
    fatal: Option<AuditProjectionError>,
}
enum Event {
    Batch(Timed<BatchResult>),
    Recovery(Timed<RecoveryResult>),
    Hint(Timed<HintResult>),
    Wake,
    Stop,
}
#[derive(Default)]
struct Tick {
    started: Option<Instant>,
    phase: &'static str,
    progressed: usize,
    deferred: usize,
    failure: Option<AuditProjectionError>,
    claim_failed: bool,
}
impl<'a> Work<'a> {
    fn new(worker: &'a Worker) -> Self {
        let now = crate::lifecycle::RuntimeTimer.now();
        Self {
            worker,
            pending: Vec::new(),
            recovering: FuturesUnordered::new(),
            batch: None,
            hint: None,
            schedule: Schedule {
                after: now,
                failures: 0,
                error: None,
            },
            diagnostics: Diagnostics::new(),
            scan_after: now,
            draining: false,
            fatal: None,
        }
    }
    fn recovery_count(&self) -> usize {
        self.pending.len() + self.recovering.len()
    }
    fn idle(&self) -> bool {
        self.batch.is_none() && self.hint.is_none() && self.recovering.is_empty()
    }
    fn launch(&mut self) {
        if self.draining {
            return;
        }
        let now = crate::lifecycle::RuntimeTimer.now();
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.after <= now);
        self.pending = waiting;
        for item in ready {
            self.recovering
                .push(timed(self.worker.recover(item)).boxed());
        }
        if self.batch.is_some() || now < self.scan_after.max(self.schedule.after) {
            return;
        }
        if let Some(free) = NonZeroUsize::new(
            self.worker
                .capacity
                .get()
                .saturating_sub(self.recovery_count()),
        ) {
            self.batch = Some(
                timed(
                    self.worker
                        .delivery
                        .project_batch(free, operation(), ACTION_BUDGET),
                )
                .boxed(),
            );
            self.scan_after = now + RESCAN;
        }
    }
    fn next_deadline(&self) -> Instant {
        let mut at = crate::lifecycle::RuntimeTimer.now() + RESCAN;
        if self.batch.is_none() && self.recovery_count() < self.worker.capacity.get() {
            at = at.min(self.scan_after.max(self.schedule.after));
        }
        self.pending
            .iter()
            .map(|p| p.after)
            .min()
            .map_or(at, |retry| at.min(retry))
    }
    async fn next(&mut self, stop: &CancellationToken) -> Event {
        let at = self.next_deadline();
        // Only borrow stored futures here. A losing branch remains owned and is polled again.
        tokio::select! { biased;
            () = stop.cancelled(), if !self.draining => Event::Stop,
            result = async { self.batch.as_mut().expect("active batch").await }, if self.batch.is_some() => Event::Batch(result),
            Some(result) = self.recovering.next(), if !self.recovering.is_empty() => Event::Recovery(result),
            result = async { self.hint.as_mut().expect("active hint").await }, if self.hint.is_some() => Event::Hint(result),
            () = self.worker.wake.notified(), if !self.draining && self.schedule.after <= crate::lifecycle::RuntimeTimer.now() => Event::Wake,
            () = tokio::time::sleep_until(at.into()), if !self.draining => Event::Wake,
        }
    }
    fn batch_finished(&mut self, completed: Timed<BatchResult>) -> Tick {
        let started = completed.started;
        let result = completed.value;
        self.batch = None;
        let report = collect_batch(result, &mut self.pending);
        self.schedule.error = report.failure;
        self.diagnostics.projected_total += report.projected as u64;
        self.diagnostics.uncertain_total += report.uncertain as u64;
        if report.failure.is_none() {
            self.schedule.failures = 0;
        }
        if report.projected > 0 || report.failure.is_some() {
            self.scan_after = crate::lifecycle::RuntimeTimer.now();
        } else if self.hint.is_none() && !self.draining {
            self.hint = Some(timed(self.worker.delivery.next_wakeup(operation())).boxed());
        }
        Tick {
            started: Some(started),
            phase: "batch",
            progressed: report.projected,
            deferred: report.deferred,
            claim_failed: report.failure.is_some_and(|error| error.is_retryable())
                && report.projected == 0,
            failure: report.failure,
        }
    }
    fn recovery_finished(&mut self, completed: Timed<RecoveryResult>) -> Tick {
        let started = completed.started;
        let result = completed.value;
        if result.1.is_ok() {
            self.scan_after = crate::lifecycle::RuntimeTimer.now();
        }
        let (progressed, deferred, failure) = collect_recoveries(vec![result], &mut self.pending);
        self.diagnostics.resolved_total += progressed as u64;
        Tick {
            started: Some(started),
            phase: "recovery",
            progressed,
            deferred,
            failure,
            claim_failed: false,
        }
    }
    fn hint_finished(&mut self, completed: Timed<HintResult>) -> Tick {
        let started = completed.started;
        let result = completed.value;
        self.hint = None;
        match result {
            Ok(hint) => {
                let now = crate::lifecycle::RuntimeTimer.now();
                let delay = hint
                    .next_deadline()
                    .and_then(|d| d.remaining(now))
                    .filter(|d| !d.is_zero())
                    .unwrap_or(RESCAN);
                self.scan_after = self.scan_after.min(now + delay.min(RESCAN));
                Tick {
                    started: Some(started),
                    phase: "wakeup",
                    ..Tick::default()
                }
            }
            Err(error) => {
                self.schedule.failures = self.schedule.failures.saturating_add(1);
                self.schedule.after =
                    crate::lifecycle::RuntimeTimer.now() + retry_delay(self.schedule.failures);
                self.schedule.error = Some(error);
                self.scan_after = crate::lifecycle::RuntimeTimer.now();
                Tick {
                    started: Some(started),
                    phase: "wakeup",
                    failure: Some(error),
                    ..Tick::default()
                }
            }
        }
    }
    fn observe(&mut self, tick: Tick) {
        let started = crate::lifecycle::RuntimeTimer.now();
        let recovery_count = self.recovery_count();
        if let Err(error) = self.schedule.advance(
            started,
            (tick.progressed, tick.deferred + recovery_count),
            tick.claim_failed,
            tick.failure,
            &self.worker.health,
        ) {
            self.fatal = Some(error);
            self.draining = true;
        }
        if tick.progressed > 0 {
            self.scan_after = crate::lifecycle::RuntimeTimer.now();
        }
        if tick.failure.is_none() && self.schedule.error.is_none() {
            self.worker
                .health
                .progress(tick.progressed, tick.deferred + recovery_count);
        }
        self.diagnostics.observe(
            self.worker,
            &tick,
            &self.pending,
            &self.schedule,
            self.recovering.len(),
        );
    }
    async fn run(mut self, stop: &CancellationToken) -> Result<(), AuditProjectionError> {
        loop {
            if !self.draining && stop.is_cancelled() {
                self.draining = true;
                #[cfg(feature = "integration")]
                self.worker.stop_observed.notify_one();
            }
            if self.draining && self.idle() {
                break;
            }
            self.launch();
            let tick = match self.next(stop).await {
                Event::Batch(result) => self.batch_finished(result),
                Event::Recovery(result) => self.recovery_finished(result),
                Event::Hint(result) => self.hint_finished(result),
                Event::Wake => {
                    self.scan_after = crate::lifecycle::RuntimeTimer.now();
                    continue;
                }
                Event::Stop => {
                    self.draining = true;
                    #[cfg(feature = "integration")]
                    self.worker.stop_observed.notify_one();
                    continue;
                }
            };
            self.observe(tick);
        }
        self.fatal.map_or(Ok(()), Err)
    }
}

const ACTION_BUDGET: Duration = Duration::from_secs(6);
const RESCAN: Duration = Duration::from_secs(30);
fn operation() -> OperationDeadline {
    OperationDeadline::from_remaining(ACTION_BUDGET)
}
struct Schedule {
    after: Instant,
    failures: u32,
    error: Option<AuditProjectionError>,
}
impl Schedule {
    fn advance(
        &mut self,
        started: Instant,
        counts: (usize, usize),
        claim_failed: bool,
        failure: Option<AuditProjectionError>,
        health: &Readiness,
    ) -> Result<(), AuditProjectionError> {
        let (progressed, retried) = counts;
        if progressed > 0 {
            if !claim_failed {
                self.failures = 0;
                self.after = crate::lifecycle::RuntimeTimer.now();
            }

            health.progress(progressed, retried);
        }
        if let Some(error) = failure {
            health.transient_failure();
            if !error.is_retryable() {
                return Err(error);
            }
        }
        if claim_failed {
            self.failures = self.failures.saturating_add(1);
            self.after = crate::lifecycle::RuntimeTimer.now() + retry_delay(self.failures);
        } else if started >= self.after {
            self.after = crate::lifecycle::RuntimeTimer.now();
        }
        Ok(())
    }
}
struct Diagnostics {
    last_progress: Option<Instant>,
    waiting_since: Option<Instant>,
    last_diagnostic: Instant,
    projected_total: u64,
    resolved_total: u64,
    uncertain_total: u64,
}
impl Diagnostics {
    fn new() -> Self {
        Self {
            last_progress: None,
            waiting_since: None,
            last_diagnostic: crate::lifecycle::RuntimeTimer.now(),
            projected_total: 0,
            resolved_total: 0,
            uncertain_total: 0,
        }
    }
    fn observe(
        &mut self,
        worker: &Worker,
        tick: &Tick,
        pending: &[Pending],
        schedule: &Schedule,
        recovering: usize,
    ) {
        let (progressed, deferred, failure) = (tick.progressed, tick.deferred, tick.failure);
        let started = tick.started.expect("completed operation timing");
        let pending_count = pending.len() + recovering;
        if progressed > 0 {
            self.last_progress = Some(crate::lifecycle::RuntimeTimer.now());
        }
        let recovery_failures = pending.iter().map(|p| u64::from(p.failures)).sum::<u64>();
        let active_failure = failure
            .or(schedule.error)
            .or_else(|| pending.iter().find_map(|p| p.error));
        if active_failure.is_some() {
            worker.health.transient_failure();
        }
        if progressed > 0 || (pending_count == 0 && deferred == 0 && active_failure.is_none()) {
            self.waiting_since = None;
        } else {
            self.waiting_since.get_or_insert(started);
        }
        // Match the existing source backlog age warning, without treating idle time as a stall.
        let stalled = self.waiting_since.is_some_and(|at| {
            crate::lifecycle::RuntimeTimer
                .now()
                .saturating_duration_since(at)
                > Duration::from_secs(300)
        });
        let observation = serde_json::json!({
            "event":"mdm_audit_projection_progress", "phase":tick.phase,
            "elapsed_ms":crate::lifecycle::RuntimeTimer.now().saturating_duration_since(started).as_millis(), "projected":progressed,
            "deferred":deferred, "capacity":worker.capacity.get(),
            "pending_recovery":pending_count, "running_recovery":recovering, "stalled":stalled, "claim_failures":schedule.failures,
            "recovery_failures":recovery_failures, "projected_total":self.projected_total,
            "uncertain_total":self.uncertain_total, "resolved_total":self.resolved_total,
            "retry_ms":schedule.after.saturating_duration_since(crate::lifecycle::RuntimeTimer.now()).as_millis(),
            "last_progress_age_ms":self.last_progress.map(|at: Instant| crate::lifecycle::RuntimeTimer.now().saturating_duration_since(at).as_millis()),
            "failure":active_failure.map(AuditProjectionError::as_label),
        });
        *worker.health.projection.lock().expect("projection health") = Some(observation.clone());
        if failure.is_some()
            || crate::lifecycle::RuntimeTimer
                .now()
                .saturating_duration_since(self.last_diagnostic)
                >= RESCAN
        {
            eprintln!("{observation}");
            self.last_diagnostic = crate::lifecycle::RuntimeTimer.now();
        }
    }
}
fn collect_recoveries(
    resolved: Vec<(Pending, Result<bool, AuditProjectionError>)>,
    pending: &mut Vec<Pending>,
) -> (usize, usize, Option<AuditProjectionError>) {
    let (mut progressed, mut deferred, mut failure) = (0, 0, None);
    for (item, result) in resolved {
        match result {
            Ok(true) => progressed += 1,
            Ok(false) => deferred += 1,
            Err(error) => {
                if error.is_retryable() {
                    pending.push(item);
                }
                retain_failure(&mut failure, error);
            }
        }
    }
    (progressed, deferred, failure)
}
struct BatchProgress {
    projected: usize,
    deferred: usize,
    uncertain: usize,
    failure: Option<AuditProjectionError>,
}
fn collect_batch(
    batch: Result<rss_mdm_audit_integration::AuditProjectionReport, AuditProjectionError>,
    pending: &mut Vec<Pending>,
) -> BatchProgress {
    match batch {
        Ok(report) => {
            let uncertain = report.recoveries.len();
            pending.extend(report.recoveries.into_iter().map(|identity| Pending {
                identity,
                after: crate::lifecycle::RuntimeTimer.now(),
                failures: 0,
                error: None,
            }));
            BatchProgress {
                projected: report.projected,
                deferred: report.deferred,
                uncertain,
                failure: report.failure,
            }
        }
        Err(error) => BatchProgress {
            projected: 0,
            deferred: 0,
            uncertain: 0,
            failure: Some(error),
        },
    }
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
