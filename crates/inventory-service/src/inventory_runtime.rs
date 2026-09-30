//! The sole production Observation -> Inventory runner. No product claim or checkpoint engine.
use crate::{
    Error, Failure, Store,
    collection::{DurableReport, Run},
};
use rss_observation::{
    Access, Authority, JournalReadGrant, LifecycleGrant, ObservationStore, ReadGrant, Scope,
    VerifiedBatch,
};
use rss_observation_postgres::{PgSource, PgStore as Observation};
use rss_projection::{BatchLimit, Control, GenerationStart, ReplayBound, RunLimit};
use rss_projection_postgres::{CloseOutcome, PgStore as Projection};
use rss_request_context::{Deadline, TenantId};
use rss_runtime::{
    ManagedResource, ManagedTask, ManagedTaskRegistration, ShutdownError, TaskStatus,
};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
pub mod diagnostics;
const BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionStatus {
    Projected,
    Pending,
    PendingReceipt,
    NotApplicable,
}
#[derive(serde::Serialize)]
pub struct ReceiptStatus {
    pub batch_id: String,
    pub received_at: u64,
    pub decision: rss_observation::Decision,
}
#[derive(serde::Serialize)]
pub struct DeliveryStatus {
    pub receipt: Option<ReceiptStatus>,
    pub projection: ProjectionStatus,
}

#[derive(Clone)]
pub struct Clock {
    now: Arc<dyn rss_observation::Clock>,
    origin: Instant,
}
impl Clock {
    pub fn new(now: Arc<dyn rss_observation::Clock>) -> Self {
        Self {
            origin: now.now(),
            now,
        }
    }
    fn deadline(&self) -> Deadline {
        Deadline::at(self.now.now() + BUDGET)
    }
    pub fn cutoff(&self) -> Duration {
        rss_projection::Timer::now(self) + BUDGET
    }
}
impl rss_observation::Clock for Clock {
    fn now(&self) -> Instant {
        self.now.now()
    }
}
impl rss_projection::Timer for Clock {
    fn now(&self) -> Duration {
        self.now.now().saturating_duration_since(self.origin)
    }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep_until((self.origin + deadline).into()).await;
    }
}
#[derive(Default)]
pub struct Readiness {
    initialized: AtomicBool,
    stopping: AtomicBool,
    task: OnceLock<TaskStatus>,
}
impl Readiness {
    pub fn health(&self) -> diagnostics::Health {
        diagnostics::Health {
            initialized: self.initialized.load(Ordering::Acquire),
            stopping: self.stopping.load(Ordering::Acquire),
            task: self.task.get().map(TaskStatus::current),
        }
    }
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }
}
pub struct ObservationResource {
    pub store: Arc<Observation<Clock>>,
    clock: Clock,
}
impl ObservationResource {
    pub async fn open(options: PgConnectOptions, clock: Clock) -> Result<Self, Error> {
        let pool = pool(options).await?;
        match Observation::new(pool.clone(), clock.clone(), clock.deadline()).await {
            Ok(store) => Ok(Self {
                store: Arc::new(store),
                clock,
            }),
            Err(_) => {
                close_pool(&pool).await?;
                Err(unavailable())
            }
        }
    }
}
impl ManagedResource for ObservationResource {
    fn name(&self) -> &str {
        "inventory-observation"
    }
    fn shutdown_timeout(&self) -> Duration {
        BUDGET
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.store
            .close(self.clock.deadline())
            .await
            .map_err(|_| shutdown_error())
    }
}
pub struct ProjectionResource {
    pub store: Arc<Projection>,
    clock: Clock,
}
impl ProjectionResource {
    pub async fn open(
        options: PgConnectOptions,
        clock: Clock,
        control: &Control<'_, Clock>,
    ) -> Result<Self, Error> {
        let pool = control
            .run(async {
                pool(options)
                    .await
                    .map_err(|_| rss_projection::Error::new(rss_projection::ErrorKind::Unavailable))
            })
            .await
            .map_err(|_| unavailable())?;
        let result = async {
            control
                .run(async {
                    rss_mdm_inventory_postgres::verify_admission(&pool)
                        .await
                        .map_err(|_| {
                            rss_projection::Error::new(rss_projection::ErrorKind::Unavailable)
                        })
                })
                .await?;
            Projection::new(pool.clone(), control).await
        }
        .await;
        match result {
            Ok(store) => Ok(Self {
                store: Arc::new(store),
                clock,
            }),
            Err(_) => {
                close_pool(&pool).await?;
                Err(unavailable())
            }
        }
    }
}
impl ManagedResource for ProjectionResource {
    fn name(&self) -> &str {
        "inventory-projection"
    }
    fn shutdown_timeout(&self) -> Duration {
        BUDGET
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        let token = CancellationToken::new();
        let control = Control::new(&self.clock, self.clock.cutoff(), &token);
        if self.store.close(&control).await == CloseOutcome::Drained {
            Ok(())
        } else {
            Err(shutdown_error())
        }
    }
}
async fn pool(options: PgConnectOptions) -> Result<PgPool, Error> {
    tokio::time::timeout(
        BUDGET,
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(BUDGET)
            .connect_with(options),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
async fn close_pool(pool: &PgPool) -> Result<(), Error> {
    tokio::time::timeout(BUDGET, pool.close())
        .await
        .map_err(|_| unavailable())
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::InventoryRuntime)
}
fn shutdown_error() -> ShutdownError {
    ShutdownError::new(std::io::Error::other("inventory runtime unavailable"))
}

/// Journal authority comes only from the configured application tenant and worker cancellation.
struct JournalAuthority<'a> {
    tenant: TenantId,
    token: &'a CancellationToken,
}
impl Authority for JournalAuthority<'_> {
    fn authorize(&self, request: Access<'_>) -> Result<(), rss_observation::Error> {
        if !self.token.is_cancelled()
            && matches!(request, Access::ReadJournal { tenant } if tenant == self.tenant)
        {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
struct ReportAuthority<'a>(&'a DurableReport);
impl Authority for ReportAuthority<'_> {
    fn authorize(&self, request: Access<'_>) -> Result<(), rss_observation::Error> {
        let allowed = match request {
            Access::Activate { scope } => scope == self.0.scope(),
            Access::Submit { scope, coverage } => {
                scope == self.0.scope() && coverage == self.0.batch().coverage()
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
struct ReadAuthority<'a>(&'a Scope);
impl Authority for ReadAuthority<'_> {
    fn authorize(&self, request: Access<'_>) -> Result<(), rss_observation::Error> {
        if matches!(request, Access::Read { scope } if scope == self.0) {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
#[derive(Debug, Clone, Copy, serde::Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[error("inventory worker failed at {self:?}")]
pub enum WorkerFailure {
    JournalAuthority,
    ReportAuthority,
    ObservationActivate,
    ObservationReceive,
    DeliveryProgress,
    PendingReports,
    ProjectionInitialize,
    ProjectionTakeover,
    ProjectionCompose,
    ProjectionRun,
}

pub struct InventoryRuntime {
    observation: Arc<Observation<Clock>>,
    projection: Arc<Projection>,
    delivery: crate::collection::store::Delivery,
    tenant: TenantId,
    clock: Clock,
    pub readiness: Arc<Readiness>,
    latest_projection: std::sync::Mutex<Option<diagnostics::ProjectionObservation>>,
}
impl InventoryRuntime {
    pub fn new(
        observation: Arc<Observation<Clock>>,
        projection: Arc<Projection>,
        access: Arc<Store>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        tenant: TenantId,
        clock: Clock,
        readiness: Arc<Readiness>,
    ) -> Self {
        Self {
            observation,
            projection,
            delivery: crate::collection::store::Delivery::new(access, audit_store),
            tenant,
            clock,
            readiness,
            latest_projection: std::sync::Mutex::new(None),
        }
    }
    pub fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> ManagedTaskRegistration {
        let (task, status) = ManagedTask::prepare("mdm-inventory", Duration::from_secs(10));
        self.readiness
            .task
            .set(status)
            .expect("one inventory worker");
        task.into_registration(move |token| async move {
            let result = self.work(&token, &notify).await;
            self.readiness.initialized.store(false, Ordering::Release);
            if token.is_cancelled() {
                return Ok(());
            }
            result.map_err(|phase| {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"mdm_inventory_failure","phase":phase})
                );
                ShutdownError::new(phase)
            })
        })
    }
    async fn deliver(
        &self,
        report: &DurableReport,
        deadline: Deadline,
    ) -> Result<(), WorkerFailure> {
        if report.scope().tenant() != self.tenant {
            return Err(WorkerFailure::ReportAuthority);
        }
        let authority = ReportAuthority(report);
        let lifecycle = LifecycleGrant::verify(&authority, report.scope().clone())
            .map_err(|_| WorkerFailure::ReportAuthority)?;
        let verified =
            VerifiedBatch::verify(&authority, report.scope().clone(), report.batch().clone())
                .map_err(|_| WorkerFailure::ReportAuthority)?;
        self.observation
            .activate(
                &lifecycle,
                None,
                &rss_observation::Policy::new(86400, 3600, 3600).expect("fixed policy"),
                deadline,
            )
            .await
            .map_err(|_| WorkerFailure::ObservationActivate)?;
        self.observation
            .receive(&verified, deadline)
            .await
            .map_err(|_| WorkerFailure::ObservationReceive)?;
        // A lost acknowledgement leaves this true. Restart repeats the exact batch; lookup None
        // is never interpreted as proof of rollback.
        tokio::time::timeout_at(deadline.instant().into(), self.delivery.delivered(report))
            .await
            .map_err(|_| WorkerFailure::DeliveryProgress)?
            .map_err(|_| WorkerFailure::DeliveryProgress)
    }
    async fn deliver_pending(
        &self,
        reports: Vec<DurableReport>,
        deadline: Deadline,
        token: &CancellationToken,
    ) -> Result<(), WorkerFailure> {
        let pending_count = reports.len();
        for report in reports {
            if deadline.remaining(self.clock.now.now()).is_none() {
                break;
            }
            if token.is_cancelled() {
                return Ok(());
            }
            if let Err(phase) = self.deliver(&report, deadline).await {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event":"mdm_inventory_delivery_failure",
                        "phase":phase,
                        "reportId":report.batch().id().as_str(),
                        "source":report.scope().source().as_str(),
                        "stream":stream_correlation(report.scope()),
                        "pendingCount":pending_count,
                    })
                );
                return Err(phase);
            }
        }
        Ok(())
    }
    async fn work(
        &self,
        token: &CancellationToken,
        notify: &tokio::sync::Notify,
    ) -> Result<(), WorkerFailure> {
        let source = Arc::new(
            PgSource::new(
                self.observation.clone(),
                JournalReadGrant::verify(
                    &JournalAuthority {
                        tenant: self.tenant,
                        token,
                    },
                    self.tenant,
                )
                .map_err(|_| WorkerFailure::JournalAuthority)?,
                rss_mdm_inventory_postgres::projection_scope(self.tenant)
                    .source()
                    .clone(),
            )
            .map_err(|_| WorkerFailure::JournalAuthority)?,
        );
        let scope = rss_mdm_inventory_postgres::projection_scope(self.tenant);
        let control = Control::new(&self.clock, self.clock.cutoff(), token);
        let definition = rss_mdm_inventory_postgres::definition();
        self.projection
            .initialize(
                &scope,
                &definition,
                GenerationStart::beginning(),
                ReplayBound::Live,
                &control,
            )
            .await
            .map_err(|_| WorkerFailure::ProjectionInitialize)?;
        let claim = self
            .projection
            .takeover(&scope, &definition, &control)
            .await
            .map_err(|_| WorkerFailure::ProjectionTakeover)?;
        let execution = self
            .projection
            .projection(
                claim,
                rss_mdm_inventory_postgres::Inventory::new(source.clone()),
            )
            .map_err(|_| WorkerFailure::ProjectionCompose)?;
        loop {
            if token.is_cancelled() {
                return Ok(());
            }
            // The Audit transaction owns its settlement budget; never drop that owner
            // at the shorter discovery deadline or when shutdown is requested.
            let expired = self.delivery.expire_apple(&self.tenant.to_string()).await;
            if token.is_cancelled() {
                return Ok(());
            }
            let deadline = self.clock.deadline();
            let reports = match expired {
                Ok(expired) => tokio::time::timeout_at(
                    deadline.instant().into(),
                    self.delivery.pending_reports(&self.tenant.to_string()),
                )
                .await
                .map(|result| result.map(|reports| (expired, reports))),
                Err(error) => Ok(Err(error)),
            };
            let (expired, reports) = match reports {
                Ok(Ok(reports)) => reports,
                // A contended Audit head or uncertain settlement leaves durable work
                // pending. The next pass acquires the same locks and reads fresh state.
                Err(_)
                | Ok(Err(
                    Error::CommitUnknown
                    | Error::RollbackFailed
                    | Error::Unavailable(crate::Failure::RequestDeadline),
                )) => {
                    tokio::select! { () = token.cancelled() => return Ok(()), () = tokio::time::sleep(Duration::from_secs(1)) => {} }
                    continue;
                }
                Ok(Err(_)) => return Err(WorkerFailure::PendingReports),
            };
            let pending_count = reports.len();
            self.deliver_pending(reports, deadline, token).await?;
            if token.is_cancelled() {
                return Ok(());
            }
            let control = Control::new(&self.clock, self.clock.cutoff(), token);
            let run = rss_projection::run(
                source.as_ref(),
                &execution,
                &control,
                RunLimit::new(BatchLimit::new(64).expect("bounded batch"), 64)
                    .expect("bounded pass"),
            );
            {
                let mut latest = self
                    .latest_projection
                    .lock()
                    .expect("projection observation");
                let last_completed_at = latest.as_ref().and_then(|p| p.last_completed_at);
                *latest = Some(diagnostics::ProjectionObservation {
                    run: run.observation(),
                    started_at: self.clock.now.now(),
                    last_completed_at,
                });
            }
            let report = run.await;
            if let Some(observation) = self
                .latest_projection
                .lock()
                .expect("projection observation")
                .as_mut()
            {
                observation.last_completed_at = Some(self.clock.now.now());
            }
            let report = report
                .into_result()
                .map_err(|_| WorkerFailure::ProjectionRun)?;
            self.readiness.initialized.store(true, Ordering::Release);
            if expired == 0 && pending_count == 0 && report.applied == 0 {
                let nearest = self
                    .delivery
                    .next_expiry(&self.tenant.to_string())
                    .await
                    .map_err(|_| WorkerFailure::PendingReports)?;
                crate::wake::wait(notify, token, nearest).await;
            }
            if report.applied > 0 {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"mdm_inventory_progress","applied":report.applied,"position":report.position.map(|p| p.get())})
                );
            }
        }
    }
    /// Called only after product permission and current scope resolution. Inspect authoritative RSS facts.
    pub async fn inspect(&self, run: &Run) -> Result<DeliveryStatus, Error> {
        if run.scope.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        let Some(batch) = run.batch() else {
            return Ok(DeliveryStatus {
                receipt: None,
                projection: ProjectionStatus::NotApplicable,
            });
        };
        self.inspect_report(&run.scope, batch).await
    }

    pub async fn inspect_report(
        &self,
        scope: &Scope,
        batch: &rss_observation::Batch,
    ) -> Result<DeliveryStatus, Error> {
        if scope.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        let grant =
            ReadGrant::verify(&ReadAuthority(scope), scope.clone()).map_err(|_| unavailable())?;
        let receipt = self
            .observation
            .lookup(&grant, batch.id(), self.clock.deadline())
            .await
            .map_err(|_| unavailable())?;
        let event = batch
            .fingerprint(scope)
            .map_err(|_| unavailable())?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let token = CancellationToken::new();
        let control = Control::new(&self.clock, self.clock.cutoff(), &token);
        let query = rss_projection::ReceiptQuery::new(
            rss_mdm_inventory_postgres::projection_scope(self.tenant),
            rss_mdm_inventory_postgres::definition(),
            event,
        )
        .map_err(|_| unavailable())?;
        let projected = self
            .projection
            .receipt_status(&query, &control)
            .await
            .map_err(|_| unavailable())?
            .is_settled();
        let applicable = receipt
            .as_ref()
            .is_some_and(|r| r.decision().outcome().is_applicable());
        let received = receipt.is_some();
        Ok(DeliveryStatus {
            receipt: receipt.map(|r| ReceiptStatus {
                batch_id: r.batch().id().as_str().to_owned(),
                received_at: r.received_at(),
                decision: r.decision().clone(),
            }),
            projection: if projected {
                ProjectionStatus::Projected
            } else if applicable {
                ProjectionStatus::Pending
            } else if !received && matches!(batch.body(), rss_observation::Body::Snapshot(_)) {
                ProjectionStatus::PendingReceipt
            } else {
                ProjectionStatus::NotApplicable
            },
        })
    }
}

fn stream_correlation(scope: &Scope) -> String {
    let encoded = scope.encode().unwrap_or_else(|_| "invalid-scope".into());
    Sha256::digest(encoded.as_bytes())[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(feature = "test-support")]
impl InventoryRuntime {
    pub async fn fixture(
        options: PgConnectOptions,
        access: Arc<Store>,
        tenant: TenantId,
        monotonic: Arc<dyn rss_observation::Clock>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Result<Arc<Self>, Error> {
        let clock = Clock::new(monotonic);
        let observation = ObservationResource::open(options.clone(), clock.clone()).await?;
        let cancel = CancellationToken::new();
        let control = Control::new(&clock, clock.cutoff(), &cancel);
        let projection = match ProjectionResource::open(options, clock.clone(), &control).await {
            Ok(p) => p,
            Err(error) => {
                observation.shutdown().await.map_err(|_| unavailable())?;
                return Err(error);
            }
        };
        Ok(Arc::new(Self::new(
            observation.store,
            projection.store,
            access.clone(),
            audit_store,
            tenant,
            clock,
            Arc::new(Readiness::default()),
        )))
    }
    pub async fn close_fixture(&self) -> Result<(), ShutdownError> {
        ProjectionResource {
            store: self.projection.clone(),
            clock: self.clock.clone(),
        }
        .shutdown()
        .await?;
        ObservationResource {
            store: self.observation.clone(),
            clock: self.clock.clone(),
        }
        .shutdown()
        .await
    }
}

#[cfg(test)]
#[path = "../tests/runtime.rs"]
mod unit;
#[cfg(feature = "test-support")]
impl InventoryRuntime {
    pub async fn fixture_activate(
        &self,
        report: &DurableReport,
    ) -> Result<VerifiedBatch, rss_observation::Error> {
        let authority = ReportAuthority(report);
        self.observation
            .activate(
                &LifecycleGrant::verify(&authority, report.scope().clone())?,
                None,
                &rss_observation::Policy::new(86400, 3600, 3600)?,
                self.clock.deadline(),
            )
            .await?;
        VerifiedBatch::verify(&authority, report.scope().clone(), report.batch().clone())
    }
    #[cfg(feature = "integration")]
    pub async fn fixture_receive(
        &self,
        batch: &VerifiedBatch,
        fault: rss_observation_postgres::Fault,
    ) -> Result<rss_observation::ReceiveOutcome, rss_observation::Error> {
        self.observation.inject_next_fault(fault);
        self.observation.receive(batch, self.clock.deadline()).await
    }
    pub async fn fixture_deliver(&self, report: &DurableReport) -> Result<(), WorkerFailure> {
        self.deliver(report, self.clock.deadline()).await
    }
    pub async fn fixture_wait_stopped(&self) -> rss_runtime::TaskExit {
        self.readiness
            .task
            .get()
            .expect("fixture worker")
            .wait_stopped()
            .await
    }
    #[cfg(feature = "integration")]
    pub fn fixture_projection_fault(&self, fault: rss_projection_postgres::PgFault) {
        self.projection.inject_next_fault(fault);
    }
}
