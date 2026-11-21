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
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
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
/// Resource bounds for this owner, compiled by the host before opening pools.
#[derive(Clone, Copy)]
pub struct Policy {
    startup: Duration,
    pass: Duration,
    drain: Duration,
    delivery: BatchLimit,
    delivery_bytes: i64,
    run: RunLimit,
}
impl Policy {
    pub fn new(
        startup: Duration,
        pass: Duration,
        drain: Duration,
        delivery: u32,
        delivery_bytes: u64,
        batch: u32,
        events: u64,
    ) -> Result<Self, Error> {
        if [startup, pass, drain]
            .iter()
            .any(|v| v.is_zero() || v.as_millis() > i64::MAX as u128)
        {
            return Err(Error::Malformed);
        }
        let delivery_bytes = i64::try_from(delivery_bytes).map_err(|_| Error::Malformed)?;
        if delivery_bytes == 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            startup,
            pass,
            drain,
            delivery_bytes,
            delivery: BatchLimit::new(delivery).map_err(|_| Error::Malformed)?,
            run: RunLimit::new(
                BatchLimit::new(batch).map_err(|_| Error::Malformed)?,
                events,
            )
            .map_err(|_| Error::Malformed)?,
        })
    }
}

#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionStatus {
    Projected,
    Pending,
    PendingReceipt,
    NotApplicable,
}
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct ReceiptStatus {
    pub batch_id: String,
    pub received_at: u64,
    #[schemars(schema_with = "observation_decision_schema")]
    pub decision: rss_observation::Decision,
}
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct DeliveryStatus {
    pub receipt: Option<ReceiptStatus>,
    pub projection: ProjectionStatus,
}

#[derive(Clone)]
pub struct Clock {
    now: Arc<dyn rss_observation::Clock>,
    origin: Instant,
    policy: Policy,
}
impl Clock {
    pub fn new(now: Arc<dyn rss_observation::Clock>, policy: Policy) -> Self {
        Self {
            policy,
            origin: now.now(),
            now,
        }
    }
    fn deadline(&self) -> Deadline {
        Deadline::at(self.now.now() + self.policy.pass)
    }
    pub fn startup_cutoff(&self) -> Duration {
        rss_projection::Timer::now(self) + self.policy.startup
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
        let deadline = Deadline::at(clock.now.now() + clock.policy.startup);
        let pool = pool(options, clock.policy.startup).await?;
        match Observation::new(pool.clone(), clock.clone(), deadline).await {
            Ok(store) => Ok(Self {
                store: Arc::new(store),
                clock,
            }),
            Err(_) => {
                close_pool(&pool, clock.policy.drain).await?;
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
        self.clock.policy.drain
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.store
            .close(Deadline::at(self.clock.now.now() + self.clock.policy.drain))
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
                pool(options, clock.policy.startup)
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
                close_pool(&pool, clock.policy.drain).await?;
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
        self.clock.policy.drain
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        let token = CancellationToken::new();
        let control = Control::new(
            &self.clock,
            rss_projection::Timer::now(&self.clock) + self.clock.policy.drain,
            &token,
        );
        if self.store.close(&control).await == CloseOutcome::Drained {
            Ok(())
        } else {
            Err(shutdown_error())
        }
    }
}
async fn pool(options: PgConnectOptions, timeout: Duration) -> Result<PgPool, Error> {
    tokio::time::timeout(
        timeout,
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(timeout)
            .connect_with(options),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
async fn close_pool(pool: &PgPool, timeout: Duration) -> Result<(), Error> {
    tokio::time::timeout(timeout, pool.close())
        .await
        .map_err(|_| unavailable())
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::InventoryRuntime)
}
fn shutdown_error() -> ShutdownError {
    ShutdownError::new(std::io::Error::other("inventory runtime unavailable"))
}

/// Journal authority is scoped to the discovered owner and the worker lifetime.
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

type ProjectionHandles = (
    Arc<PgSource<Clock>>,
    rss_projection_postgres::PgProjection<rss_mdm_inventory_postgres::Inventory<Clock>>,
);

pub struct InventoryRuntime {
    observation: Arc<Observation<Clock>>,
    projection: Arc<Projection>,
    delivery: crate::collection::store::Delivery,
    storage: StorageIdentity,
    expected_epoch: Epoch,

    clock: Clock,
    pub readiness: Arc<Readiness>,
    long_operations: Arc<tokio::sync::Semaphore>,
    projections: std::sync::Mutex<std::collections::BTreeMap<uuid::Uuid, Arc<ProjectionHandles>>>,
    latest_projection:
        std::sync::Mutex<std::collections::HashMap<TenantId, diagnostics::ProjectionObservation>>,
}
impl InventoryRuntime {
    #[allow(
        clippy::too_many_arguments,
        reason = "keep execution scope and existing operation inputs explicit"
    )]
    pub fn new(
        observation: Arc<Observation<Clock>>,
        projection: Arc<Projection>,
        access: Arc<Store>,
        long_operations: Arc<tokio::sync::Semaphore>,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        storage: StorageIdentity,
        expected_epoch: Epoch,
        clock: Clock,
        readiness: Arc<Readiness>,
    ) -> Self {
        Self {
            observation,
            projection,
            delivery: crate::collection::store::Delivery::new(access, audit_store),
            storage,
            expected_epoch,

            clock,
            readiness,
            long_operations,
            projections: Default::default(),
            latest_projection: Default::default(),
        }
    }
    pub fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> ManagedTaskRegistration {
        let (task, status) = ManagedTask::prepare("mdm-inventory", self.clock.policy.drain);
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
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        report: &DurableReport,
        deadline: Deadline,
    ) -> Result<bool, WorkerFailure> {
        if report.scope().tenant() != binding.tenant() || report.expected_epoch() != binding.epoch()
        {
            return Err(WorkerFailure::ReportAuthority);
        }
        // Keep the source execution lock through Observation I/O and the original ACK.
        // Observation owns its own commit/receipt; a source rollback cannot undo that fact.
        let mut tx = self
            .delivery
            .execution(binding)
            .await
            .map_err(|_| WorkerFailure::ReportAuthority)?;
        let authority = ReportAuthority(report);
        let lifecycle = LifecycleGrant::verify(&authority, report.scope().clone())
            .map_err(|_| WorkerFailure::ReportAuthority)?;
        let verified =
            VerifiedBatch::verify(&authority, report.scope().clone(), report.batch().clone())
                .map_err(|_| WorkerFailure::ReportAuthority)?;
        let activated = self
            .observation
            .activate(
                &lifecycle,
                None,
                &rss_observation::Policy::new(86400, 3600, 3600).expect("fixed policy"),
                deadline,
            )
            .await;
        if let Err(error) = activated {
            if observation_deferred(&error, "activate") {
                return Ok(false);
            }
            return Err(WorkerFailure::ObservationActivate);
        }
        if let Err(error) = self.observation.receive(&verified, deadline).await {
            if observation_deferred(&error, "receive") {
                return Ok(false);
            }
            return Err(WorkerFailure::ObservationReceive);
        }
        // A lost acknowledgement leaves this true. Restart repeats the exact batch; lookup None
        // is never interpreted as proof of rollback.
        match self.delivery.delivered_on(&mut tx, report).await {
            Ok(()) => match tx.commit().await {
                Ok(()) => Ok(true),
                Err(_) => {
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"mdm_inventory_ack_deferred","commitUnknown":true})
                    );
                    Ok(false)
                }
            },
            Err(crate::collection::store::DeliveryError::Permanent(_)) => {
                Err(WorkerFailure::DeliveryProgress)
            }
            Err(_) => Ok(false),
        }
    }

    async fn deliver_pending(
        &self,
        reports: Vec<DurableReport>,
        deadline: Deadline,
        token: &CancellationToken,
    ) -> Result<bool, WorkerFailure> {
        let pending_count = reports.len();
        for report in reports {
            if deadline.remaining(self.clock.now.now()).is_none() {
                return Ok(false);
            }
            if token.is_cancelled() {
                return Ok(false);
            }
            match self
                .deliver(
                    ExecutionBinding::new(
                        self.storage,
                        report.scope().tenant(),
                        report.expected_epoch(),
                    ),
                    &report,
                    deadline,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(phase) => {
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
        }
        Ok(true)
    }
    async fn work(
        self: &Arc<Self>,
        token: &CancellationToken,
        notify: &tokio::sync::Notify,
    ) -> Result<(), WorkerFailure> {
        let idle = Duration::from_secs(5);
        rss_mdm_work_page::run_grouped(
            std::num::NonZeroUsize::new(2).unwrap(),
            idle,
            token,
            notify,
            (
                |(tenant, _)| tenant,
                |after| async move { self.delivery.scopes(after).await.map_err(|_| ()) },
            ),
            |(tenant, epoch)| {
                let owner = self.clone();
                let stop = token.clone();
                async move {
                    let _slot = tokio::select! { biased;
                        () = stop.cancelled() => return Ok(idle),
                        slot = owner.long_operations.acquire() => slot.expect("live access pool"),
                    };
                    owner
                        .work_scope(tenant, epoch, &stop)
                        .await
                        .map_err(|phase| {
                            eprintln!("inventory work for {tenant} deferred: {phase}")
                        })?;
                    Ok(idle)
                }
            },
            |failed| self.readiness.initialized.store(!failed, Ordering::Release),
        )
        .await;
        Ok(())
    }

    async fn work_scope(
        &self,
        tenant: uuid::Uuid,
        epoch: i64,
        token: &CancellationToken,
    ) -> Result<(), WorkerFailure> {
        let tenant_id =
            TenantId::parse(&tenant.to_string()).map_err(|_| WorkerFailure::ReportAuthority)?;
        let original = ExecutionBinding::new(
            self.storage,
            tenant_id,
            Epoch::new(epoch).map_err(|_| WorkerFailure::ReportAuthority)?,
        );
        let delivered = async {
            self.delivery
                .expire_timed(original)
                .await
                .map_err(|_| WorkerFailure::PendingReports)?;
            let deadline = self.clock.deadline();
            let reports = self
                .delivery
                .pending_reports(
                    original,
                    self.clock.policy.delivery,
                    self.clock.policy.delivery_bytes,
                )
                .await
                .map_err(|_| WorkerFailure::PendingReports)?;
            self.deliver_pending(reports, deadline, token).await
        }
        .await;
        if let Err(phase) = delivered {
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_inventory_delivery_deferred","tenant":tenant,"phase":phase})
            );
        }
        if token.is_cancelled() {
            return Ok(());
        }
        // A new projection operation may consume already committed facts from an older
        // execution. Its authorization does not rebind any unfinished collection run.
        let current = ExecutionBinding::new(self.storage, tenant_id, self.expected_epoch);
        let guard = self
            .delivery
            .execution(current)
            .await
            .map_err(|_| WorkerFailure::ReportAuthority)?;
        let drain = CancellationToken::new();
        // Discovery groups all epochs of a tenant together. Keep the first claim
        // for the lifetime of this registration, including after a fence.
        let cached = self
            .projections
            .lock()
            .expect("projection handles")
            .get(&tenant)
            .cloned();
        let handles = match cached {
            Some(handles) => handles,
            None => {
                let handles = Arc::new(self.projection_handles(current, &drain).await?);
                self.projections
                    .lock()
                    .expect("projection handles")
                    .insert(tenant, handles.clone());
                handles
            }
        };
        let (source, execution) = handles.as_ref();
        let deadline = self.clock.deadline();
        let control = Control::new(
            &self.clock,
            deadline
                .instant()
                .saturating_duration_since(self.clock.origin),
            &drain,
        );
        let run = rss_projection::run(source.as_ref(), execution, &control, self.clock.policy.run);
        {
            let mut latest = self
                .latest_projection
                .lock()
                .expect("projection observation");
            let last_completed_at = latest.get(&tenant_id).and_then(|p| p.last_completed_at);
            latest.insert(
                tenant_id,
                diagnostics::ProjectionObservation {
                    run: run.observation(),
                    started_at: self.clock.now.now(),
                    last_completed_at,
                },
            );
        }
        let result = run.await.into_result();
        if let Some(latest) = self
            .latest_projection
            .lock()
            .expect("projection observation")
            .get_mut(&tenant_id)
        {
            latest.last_completed_at = Some(self.clock.now.now());
        }
        // The source guard also covers duplicate-event checkpoint advancement, which
        // intentionally skips the application effect. It has no writes to commit.
        let _ = guard.rollback().await;
        match result {
            Ok(report) if report.applied > 0 => eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_inventory_progress","tenant":tenant,"applied":report.applied})
            ),
            Ok(_) => {}
            Err(error) => {
                // Keep the claim, including when fenced. Retaking every pass would
                // repeatedly evict another running process and lose ownership semantics.
                self.readiness.initialized.store(false, Ordering::Release);
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"mdm_projection_deferred","tenant":tenant,"kind":format!("{:?}",error.kind()),"sqlstate":error.diagnostic().and_then(|d|d.sqlstate())})
                );
                return Err(WorkerFailure::ProjectionRun);
            }
        }
        delivered.map(|_| ())
    }
    async fn projection_handles(
        &self,
        binding: ExecutionBinding,
        token: &CancellationToken,
    ) -> Result<
        (
            Arc<PgSource<Clock>>,
            rss_projection_postgres::PgProjection<rss_mdm_inventory_postgres::Inventory<Clock>>,
        ),
        WorkerFailure,
    > {
        let scope = rss_mdm_inventory_postgres::projection_scope(binding.tenant());
        let source = Arc::new(
            PgSource::new(
                self.observation.clone(),
                JournalReadGrant::verify(
                    &JournalAuthority {
                        tenant: binding.tenant(),
                        token,
                    },
                    binding.tenant(),
                )
                .map_err(|_| WorkerFailure::JournalAuthority)?,
                scope.source().clone(),
            )
            .map_err(|_| WorkerFailure::JournalAuthority)?,
        );
        let control = Control::new(&self.clock, self.clock.startup_cutoff(), token);
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
                rss_mdm_inventory_postgres::Inventory::new(source.clone(), binding),
            )
            .map_err(|_| WorkerFailure::ProjectionCompose)?;
        Ok((source, execution))
    }
    /// Called only after product permission and current scope resolution. Inspect authoritative RSS facts.
    pub async fn inspect(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        run: &Run,
        deadline: Deadline,
        cancellation: rss_request_context::Cancellation<'_>,
    ) -> Result<DeliveryStatus, Error> {
        if run.scope.tenant() != binding.tenant() {
            return Err(Error::Forbidden);
        }
        let Some(batch) = run.batch() else {
            return Ok(DeliveryStatus {
                receipt: None,
                projection: ProjectionStatus::NotApplicable,
            });
        };
        self.inspect_report(binding.tenant(), &run.scope, batch, deadline, cancellation)
            .await
    }

    pub async fn inspect_report(
        &self,
        tenant: rss_request_context::TenantId,
        scope: &Scope,
        batch: &rss_observation::Batch,
        deadline: Deadline,
        cancellation: rss_request_context::Cancellation<'_>,
    ) -> Result<DeliveryStatus, Error> {
        if scope.tenant() != tenant {
            return Err(Error::Forbidden);
        }
        let token = CancellationToken::new();
        let work = async {
            let grant = ReadGrant::verify(&ReadAuthority(scope), scope.clone())
                .map_err(|_| unavailable())?;
            let receipt = self
                .observation
                .lookup(&grant, batch.id(), deadline)
                .await
                .map_err(|_| unavailable())?;
            let event = batch
                .fingerprint(scope)
                .map_err(|_| unavailable())?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let control = Control::new(
                &self.clock,
                deadline
                    .instant()
                    .saturating_duration_since(self.clock.origin),
                &token,
            );
            let query = rss_projection::ReceiptQuery::new(
                rss_mdm_inventory_postgres::projection_scope(tenant),
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
        };
        tokio::select! { biased;
            () = cancellation.cancelled() => { token.cancel(); Err(unavailable()) },
            result = work => result,
        }
    }
}

fn stream_correlation(scope: &Scope) -> String {
    let encoded = scope.encode().unwrap_or_else(|_| "invalid-scope".into());
    Sha256::digest(encoded.as_bytes())[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn observation_deferred(error: &rss_observation::Error, phase: &str) -> bool {
    use rss_observation::ErrorKind;
    let retry = matches!(
        error.kind(),
        ErrorKind::Storage
            | ErrorKind::Deadline
            | ErrorKind::CommitUnknown
            | ErrorKind::RollbackFailed
    );
    if retry {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_inventory_delivery_deferred","phase":phase,"kind":format!("{:?}",error.kind())})
        );
    }
    retry
}

#[cfg(test)]
#[path = "../tests/runtime.rs"]
mod unit;

// Narrow schema adapter for the actual RSS serializer, not an alternate observation DTO.
// ref: rss@3de9b9eb7c43fad5ed39a02e41a035464224d3fb crates/observation/src/state.rs.
fn observation_decision_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    use rss_observation::NeedSnapshot as N;
    let need = serde_json::json!({"type":"string","enum":[N::MissingBaseline,N::BaselineMismatch,N::Gap,N::BaselineExpired,N::Partial,N::CollectionFailed]});
    let id = serde_json::json!({"type":"string","minLength":1,"maxLength":256});
    let uint = serde_json::json!({"type":"integer","format":"uint64","minimum":0});
    let baseline = serde_json::json!({"type":"object","required":["id","coverage","expiresAt"],"properties":{
        "id":id,"coverage":rss_mdm_inventory::coverage_schema(generator),"expiresAt":uint
    },"additionalProperties":false});
    let state = serde_json::json!({"type":"object","required":["version","revision","highWater","cursor","baseline","need"],"properties":{
        "version":{"type":"integer","const":1},"revision":uint,
        "highWater":{"anyOf":[uint,{"type":"null"}]},"cursor":{"anyOf":[uint,{"type":"null"}]},
        "baseline":{"anyOf":[baseline,{"type":"null"}]},"need":{"anyOf":[need,{"type":"null"}]}
    },"additionalProperties":false});
    let outcome = serde_json::json!({"oneOf":[
        {"type":"string","enum":[rss_observation::SyncOutcome::Snapshot,rss_observation::SyncOutcome::Delta,rss_observation::SyncOutcome::Stale]},
        {"type":"object","required":["needSnapshot"],"properties":{"needSnapshot":need},"additionalProperties":false}
    ]});
    schemars::json_schema!({"type":"object","required":["version","before","after","outcome"],"properties":{
        "version":{"type":"integer","const":1},"before":state,"after":state,"outcome":outcome
    },"additionalProperties":false,"x-rss-owner":"rss-observation::Decision"})
}
