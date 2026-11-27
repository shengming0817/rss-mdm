//! Standalone DA report delivery and Inventory projection.
mod delivery;
mod effect;
use crate::Error;
use rss_observation::{Access, Authority, Batch, JournalReadGrant, ObservationStore as _};
use rss_observation_postgres::{LocalPages, PgSource, PgStore};
use rss_projection::{
    Control, DefinitionIdentity, GenerationStart, ProjectionScope, ReceiptQuery, ReceiptStatus,
    ReplayBound,
};
use rss_projection_postgres::{PgProjection, PgStore as Projection};
use rss_request_context::{Deadline, TenantId};
use rss_transactional_messaging::fence::ExecutionBinding;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const INSTALL_SQL: &str = include_str!("../../schema/report-inventory.sql");
pub const MIN_PAGE_BYTES: u32 = Batch::MAX_ENCODED_BYTES;
pub(super) const GENERATION: &str = "da-report-assets-v1";
const PASS: Duration = Duration::from_secs(10);
#[derive(Clone, Copy, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ProjectionStatus {
    Running,
    HistoryExpired { confirmed: Option<u64> },
    Fenced { confirmed: Option<u64> },
}

/// Reasons why a tenant's worker stopped delivering. Each host builds a new status after admission.
#[derive(Default)]
pub struct Health(std::sync::Mutex<std::collections::HashMap<TenantId, ProjectionStatus>>);
impl Health {
    pub(super) fn status(&self, tenant: TenantId) -> ProjectionStatus {
        self.0
            .lock()
            .expect("inventory status")
            .get(&tenant)
            .copied()
            .unwrap_or(ProjectionStatus::Running)
    }
    fn blocked(&self, tenant: TenantId, status: ProjectionStatus) {
        self.0
            .lock()
            .expect("inventory status")
            .insert(tenant, status);
    }
}
type Source = PgSource<Clock, LocalPages>;

#[derive(Clone)]
struct Clock {
    origin: Instant,
    source: Arc<dyn rss_request_context::Clock>,
}
impl rss_observation::Clock for Clock {
    fn now(&self) -> Instant {
        self.source.now()
    }
}
impl rss_projection::Timer for Clock {
    fn now(&self) -> Duration {
        rss_observation::Clock::now(self).saturating_duration_since(self.origin)
    }
    async fn sleep_until(&self, at: Duration) {
        tokio::time::sleep_until((self.origin + at).into()).await;
    }
}
struct Journal(TenantId);
impl Authority for Journal {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_observation::Error> {
        if matches!(access,Access::ReadJournal{tenant} if tenant==self.0) {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}

async fn fence(c: &mut PgConnection, binding: ExecutionBinding) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
      .bind(binding.tenant().to_string()).bind(Uuid::from_bytes(binding.storage().target()).simple().to_string()).bind(Uuid::from_bytes(binding.storage().lineage()).simple().to_string()).bind(binding.epoch().get().to_string()).execute(&mut *c).await?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(c)
        .await?;
    Ok(())
}
/// One tenant-scoped worker. The host owns its database pool and shutdown order.
pub struct Worker {
    pool: PgPool,
    observation: Arc<PgStore<Clock>>,
    source: Arc<Source>,
    effect: PgProjection<effect::Assets>,
    clock: Clock,
    installation: Uuid,
    binding: ExecutionBinding,
}
/// Read-only startup qualification; acquiring a worker claim is a separate operation.
pub struct Admission {
    pool: PgPool,
    observation: Arc<PgStore<Clock>>,
    source: Arc<Source>,
    store: Projection,
    clock: Clock,
    installation: Uuid,
    binding: ExecutionBinding,
    scope: ProjectionScope,
    definition: DefinitionIdentity,
    initialized: bool,
}
impl Admission {
    pub async fn check(
        pool: PgPool,
        installation: Uuid,
        binding: ExecutionBinding,
        page_bytes: u32,
        deadline: Deadline,
        timer: Arc<dyn rss_request_context::Clock>,
    ) -> Result<Self, Error> {
        let mut probe = pool.begin().await.map_err(crate::database::db)?;
        let remaining = deadline.remaining(timer.now()).ok_or(Error::Deadline)?;
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128).to_string();
        sqlx::query(
            "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",
        )
        .bind(millis)
        .execute(&mut *probe)
        .await
        .map_err(crate::database::db)?;
        fence(&mut probe, binding)
            .await
            .map_err(crate::database::db)?;
        let allowed: bool = sqlx::query_scalar(include_str!("inventory/admission.sql"))
            .fetch_one(&mut *probe)
            .await
            .map_err(crate::database::db)?;
        probe.rollback().await.map_err(crate::database::db)?;
        if !allowed {
            return Err(Error::Forbidden);
        }
        let clock = Clock {
            origin: timer.now(),
            source: timer,
        };
        let stop = CancellationToken::new();
        let control = Control::new(
            &clock,
            deadline.instant().saturating_duration_since(clock.origin),
            &stop,
        );
        let observation = Arc::new(
            PgStore::new(pool.clone(), clock.clone(), deadline)
                .await
                .map_err(|_| Error::Storage)?,
        );
        let tenant = binding.tenant();
        let scope = ProjectionScope::new(
            rss_projection::SourceScope::new(tenant, "da.observation.v1")
                .map_err(|_| Error::Configuration)?,
            "da-inventory",
            GENERATION,
        )
        .map_err(|_| Error::Configuration)?;
        let grant =
            JournalReadGrant::verify(&Journal(tenant), tenant).map_err(|_| Error::Forbidden)?;
        let source = Arc::new(
            PgSource::new(
                observation.clone(),
                grant,
                scope.source().clone(),
                page_bytes,
            )
            .map_err(|_| Error::Configuration)?
            .into_local(),
        );
        let store = Projection::new(pool.clone(), &control)
            .await
            .map_err(|_| Error::Storage)?;
        let definition = DefinitionIdentity::new(Sha256::digest(INSTALL_SQL).into());
        let query = ReceiptQuery::new(scope.clone(), definition, GENERATION)
            .map_err(|_| Error::Configuration)?;
        let (initialized, position) = match store
            .receipt_status(&query, &control)
            .await
            .map_err(|_| Error::Storage)?
        {
            ReceiptStatus::Uninitialized => (false, None),
            ReceiptStatus::Pending(c) | ReceiptStatus::Settled(c)
                if c.bound == ReplayBound::Live =>
            {
                (true, c.position)
            }
            _ => return Err(Error::Conflict),
        };
        let bounds = source.bounds(&control).await.map_err(|_| Error::Storage)?;
        if position < bounds.expired_through || position > bounds.high_water {
            return Err(Error::Conflict);
        }
        Ok(Self {
            pool,
            observation,
            source,
            store,
            clock,
            installation,
            binding,
            scope,
            definition,
            initialized,
        })
    }

    pub async fn start(self, deadline: Deadline) -> Result<Worker, Error> {
        let Self {
            pool,
            observation,
            source,
            store,
            clock,
            installation,
            binding,
            scope,
            definition,
            initialized,
        } = self;
        let stop = CancellationToken::new();
        let control = Control::new(
            &clock,
            deadline.instant().saturating_duration_since(clock.origin),
            &stop,
        );
        if !initialized {
            store
                .initialize(
                    &scope,
                    &definition,
                    GenerationStart::beginning(),
                    ReplayBound::Live,
                    &control,
                )
                .await
                .map_err(|_| Error::Storage)?;
        }
        let claim = store
            .takeover(&scope, &definition, &control)
            .await
            .map_err(|_| Error::Storage)?;
        let effect = store
            .projection(
                claim,
                effect::Assets {
                    source: source.clone(),
                    binding,
                    installation,
                },
            )
            .map_err(|_| Error::Storage)?;
        Ok(Worker {
            pool,
            observation,
            source,
            effect,
            clock,
            installation,
            binding,
        })
    }
}
impl Worker {
    /// Execute a bounded projection pass on this tenant's durable generation.
    pub async fn project(
        &self,
        stop: &CancellationToken,
        limit: rss_projection::RunLimit,
    ) -> rss_projection::Report {
        let cutoff = rss_projection::Timer::now(&self.clock) + PASS;
        let control = Control::new(&self.clock, cutoff, stop);
        rss_projection::run_batched(&*self.source, &self.effect, &control, limit).await
    }

    async fn run(
        self,
        stop: CancellationToken,
        health: Arc<Health>,
        max_rows: rss_projection::BatchLimit,
    ) -> Result<(), rss_runtime::ShutdownError> {
        let mut rows = max_rows.get();
        loop {
            let page =
                rss_projection::PageBudget::new(rows, rss_projection::Event::MAX_PAYLOAD_BYTES)
                    .expect("positive reference budget");
            let limit = rss_projection::RunLimit::new(page, u64::from(max_rows.get()))
                .expect("positive pass");
            let started = rss_projection::Timer::now(&self.clock);
            let report = self.project(&stop, limit).await;
            let healthy = !matches!(&report.stop, rss_projection::Stop::Failed(_));
            match report.stop {
                rss_projection::Stop::Failed(e)
                    if matches!(
                        e.kind(),
                        rss_projection::ErrorKind::HistoryExpired
                            | rss_projection::ErrorKind::Fenced
                    ) =>
                {
                    let confirmed = report.position.map(|p| p.get());
                    let status = if e.kind() == rss_projection::ErrorKind::Fenced {
                        ProjectionStatus::Fenced { confirmed }
                    } else {
                        ProjectionStatus::HistoryExpired { confirmed }
                    };
                    health.blocked(self.binding.tenant(), status);
                    eprintln!(
                        "da_report_inventory_blocked tenant={} kind={:?} confirmed={confirmed:?}",
                        self.binding.tenant(),
                        e.kind()
                    );
                    stop.cancelled().await;
                    return Ok(());
                }
                rss_projection::Stop::Failed(e) => {
                    let timed_out = e.kind() == rss_projection::ErrorKind::Deadline
                        || e.diagnostic().and_then(|d| d.sqlstate()) == Some("57014")
                        || (rss_projection::Timer::now(&self.clock).saturating_sub(started)
                            >= PASS
                            && matches!(
                                e.kind(),
                                rss_projection::ErrorKind::Unavailable
                                    | rss_projection::ErrorKind::CommitUnknown
                                    | rss_projection::ErrorKind::RollbackFailed
                            ));
                    if timed_out {
                        rows = rows.div_ceil(2);
                    }
                    eprintln!(
                        "da_report_projection tenant={} kind={:?} position={:?}",
                        self.binding.tenant(),
                        e.kind(),
                        e.diagnostic().and_then(|d| d.position())
                    );
                }
                rss_projection::Stop::CaughtUp => rows = max_rows.get(),
                _ => {}
            }
            if healthy {
                let deadline = Deadline::at(rss_observation::Clock::now(&self.clock) + PASS);
                for _ in 0..max_rows.get() {
                    let delivery = tokio::select! {
                        biased;
                        ()=stop.cancelled()=>return Ok(()),
                        result=tokio::time::timeout_at(deadline.instant().into(),self.deliver(deadline))=>result,
                    };
                    match delivery {
                        Ok(Ok(true)) => {}
                        Ok(Ok(false)) => break,
                        _ => {
                            eprintln!("da_report_delivery_deferred");
                            break;
                        }
                    }
                }
            }
            tokio::select! {biased; ()=stop.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_millis(200))=>{}}
        }
    }
    pub fn registration(
        self,
        health: Arc<Health>,
        max_rows: rss_projection::BatchLimit,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) = rss_runtime::ManagedTask::prepare("da-report-inventory", PASS);
        task.into_registration(move |stop| self.run(stop, health, max_rows))
    }
}
