//! Bounded lifecycle for the two fixed product local projection lanes.
use crate::delivery_capacity::{Capacity, PROJECTION_SLOTS, Slot};
use crate::{Error, Failure};
use futures::{Stream, StreamExt};
use rss_transactional_messaging::transaction::IngressValidator;
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    inbox::ConsumerGroup,
    message::MessagingDomain,
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
};
use rss_transactional_messaging_postgres::PgConsumerEffect;
use rss_transactional_messaging_postgres::{
    PgConfig, PgLocalProjection, PgPassword, PgPrivateCa, PgProjectionOutcome, PgRecoveryCapture,
    PgRuntime,
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

// RSS reserves one connection in each dedicated projection pool for lease renewal.
pub(crate) use crate::delivery_capacity::PROJECTION_CONNECTIONS as CONNECTIONS;

#[derive(Default)]
pub(crate) struct Health {
    task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    observed: std::sync::atomic::AtomicBool,
    failed: std::sync::atomic::AtomicBool,
}
impl Health {
    pub(crate) fn state(&self) -> Option<rss_runtime::TaskState> {
        self.task.get().map(rss_runtime::TaskStatus::current)
    }
    pub(crate) fn observed(&self) -> bool {
        self.observed.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed.load(std::sync::atomic::Ordering::Acquire)
    }
}
pub(crate) struct Lane<'a> {
    pub database: &'a crate::config::Database,
    pub role: &'static str,
    pub domain: &'static str,
    pub consumer: &'static str,
    pub name: &'static str,
    pub scopes: &'static str,
}
pub(crate) struct Delivery<H, V> {
    name: &'static str,
    health: Arc<Health>,
    runtime: Arc<PgRuntime>,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    read_pool: sqlx::PgPool,
    scopes: &'static str,
    projection: PgLocalProjection<H, rss_mdm_native_protection::Protector>,
    validator: V,
}
fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(6))
}
// Claimed effects drain to their durable outcome. Advisory reads may end as soon as shutdown begins.
async fn read_while_running<T>(
    stop: &tokio_util::sync::CancellationToken,
    read: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! { biased; () = stop.cancelled() => None, result = read => Some(result) }
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Database)
}
impl<H, V> Delivery<H, V>
where
    H: PgConsumerEffect<Vec<u8>> + Send + Sync + 'static,
    V: IngressValidator<Vec<u8>> + Send + Sync + 'static,
{
    pub(crate) fn open<'a>(
        config: &'a crate::config::Config,
        read_pool: sqlx::PgPool,
        protection: Arc<rss_mdm_native_protection::Protector>,
        health: Arc<Health>,
        lane: Lane<'a>,
        bind: impl FnOnce(
            Arc<PgRuntime>,
            rss_transactional_messaging::fence::ExecutionBinding,
            rss_reconcile_postgres::PgMessagingStore,
        ) -> (H, V)
        + Send
        + 'a,
    ) -> futures::future::BoxFuture<'a, Result<Arc<Self>, Error>> {
        Box::pin(async move {
            let db = lane.database;
            if db.user != lane.role {
                return Err(Error::Malformed);
            }
            let binding = config.management_binding()?;
            let pg = PgConfig::new(
                &db.host,
                db.port,
                &db.name,
                &db.user,
                PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
                PgPrivateCa::from_pem(
                    crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec(),
                )
                .map_err(|_| Error::Malformed)?,
            )
            .with_pool_limits(0, CONNECTIONS);
            let runtime = Arc::new(
                PgRuntime::connect_consumer(pg, crate::lifecycle::RuntimeTimer, binding.storage())
                    .await
                    .map_err(|_| unavailable())?,
            );
            let result = async {
                let messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
                    runtime.clone(),
                    binding,
                    deadline(),
                ))
                .await
                .map_err(|_| unavailable())?;
                let (effect, validator) = bind(runtime.clone(), binding, messaging);
                let capture = PgRecoveryCapture::new(runtime.clone(), protection, deadline())
                    .await
                    .map_err(|_| unavailable())?;
                let projection = PgLocalProjection::new(
                    capture,
                    ConsumerGroup::parse(lane.consumer).expect("constant consumer"),
                    MessagingDomain::parse(lane.domain).expect("constant domain"),
                    effect,
                    DeliveryBudget::new(
                        Duration::from_secs(30),
                        Duration::from_secs(6),
                        Duration::from_secs(6),
                        Duration::from_secs(2),
                    )
                    .map_err(|_| Error::Malformed)?,
                    LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))
                        .map_err(|_| Error::Malformed)?,
                    deadline(),
                )
                .await
                .map_err(|_| unavailable())?;
                Ok(Arc::new(Self {
                    name: lane.name,
                    health,
                    runtime: runtime.clone(),
                    storage: binding.storage(),
                    read_pool,
                    scopes: lane.scopes,
                    projection,
                    validator,
                }))
            }
            .await;
            if result.is_err() {
                runtime.close().await;
            }
            result
        })
    }

    async fn poll(
        &self,
        binding: ExecutionBinding,
        cancel: &tokio_util::sync::CancellationToken,
        mut slots: Vec<Slot>,
    ) -> Result<usize, PollFailure> {
        let Some(dead) = read_while_running(
            cancel,
            self.projection.has_dead_letters(binding, deadline()),
        )
        .await
        else {
            return Ok(0);
        };
        if dead.map_err(|_| PollFailure::Unavailable)? {
            return Err(PollFailure::RecoveryRequired);
        }
        if cancel.is_cancelled() {
            return Ok(0);
        }
        let batch = self
            .projection
            .project_batch(
                binding,
                &self.validator,
                NonZeroUsize::new(slots.len()).expect("admitted projection"),
                OperationDeadline::from_remaining(Duration::from_secs(1)),
                Duration::from_secs(6),
            )
            .await
            .map_err(|_| PollFailure::Unavailable)?;
        // RSS may claim fewer heads than requested. Its stream bounds tell us
        // how many reservations can be returned before a slow effect completes.
        if let Some(upper) = batch.size_hint().1 {
            slots.truncate(upper);
        }
        let outcomes = batch
            .map(|item| {
                let slot = slots.pop().expect("claimed head has an execution slot");
                async move {
                    let _slot = slot;
                    self.outcome(item, cancel).await
                }
            })
            .buffer_unordered(PROJECTION_SLOTS);
        tokio::pin!(outcomes);
        let mut progress = 0;
        let mut failure = None;
        while let Some(result) = outcomes.next().await {
            match result {
                Ok(committed) => progress += usize::from(committed),
                Err(PollFailure::RecoveryRequired) => failure = Some(PollFailure::RecoveryRequired),
                Err(PollFailure::Unavailable) => {
                    failure.get_or_insert(PollFailure::Unavailable);
                }
            }
        }
        failure.map_or(Ok(progress), Err)
    }

    async fn outcome(
        &self,
        item: rss_transactional_messaging_postgres::PgProjectionItem,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<bool, PollFailure> {
        match item.into_outcome() {
            Ok(PgProjectionOutcome::Attempt(attempt)) => {
                let (outcome, recovery) = attempt.into_parts();
                use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
                match outcome.status() {
                    Status::Committed => Ok(true),
                    Status::CommitUnknown | Status::RollbackFailed => match read_while_running(
                        cancel,
                        self.projection.resolve(&recovery, deadline()),
                    )
                    .await
                    {
                        None => Ok(false),
                        Some(result) => result
                            .ok()
                            .flatten()
                            .map(|_| true)
                            .ok_or(PollFailure::Unavailable),
                    },
                    _ => Err(PollFailure::Unavailable),
                }
            }
            Ok(PgProjectionOutcome::InProgress) => Ok(false),
            Ok(PgProjectionOutcome::DeliveryExpired | PgProjectionOutcome::Rejected(_)) => {
                Err(PollFailure::RecoveryRequired)
            }
            Err(_) => Err(PollFailure::Unavailable),
        }
    }

    async fn batch(
        &self,
        key: (uuid::Uuid, i64),
        stop: &tokio_util::sync::CancellationToken,
        budget: &Arc<Capacity>,
    ) -> Result<Duration, PollFailure> {
        let Some(slots) = budget.acquire(self.name, key.0, stop).await else {
            return Ok(Duration::ZERO);
        };
        let tenant = rss_request_context::TenantId::parse(&key.0.to_string())
            .map_err(|_| PollFailure::Unavailable)?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(key.1)
            .map_err(|_| PollFailure::Unavailable)?;
        let binding = ExecutionBinding::new(self.storage, tenant, epoch);
        if self.poll(binding, stop, slots).await? > 0 {
            return Ok(Duration::ZERO);
        }
        // The advisory read uses this same pool. Keep its renewal connection available.
        let Some(_slots) = budget.acquire(self.name, key.0, stop).await else {
            return Ok(Duration::ZERO);
        };
        read_while_running(stop, self.next_delay(binding))
            .await
            .transpose()
            .map(|delay| delay.unwrap_or_default())
            .map_err(|_| PollFailure::Unavailable)
    }
    pub(crate) async fn next_delay(
        &self,
        binding: ExecutionBinding,
    ) -> Result<Duration, rss_transactional_messaging_postgres::PgError> {
        let wake = self.projection.next_wakeup(binding, deadline()).await?;
        if wake.due_now() {
            return Ok(Duration::from_millis(100));
        }
        Ok(wake.next_deadline().map_or(Duration::from_secs(60), |d| {
            d.instant()
                .saturating_duration_since(rss_request_context::Clock::now(
                    &crate::lifecycle::RuntimeTimer,
                ))
        }))
    }
    pub(crate) fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare(self.name, Duration::from_secs(8));
        let _ = self.health.task.set(status);
        task.into_registration(move |stop| async move {
            let budget = Capacity::projection();
            rss_mdm_work_page::run_partitioned(
                (budget.total(), budget.batches_per_binding()),
                Duration::from_secs(60),
                &stop,
                &notify,
                (
                    |key: (uuid::Uuid, i64)| key.0,
                    |after: Option<(uuid::Uuid, i64)>| {
                        let lane = &self;
                        async move {
                            sqlx::query_as(lane.scopes)
                                .bind(after.map(|key| key.0))
                                .bind(after.map(|key| key.1))
                                .fetch_all(&lane.read_pool)
                                .await
                                .map_err(|_| eprintln!("{} discovery failed", lane.name))
                        }
                    },
                ),
                |key| {
                    let lane = self.clone();
                    let budget = budget.clone();
                    let cancel = stop.clone();
                    async move {
                        lane.batch(key, &cancel, &budget).await.map_err(|error| {
                            let event = serde_json::json!({
                                "event":"local_delivery_unavailable", "worker":lane.name,
                                "tenant":key.0, "epoch":key.1,
                                "recoveryRequired":matches!(error, PollFailure::RecoveryRequired)
                            });
                            eprintln!("{event}");
                        })
                    }
                },
                |failed| {
                    self.health
                        .failed
                        .store(failed, std::sync::atomic::Ordering::Release);
                    self.health
                        .observed
                        .store(true, std::sync::atomic::Ordering::Release);
                },
            )
            .await;
            Ok(())
        })
    }
}
enum PollFailure {
    Unavailable,
    RecoveryRequired,
}

pub(crate) struct Resource<H, V>(pub Arc<Delivery<H, V>>);
impl<H, V> rss_runtime::ManagedResource for Resource<H, V>
where
    H: PgConsumerEffect<Vec<u8>> + Send + Sync + 'static,
    V: IngressValidator<Vec<u8>> + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        self.0.name
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.runtime.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::read_while_running;
    #[tokio::test]
    async fn shutdown_ends_receipt_reads_and_skips_late_recovery_queries() {
        let stop = tokio_util::sync::CancellationToken::new();
        let read = read_while_running(&stop, std::future::pending::<()>());
        tokio::pin!(read);
        assert!(futures::poll!(&mut read).is_pending());
        stop.cancel();
        assert_eq!(read.await, None);
        let late = read_while_running(&stop, async {
            panic!("receipt read started after shutdown")
        })
        .await;
        assert_eq!(late, None::<()>);
    }
}
