//! Bounded lifecycle for the two fixed product local projection lanes.
use crate::{Error, Failure};
use futures::StreamExt;
use rss_transactional_messaging::transaction::IngressValidator;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
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
}
pub(crate) struct Delivery<H, V> {
    name: &'static str,
    health: Arc<Health>,
    runtime: Arc<PgRuntime>,
    projection: PgLocalProjection<H, rss_mdm_native_protection::Protector>,
    validator: V,
}
fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(6))
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
        protection: Arc<rss_mdm_native_protection::Protector>,
        health: Arc<Health>,
        lane: Lane<'a>,
        bind: impl FnOnce(
            Arc<PgRuntime>,
            rss_request_context::TenantId,
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
            let tenant = rss_request_context::TenantId::parse(&config.identity.tenant_id)
                .map_err(|_| Error::Malformed)?;
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
            .with_pool_limits(0, 2);
            let binding = ExecutionBinding::new(
                StorageIdentity::new(
                    config.storage_binding.target,
                    config.storage_binding.lineage,
                )
                .map_err(|_| Error::Malformed)?,
                vec![(
                    tenant,
                    Epoch::new(config.storage_binding.epoch).map_err(|_| Error::Malformed)?,
                )],
            )
            .map_err(|_| Error::Malformed)?;
            let runtime = Arc::new(
                PgRuntime::connect_consumer(pg, crate::lifecycle::RuntimeTimer, binding)
                    .await
                    .map_err(|_| unavailable())?,
            );
            let result = async {
                let messaging = rss_reconcile_postgres::PgMessagingStore::new(
                    runtime.clone(),
                    tenant,
                    deadline(),
                )
                .await
                .map_err(|_| unavailable())?;
                let (effect, validator) = bind(runtime.clone(), tenant, messaging);
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
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<usize, PollFailure> {
        if self
            .projection
            .has_dead_letters(deadline())
            .await
            .map_err(|_| PollFailure::Unavailable)?
        {
            return Err(PollFailure::RecoveryRequired);
        }
        if cancel.is_cancelled() {
            return Ok(0);
        }
        let batch = self
            .projection
            .project_batch(
                &self.validator,
                NonZeroUsize::new(1).expect("one"),
                OperationDeadline::from_remaining(Duration::from_secs(1)),
                Duration::from_secs(6),
            )
            .await
            .map_err(|_| PollFailure::Unavailable)?;
        tokio::pin!(batch);
        let mut count = 0;
        while let Some(item) = batch.next().await {
            count += 1;
            match item.into_outcome().map_err(|_| PollFailure::Unavailable)? {
                PgProjectionOutcome::Attempt(attempt) => {
                    let (outcome, recovery) = attempt.into_parts();
                    use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
                    match outcome.status() {
                        Status::Committed => {}
                        Status::CommitUnknown | Status::RollbackFailed => {
                            if cancel.is_cancelled() {
                                return Ok(count);
                            }
                            if self
                                .projection
                                .resolve(&recovery, deadline())
                                .await
                                .map_err(|_| PollFailure::Unavailable)?
                                .is_none()
                            {
                                return Err(PollFailure::Unavailable);
                            }
                        }
                        _ => return Err(PollFailure::Unavailable),
                    }
                }
                PgProjectionOutcome::InProgress => {}
                PgProjectionOutcome::DeliveryExpired | PgProjectionOutcome::Rejected(_) => {
                    return Err(PollFailure::RecoveryRequired);
                }
            }
        }
        Ok(count)
    }
    pub(crate) fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare(self.name, Duration::from_secs(8));
        let _ = self.health.task.set(status);
        task.into_registration(move |cancel|async move {
            loop {
                if cancel.is_cancelled(){return Ok(());}
                match self.poll(&cancel).await {
                    Ok(count)=>{
                        self.health.failed.store(false,std::sync::atomic::Ordering::Release);
                        self.health.observed.store(true,std::sync::atomic::Ordering::Release);
                        if count>0 {continue;}
                    }
                    Err(PollFailure::RecoveryRequired)=>return Err(rss_runtime::ShutdownError::new(std::io::Error::other("Product input event requires recovery"))),
                    Err(PollFailure::Unavailable)=>{
                        self.health.failed.store(true,std::sync::atomic::Ordering::Release);
                        eprintln!("{}",serde_json::json!({"event":"local_delivery_unavailable","worker":self.name}));
                    }
                }
                let delay = match self.projection.next_wakeup(deadline()).await {
                    Ok(wakeup) if wakeup.due_now() => Duration::from_millis(100),
                    Ok(wakeup) => wakeup.next_deadline().map_or(Duration::from_secs(60), |at| {
                        at.instant().saturating_duration_since(rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer))
                            .min(Duration::from_secs(60)).max(Duration::from_millis(100))
                    }),
                    Err(_) => { self.health.failed.store(true,std::sync::atomic::Ordering::Release); Duration::from_secs(5) }
                };
                tokio::select!{()=cancel.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(delay)=>{}}
            }
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
