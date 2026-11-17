//! Bounded lifecycle for the two fixed product local projection lanes.
use crate::{Error, Failure};
use futures::StreamExt;
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
            .with_pool_limits(0, 2);
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
    ) -> Result<usize, PollFailure> {
        if self
            .projection
            .has_dead_letters(binding, deadline())
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
                binding,
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
            let mut after:Option<(uuid::Uuid,i64)>=None;
            let mut failed=false;let mut delay=Duration::from_secs(60);
            loop {
                if cancel.is_cancelled(){return Ok(())}
                let page=sqlx::query_as::<_,(uuid::Uuid,i64)>(self.scopes).bind(after.map(|v|v.0)).bind(after.map(|v|v.1)).fetch_all(&self.read_pool).await;
                let rows=match page {
                    Ok(rows)=>rows,
                    Err(_)=>{failed=true;delay=Duration::from_secs(5);Vec::new()},
                };
                if rows.is_empty(){
                    self.health.failed.store(failed,std::sync::atomic::Ordering::Release);
                    self.health.observed.store(true,std::sync::atomic::Ordering::Release);
                    after=None;failed=false;
                    tokio::select!{()=cancel.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(delay)=>{}}
                    delay=Duration::from_secs(60);continue;
                }
                for (tenant,epoch) in rows {
                    after=Some((tenant,epoch));
                    let tenant=rss_request_context::TenantId::parse(&tenant.to_string()).map_err(rss_runtime::ShutdownError::new)?;
                    let epoch=rss_transactional_messaging::fence::Epoch::new(epoch).map_err(rss_runtime::ShutdownError::new)?;
                    let binding=ExecutionBinding::new(self.storage,tenant,epoch);
                    match self.poll(binding,&cancel).await {
                        Ok(count)=>{if count>0{delay=Duration::from_millis(100)}},
                        Err(error)=>{
                            failed=true;
                            self.health.failed.store(true,std::sync::atomic::Ordering::Release);
                            eprintln!("{}",serde_json::json!({"event":"local_delivery_unavailable","worker":self.name,"tenant":tenant.to_string(),"recoveryRequired":matches!(error,PollFailure::RecoveryRequired)}));
                        },
                    }
                    let wakeup=match self.projection.next_wakeup(binding,deadline()).await {
                        Ok(wakeup) if wakeup.due_now()=>Duration::from_millis(100),
                        Ok(wakeup)=>wakeup.next_deadline().map_or(Duration::from_secs(60),|at|at.instant().saturating_duration_since(rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)).max(Duration::from_millis(100))),
                        Err(_)=>{failed=true;Duration::from_secs(5)},
                    };
                    delay=delay.min(wakeup);
                }
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
