//! Fixed Group-to-Scope local delivery assembly and bounded lifecycle.
use crate::{Error, Failure};
use futures::StreamExt;
use rss_mdm_scope_service::group_changes::{CONSUMER, DOMAIN, Receiver, Validator};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::ConsumerGroup,
    message::MessagingDomain,
    policy::{DeliveryBudget, LeaseRenewalPolicy, OperationDeadline},
};
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
pub(crate) struct Delivery {
    health: Arc<Health>,
    runtime: Arc<PgRuntime>,
    projection: PgLocalProjection<Receiver, rss_mdm_native_protection::Protector>,
    validator: Validator,
}
fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(6))
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Database)
}
impl Delivery {
    pub(crate) async fn open(
        config: &crate::config::Config,
        protection: Arc<rss_mdm_native_protection::Protector>,
        health: Arc<Health>,
    ) -> Result<Arc<Self>, Error> {
        let db = &config.scope_group_database;
        if db.user != "mdm_scope_group_consumer" {
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
            PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())
                .map_err(|_| Error::Malformed)?,
        )
        .with_pool_limits(0, 2);
        let binding = ExecutionBinding::new(
            StorageIdentity::new(config.flow.storage.target, config.flow.storage.lineage)
                .map_err(|_| Error::Malformed)?,
            vec![(
                tenant,
                Epoch::new(config.flow.storage.epoch).map_err(|_| Error::Malformed)?,
            )],
        )
        .map_err(|_| Error::Malformed)?;
        let runtime = Arc::new(
            PgRuntime::connect_consumer(pg, crate::lifecycle::RuntimeTimer, binding)
                .await
                .map_err(|_| unavailable())?,
        );
        let result = async {
            let capture = PgRecoveryCapture::new(runtime.clone(), protection, deadline())
                .await
                .map_err(|_| unavailable())?;
            let projection = PgLocalProjection::new(
                capture,
                ConsumerGroup::parse(CONSUMER).expect("constant consumer"),
                MessagingDomain::parse(DOMAIN).expect("constant domain"),
                Receiver::new(runtime.clone(), tenant),
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
                health,
                runtime: runtime.clone(),
                projection,
                validator: Validator { tenant },
            }))
        }
        .await;
        if result.is_err() {
            runtime.close().await;
        }
        result
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
    pub(crate) fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("scope-group-delivery", Duration::from_secs(8));
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
                    Err(PollFailure::RecoveryRequired)=>return Err(rss_runtime::ShutdownError::new(std::io::Error::other("Group event requires recovery"))),
                    Err(PollFailure::Unavailable)=>{
                        self.health.failed.store(true,std::sync::atomic::Ordering::Release);
                        eprintln!("{}",serde_json::json!({"event":"scope_group_delivery_unavailable"}));
                    }
                }
                tokio::select!{()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
        })
    }
}
enum PollFailure {
    Unavailable,
    RecoveryRequired,
}

pub(crate) struct Resource(pub Arc<Delivery>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "scope-group-consumer"
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
#[path = "../tests/groups/delivery.rs"]
mod tests;
