//! Durable enrollment work uses the host's store, runtime and shared process concurrency budget.
use crate::enrollment::tasks::{Error, Service};
use rss_mdm_audit_integration::RequestAudit;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use rss_transactional_messaging_postgres::{PgOutboxStore, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
pub struct Worker {
    readiness: rss_mdm_recovery_observation::Readiness,
    service: Arc<Service>,
    store: rss_reconcile_postgres::PgStore,
    outbox: Arc<PgOutboxStore<()>>,
    budget: Arc<tokio::sync::Semaphore>,
    concurrency: usize,
}
impl Worker {
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        service: Arc<Service>,
        store: rss_reconcile_postgres::PgStore,
        budget: Arc<tokio::sync::Semaphore>,
        concurrency: usize,
    ) -> std::result::Result<Self, Error> {
        let delivery = rss_transactional_messaging::policy::DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(6),
            Duration::from_secs(6),
            Duration::from_secs(6),
        )
        .map_err(|_| Error::Invariant)?;
        let outbox = Arc::new(
            PgOutboxStore::new(
                service.transactions.runtime.clone(),
                crate::enrollment::tasks::admission::messaging_domain(profile),
                delivery,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        let readiness = rss_mdm_recovery_observation::Readiness::new(
            crate::enrollment::tasks::wake::scope(profile, service.transactions.tenant),
            true,
            false,
        );
        Ok(Self {
            readiness,
            service,
            store,
            outbox,
            budget,
            concurrency,
        })
    }
    pub fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let profile = self.service.profile();

        let (task, status) = rss_runtime::ManagedTask::prepare(
            "mdm-device-enrollment-recovery",
            Duration::from_secs(20),
        );
        self.readiness.bind(status);
        task.into_registration(move|stop|async move {
            let timer=Timer::new();let force=tokio_util::sync::CancellationToken::new();
            let control=rss_reconcile::Control::new(&timer,Duration::MAX,&force);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:self.concurrency,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),
                scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),initial_backoff:Duration::from_secs(5),max_backoff:Duration::from_secs(60),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let result = rss_reconcile::run_with_notify(&self.recovery_store(),self.as_ref(),&crate::enrollment::tasks::wake::scope(profile, self.service.transactions.tenant),policy,&control,&stop,&notify,|event| {
                self.readiness.observe(&event);
                if let rss_reconcile::Observation::ScanFailed { scope, error } = &event { eprintln!("{}",serde_json::json!({"event":"mdm_registration_tasks_recovery_failure","phase":"scan","scope":scope.reconciler(),"reason":format!("{:?}",error.kind())})); }
                if let rss_reconcile::Observation::AttemptFailed{target,error,..}=event {eprintln!("{}",serde_json::json!({"event":"mdm_registration_tasks_recovery_failure","target":target.entity(),"reason":format!("{:?}",error.kind())}));}
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new);
            self.readiness.stop();
            result
        })
    }
    pub fn health(&self) -> rss_mdm_recovery_observation::Health {
        self.readiness.health()
    }
    pub fn recovery_store(
        &self,
    ) -> impl rss_reconcile::DurableStore<Claim = rss_reconcile_postgres::PgClaim> + '_ {
        rss_mdm_recovery_observation::ObservedStore::new(&self.store, &self.readiness)
    }
    pub fn record_relay_health(&self, result: &std::result::Result<usize, Error>) {
        self.readiness.relay(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
    /// Host polls each concrete owner once in the single existing relay loop.
    pub async fn relay_once(&self) -> std::result::Result<usize, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(
                std::num::NonZeroUsize::MIN,
                crate::enrollment::tasks::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        let count = claims.len();
        for claim in claims {
            let message = PgOutboxStore::<()>::message(&claim);
            let id = message
                .message_id()
                .as_str()
                .strip_prefix("enrollment.")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(Error::Invariant)?;
            let result = self
                .service
                .accept_action_dispatch(id, message.fingerprint().as_bytes().to_vec())
                .await;
            if result.as_ref().err().is_some_and(permanent) {
                return result.map(|_| count);
            }
            let settlement = if result.is_ok() {
                OutboxSettlement::Published(())
            } else {
                OutboxSettlement::Retry
            };
            self.outbox
                .settle(
                    claim,
                    settlement,
                    crate::enrollment::tasks::transaction::deadline(),
                )
                .await
                .map_err(|_| Error::Unavailable)?;
            result?;
        }
        Ok(count)
    }
}
fn permanent(e: &Error) -> bool {
    matches!(
        e,
        Error::Malformed | Error::Forbidden | Error::Unauthorized | Error::Invariant
    )
}
fn failure(e: Error) -> rss_reconcile::Error {
    let kind = match e {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::RollbackFailed => rss_reconcile::ErrorKind::RollbackFailed,
        Error::Conflict => rss_reconcile::ErrorKind::Fenced,
        ref e if permanent(e) => rss_reconcile::ErrorKind::Permanent,
        _ => rss_reconcile::ErrorKind::Transient,
    };
    rss_reconcile::Error::new(kind)
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for Worker {
    type State = bool;
    async fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error> {
        let profile = self.service.profile();

        control.check()?;
        if claim.target().scope()
            != &crate::enrollment::tasks::wake::scope(profile, self.service.transactions.tenant)
        {
            return Err(failure(Error::Invariant));
        }
        let service = &self.service;
        let pending = crate::enrollment::tasks::transaction::inspect_budget(
            &service.transactions.runtime,
            service.transactions.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                control.remaining(),
            ),
            (service.as_ref(), claim.target().entity()),
            |ctx, tx| Box::pin(async move { pending_in(profile, ctx.0, tx, ctx.1).await }),
        )
        .await
        .map_err(failure)?;
        control.check()?;
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        )))
    }
    async fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, rss_reconcile::Error> {
        let profile = self.service.profile();

        control.check()?;
        let Ok(_permit) = self.budget.try_acquire() else {
            return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
        };
        let service = &self.service;
        if claim.target().scope()
            != &crate::enrollment::tasks::wake::scope(profile, service.transactions.tenant)
        {
            return Err(failure(Error::Invariant));
        }
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            profile,
            service.transactions.tenant.to_string(),
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("enrollment-recovery");
        let error = Mutex::new(None);
        let attempt=service.transactions.runtime.local_tx_with_context(service.transactions.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),(service,claim,&audit,&error),|ctx,tx|Box::pin(async move {
            let (service,claim,audit,error)=ctx;
            if let Err(e)=service.transactions.audit_store.bind_in(tx).await {return Err(crate::enrollment::tasks::transaction::rejection(e.into(),error));}
            let ready=match prepare_in(profile, service,tx,claim.target().entity()).await {Ok(v)=>v,Err(e)=>return Err(crate::enrollment::tasks::transaction::rejection(e,error))};
            service.transactions.reconcile_messaging.protect_in(tx,claim,(service,claim.target().entity(),audit,error,ready),|ctx,tx|Box::pin(async move {
                let (service,entity,audit,error,ready)=ctx;
                if matches!(ready, Prepared::Deferred) {audit.mark_commit_started();return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(Duration::from_millis(50)));}
                match advance_in(profile, service,tx,entity,ready).await {
                    Ok(delay)=>{audit.mark_commit_started();Ok(match delay {Some(after)=>rss_reconcile_postgres::ProtectedStep::Deferred(after),None=>rss_reconcile_postgres::ProtectedStep::Ready(())})},
                    Err(e)=>Err(crate::enrollment::tasks::transaction::rejection(e,error)),
                }
            })).await
        })).await;
        let result = crate::enrollment::tasks::transaction::settle(attempt, &audit, error);
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result.map_err(failure)
    }
}
enum Prepared {
    Deferred,
    Ready,
    Policy(Option<Box<crate::enrollment::tasks::policy_recovery::Prepared>>),
}
async fn prepare_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::enrollment::tasks::transaction::Result<Prepared> {
    service.transactions.validate_in(tx)?;
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(Prepared::Policy(
            crate::enrollment::tasks::policy_recovery::prepare_in(
                profile,
                &service.transactions,
                tx,
                id,
            )
            .await?
            .map(Box::new),
        ));
    }
    let device = if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(
            crate::enrollment::tasks::storage::read_run(profile, tx, id)
                .await?
                .target
                .device,
        )
    } else {
        None
    };
    if let Some(device) = device {
        let tenant = tx.tenant_id().to_string();
        let locked = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(crate::lifecycle::try_lock_devices_in(profile, c, &tenant, &[device]).await)
                })
            })
            .await??;
        return Ok(if locked {
            Prepared::Ready
        } else {
            Prepared::Deferred
        });
    }
    Ok(Prepared::Ready)
}
async fn advance_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    prepared: &Prepared,
) -> crate::enrollment::tasks::transaction::Result<Option<Duration>> {
    if let Prepared::Policy(policy) = prepared {
        return match policy {
            Some(policy) => Ok(crate::enrollment::tasks::policy_recovery::advance_in(
                profile,
                &service.transactions,
                tx,
                policy,
            )
            .await?
            .then_some(Duration::from_millis(20))),
            None => Ok(None),
        };
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        crate::enrollment::tasks::recovery::recover_one(profile, service, tx, id).await?;
        return Ok(pending_in(profile, service, tx, entity)
            .await?
            .then_some(Duration::from_secs(5)));
    }
    Err(Error::Invariant.into())
}
// Read durable owner facts so RSS can finish the current epoch as converged.
// A concurrent wake increments the epoch and cannot be consumed by this observation.
async fn pending_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::enrollment::tasks::transaction::Result<bool> {
    service.transactions.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        crate::storage_profile::sql(profile).enrollment_tasks_worker_pending_in_1,
                    )
                    .bind(tenant)
                    .bind(id)
                    .fetch_one(c)
                    .await
                })
            })
            .await?);
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        crate::storage_profile::sql(profile).enrollment_tasks_worker_pending_in_2,
                    )
                    .bind(tenant)
                    .bind(id)
                    .fetch_one(c)
                    .await
                })
            })
            .await?);
    }

    Err(Error::Invariant.into())
}

struct Timer(tokio::time::Instant);
impl Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete monotonic injection boundary"
    )]
    fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl rss_reconcile::Timer for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete monotonic injection boundary"
    )]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }
}
