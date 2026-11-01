//! Durable device-access work uses the host's store, runtime and shared process concurrency budget.
use crate::device_access::execution::{Error, Service};
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
    service: Arc<Service>,
    store: rss_reconcile_postgres::PgStore,
    outbox: Arc<PgOutboxStore<()>>,
    budget: Arc<tokio::sync::Semaphore>,
    concurrency: usize,
}
impl Worker {
    pub fn new(
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
                crate::device_access::execution::production::messaging_domain(),
                delivery,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        Ok(Self {
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
        let (task, _) = rss_runtime::ManagedTask::prepare(
            "mdm-registration-access-recovery",
            Duration::from_secs(20),
        );
        task.into_registration(move|stop|async move {
            let timer=Timer::new();let force=tokio_util::sync::CancellationToken::new();
            let control=rss_reconcile::Control::new(&timer,Duration::MAX,&force);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:self.concurrency,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),
                scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),initial_backoff:Duration::from_secs(5),max_backoff:Duration::from_secs(60),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            rss_reconcile::run_with_notify(&self.store,self.as_ref(),&crate::device_access::execution::wake::scope(self.service.transactions.tenant),policy,&control,&stop,&notify,|event| {
                match event {
                    rss_reconcile::Observation::ScanFailed { scope, error } => {
                        eprintln!("{}", serde_json::json!({"event":"mdm_access_tasks_recovery_failure","phase":"scan","scope":scope.reconciler(),"reason":format!("{:?}",error.kind())}));
                    }
                    rss_reconcile::Observation::AttemptFailed { target, error, .. } => {
                        eprintln!("{}", serde_json::json!({"event":"mdm_access_tasks_recovery_failure","phase":"attempt","target":target.entity(),"reason":format!("{:?}",error.kind())}));
                    }
                    _ => {}
                }
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)
        })
    }
    /// Host polls each concrete owner once in the single existing relay loop.
    pub async fn relay_once(&self) -> std::result::Result<usize, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(
                std::num::NonZeroUsize::MIN,
                crate::device_access::execution::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        let count = claims.len();
        for claim in claims {
            let message = PgOutboxStore::<()>::message(&claim);
            let id = message
                .message_id()
                .as_str()
                .strip_prefix("access.")
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
                    crate::device_access::execution::transaction::deadline(),
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
        control.check()?;
        if claim.target().scope()
            != &crate::device_access::execution::wake::scope(self.service.transactions.tenant)
        {
            return Err(failure(Error::Invariant));
        }
        let service = &self.service;
        let pending = crate::device_access::execution::transaction::inspect_budget(
            &service.transactions.runtime,
            service.transactions.tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                control.remaining(),
            ),
            (service.as_ref(), claim.target().entity()),
            |ctx, tx| Box::pin(async move { pending_in(ctx.0, tx, ctx.1).await }),
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
        control.check()?;
        let Ok(_permit) = self.budget.try_acquire() else {
            return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
        };
        let service = &self.service;
        if claim.target().scope()
            != &crate::device_access::execution::wake::scope(service.transactions.tenant)
        {
            return Err(failure(Error::Invariant));
        }
        let audit = RequestAudit::new(
            service.transactions.tenant.to_string(),
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("access-recovery");
        let error = Mutex::new(None);
        let attempt=service.transactions.runtime.local_tx_with_context(service.transactions.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),(service,claim,&audit,&error),|ctx,tx|Box::pin(async move {
            let (service,claim,audit,error)=ctx;
            if let Err(e)=service.transactions.audit_store.bind_in(tx).await {return Err(crate::device_access::execution::transaction::rejection(e.into(),error));}
            let ready=match prepare_in(service,tx,claim.target().entity()).await {Ok(v)=>v,Err(e)=>return Err(crate::device_access::execution::transaction::rejection(e,error))};
            service.transactions.reconcile_messaging.protect_in(tx,claim,(service,claim.target().entity(),audit,error,ready),|ctx,tx|Box::pin(async move {
                let (service,entity,audit,error,ready)=ctx;
                if matches!(ready, Prepared::Deferred) {audit.mark_commit_started();return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(Duration::from_millis(50)));}
                match advance_in(service,tx,entity,ready).await {
                    Ok(delay)=>{audit.mark_commit_started();Ok(match delay {Some(after)=>rss_reconcile_postgres::ProtectedStep::Deferred(after),None=>rss_reconcile_postgres::ProtectedStep::Ready(())})},
                    Err(e)=>Err(crate::device_access::execution::transaction::rejection(e,error)),
                }
            })).await
        })).await;
        let result = crate::device_access::execution::transaction::settle(attempt, &audit, error);
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
    Policy(Option<Box<crate::device_access::execution::policy_recovery::Prepared>>),
}
async fn prepare_in(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::device_access::execution::transaction::Result<Prepared> {
    service.transactions.validate_in(tx)?;
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(Prepared::Policy(
            crate::device_access::execution::policy_recovery::prepare_in(
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
            crate::device_access::execution::storage::read_run(tx, id)
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
                    Ok(crate::lifecycle::try_lock_devices_in(c, &tenant, &[device]).await)
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
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    prepared: &Prepared,
) -> crate::device_access::execution::transaction::Result<Option<Duration>> {
    if let Prepared::Policy(policy) = prepared {
        return match policy {
            Some(policy) => Ok(
                crate::device_access::execution::policy_recovery::advance_in(
                    &service.transactions,
                    tx,
                    policy,
                )
                .await?
                .then_some(Duration::from_millis(20)),
            ),
            None => Ok(None),
        };
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        crate::device_access::execution::recovery::recover_one(service, tx, id).await?;
        return Ok(pending_in(service, tx, entity)
            .await?
            .then_some(Duration::from_secs(5)));
    }
    Err(Error::Invariant.into())
}
// Read durable owner facts so RSS can finish the current epoch as converged.
// A concurrent wake increments the epoch and cannot be consumed by this observation.
async fn pending_in(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::device_access::execution::transaction::Result<bool> {
    service.transactions.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access_tasks.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access_tasks.runs t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
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
