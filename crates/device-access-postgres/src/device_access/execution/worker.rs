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
    read_pool: sqlx::PgPool,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    readiness: rss_mdm_recovery_observation::Readiness,
    service: Arc<Service>,
    store: rss_reconcile_postgres::PgStore,
    outbox: Arc<PgOutboxStore<()>>,
    budget: Arc<tokio::sync::Semaphore>,
}
impl Worker {
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        service: Arc<Service>,
        store: rss_reconcile_postgres::PgStore,
        budget: Arc<tokio::sync::Semaphore>,
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
        let readiness = rss_mdm_recovery_observation::Readiness::new(
            "mdm.registration.device-access.v1",
            true,
            false,
        );
        Ok(Self {
            read_pool,
            storage,
            readiness,
            service,
            store,
            outbox,
            budget,
        })
    }
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-registration-access-recovery", drain);
        self.readiness.bind(status);
        task.into_registration(move |stop| async move {
            let timer = Timer::new();
            let force = tokio_util::sync::CancellationToken::new();
            let control = rss_reconcile::Control::new(&timer, Duration::MAX, &force);
            let mut after: Option<Uuid> = None;
            let mut worked = false;
            let result = async {
                loop {
                    if stop.is_cancelled() {
                        return Ok(());
                    }
                    let discovered = tokio::select! { biased;
                    () = stop.cancelled() => { self.readiness.stop(); return Ok(()); },
                    result = tokio::time::timeout(Duration::from_secs(5), sqlx::query_scalar(
                        "SELECT tenant_id FROM rss_da.access_runs_work_scopes($1)",
                    )
                    .bind(after)
                    .fetch_all(&self.read_pool)) =>
                        result.map_err(|_| rss_reconcile::ErrorKind::Deadline)
                            .and_then(|page| page.map_err(|error| crate::discovery::classify(&error))),
                };
                if stop.is_cancelled() { { self.readiness.stop(); return Ok(()); } }
                self.readiness.discovery(discovered.as_ref().map(|_| ()).map_err(|kind| *kind));
                let tenants: Vec<Uuid> = match discovered {
                    Ok(page) => page,
                    Err(rss_reconcile::ErrorKind::Transient | rss_reconcile::ErrorKind::Deadline) => {
                        // A failed page is not empty. Keep its cursor and rate-limit retries even under wake storms.
                        tokio::select! { biased;
                            () = stop.cancelled() => { self.readiness.stop(); return Ok(()); },
                            () = tokio::time::sleep(Duration::from_secs(5)) => {},
                        }
                        continue;
                    }
                    Err(kind) => return Err(rss_runtime::ShutdownError::new(rss_reconcile::Error::new(kind))),
                };
                if tenants.is_empty() {
                        after = None;
                        if std::mem::take(&mut worked) {
                            continue;
                        }

                        tokio::select! { biased;
                            () = stop.cancelled() => return Ok(()),
                            () = notify.notified() => {},
                            () = tokio::time::sleep(Duration::from_secs(5)) => {},
                        }
                        continue;
                    }
                    for tenant in tenants {
                        after = Some(tenant);
                        let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                            .map_err(rss_runtime::ShutdownError::new)?;
                        let scope = crate::device_access::execution::wake::scope(tenant);

                        let report = match rss_reconcile::run_batch(
                            &self.recovery_store(),
                            self.as_ref(),
                            &scope,
                            policy,
                            &control,
                            &stop,
                            |event| {
                                self.readiness.observe(&event);
                            },
                        )
                        .await
                        {
                            Ok(report) => report,
                            Err(error)
                                if control.check().is_ok()
                                    && matches!(
                                        error.kind(),
                                        rss_reconcile::ErrorKind::Transient
                                            | rss_reconcile::ErrorKind::Deadline
                                            | rss_reconcile::ErrorKind::CommitUnknown
                                    ) =>
                            {
                                // The observer retained this scope's failure. Advance the tenant cursor;
                                // an unconfirmed claim is not an empty or successfully drained batch.
                                continue;
                            }
                            Err(error) => return Err(rss_runtime::ShutdownError::new(error)),
                        };
                        worked |= [
                            report.converged,
                            report.reobserve,
                            report.deferred,
                            report.retried,
                            report.suspended,
                            report.fenced,
                            report.execution_failed,
                        ]
                        .into_iter()
                        .any(|count| count > 0);
                    }
                }
            }
            .await;
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
    pub fn record_relay_health<T>(&self, result: &std::result::Result<T, Error>) {
        self.readiness.relay_round(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
    pub async fn claim_relay(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        limit: std::num::NonZeroUsize,
    ) -> std::result::Result<Vec<impl Future<Output = std::result::Result<(), Error>> + Send + '_>, Error> {
        if !self.service.accepts_new_work() {
            return Ok(Vec::new());
        }
        let claims = self
            .outbox
            .claim_partition_heads(
                binding,
                limit,
                crate::device_access::execution::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(claims.into_iter().map(|claim| self.relay_claim(binding, claim)).collect())
    }
    async fn relay_claim(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        claim: rss_transactional_messaging_postgres::PgOutboxClaim,
    ) -> std::result::Result<(), Error> {
        let message = PgOutboxStore::<()>::message(&claim);
        let id = message
            .message_id()
            .as_str()
            .strip_prefix("access.")
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or(Error::Invariant)?;
        let result = self
            .service
            .accept_action_dispatch(binding, id, message.fingerprint().as_bytes().to_vec())
            .await;
        if result.as_ref().err().is_some_and(permanent) {
            return result;
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
        result
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
        let binding = self.execution(claim, control).await?;
        control.check()?;
        if claim.target().scope().reconciler() != ("mdm.registration.device-access.v1") {
            return Err(failure(Error::Invariant));
        }
        let service = &self.service;
        let pending = crate::device_access::execution::transaction::inspect_budget(
            &service.transactions.runtime,
            binding,
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
        let binding = self.execution(claim, control).await?;
        control.check()?;
        let Ok(_permit) = self.budget.try_acquire() else {
            return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
        };
        let service = &self.service;
        if claim.target().scope().reconciler() != ("mdm.registration.device-access.v1") {
            return Err(failure(Error::Invariant));
        }
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Da,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("access-recovery");
        let error = Mutex::new(None);
        let attempt=service.transactions.runtime.local_tx_with_context(binding,rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),(service,claim,&audit,&error),|ctx,tx|Box::pin(async move {
            let (service,claim,audit,error)=ctx;
            if let Err(e)=service.transactions.audit_store.bind_in(tx).await {return Err(crate::device_access::execution::transaction::rejection(e.into(),error));}
            let ready=match prepare_in(service,tx,claim.target().entity()).await {Ok(v)=>v,Err(e)=>return Err(crate::device_access::execution::transaction::rejection(e,error))};
            if !matches!(ready, Prepared::Deferred) {
                let resources = match crate::device_access::execution::wake::resources_in(tx, claim.target().entity()).await {Ok(v)=>v, Err(e)=>return Err(crate::device_access::execution::transaction::rejection(e,error))};
                service.transactions.reconcile_messaging.bind_in(tx, claim.target(), &resources).await?;
            }
            let settlement_audit = *audit;
            let outcome = service.transactions.reconcile_messaging.protect_in(tx,claim,(service,claim.target().entity(),audit,error,ready),|ctx,tx|Box::pin(async move {
                let (service,entity,_audit,error,ready)=ctx;
                if matches!(ready, Prepared::Deferred) {return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(Duration::from_millis(50)));}
                match advance_in(binding, service,tx,entity,ready).await {
                    Ok(delay)=>{Ok(match delay {Some(after)=>rss_reconcile_postgres::ProtectedStep::Deferred(after),None=>rss_reconcile_postgres::ProtectedStep::Ready(())})},
                    Err(e)=>Err(crate::device_access::execution::transaction::rejection(e,error)),
                }
            })).await;
            if outcome.is_ok() { settlement_audit.mark_commit_started(); }
            outcome
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
    if !service.accepts_new_work() && entity.starts_with("policy:") {
        return Ok(Prepared::Policy(None));
    }
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
                    Ok(
                        rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                            rss_mdm_install_support::StorageProfile::Da,
                            c,
                            &tenant,
                            &[device],
                        )
                        .await,
                    )
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
    binding: rss_transactional_messaging::fence::ExecutionBinding,
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
        crate::device_access::execution::recovery::recover_one(binding, service, tx, id).await?;
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
    if !service.accepts_new_work() && entity.starts_with("policy:") {
        return Ok(false);
    }
    let tenant = tx.tenant_id().to_string();
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_da.access_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_da.access_runs t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))")
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

impl Worker {
    async fn execution<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<
        rss_transactional_messaging::fence::ExecutionBinding,
        rss_reconcile::Error,
    > {
        control.check()?;
        let tenant = claim.target().scope().tenant();
        let epoch: i64 = sqlx::query_scalar("SELECT rss_da.access_runs_work_epoch($1::uuid,$2)")
            .bind(tenant.to_string())
            .bind(claim.target().entity())
            .fetch_one(&self.read_pool)
            .await
            .map_err(|_| failure(Error::Unavailable))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| failure(Error::Invariant))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
    pub async fn relay_page(
        &self,
        after: Option<(Uuid, i64)>,
    ) -> std::result::Result<Vec<(Uuid, i64)>, Error> {
        let result = sqlx::query_as(
            "SELECT tenant_id,expected_epoch FROM rss_da.access_runs_work_relay_scopes($1,$2)",
        )
        .bind(after.map(|x| x.0))
        .bind(after.map(|x| x.1))
        .fetch_all(&self.read_pool)
        .await
        .map_err(|_| Error::Unavailable);
        self.record_relay_health(&result);
        result
    }
    pub fn observe_relay(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        result: &std::result::Result<usize, Error>,
    ) {
        self.readiness.relay_scope(
            &crate::device_access::execution::wake::scope(binding.tenant()),
            binding.epoch().get(),
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
}
