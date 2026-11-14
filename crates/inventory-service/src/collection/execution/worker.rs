//! Durable collection work uses the host's store, runtime and shared process concurrency budget.
use super::CollectionService;
use crate::Error;
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
    relay_after: Mutex<Option<(Uuid, i64)>>,
    readiness: rss_mdm_recovery_observation::Readiness,
    service: Arc<CollectionService>,
    store: rss_reconcile_postgres::PgStore,
    outbox: Arc<PgOutboxStore<()>>,
    budget: Arc<tokio::sync::Semaphore>,
}
impl Worker {
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        service: Arc<CollectionService>,
        store: rss_reconcile_postgres::PgStore,
        budget: Arc<tokio::sync::Semaphore>,
    ) -> std::result::Result<Self, Error> {
        let delivery = rss_transactional_messaging::policy::DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(6),
            Duration::from_secs(6),
            Duration::from_secs(6),
        )
        .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
        let outbox = Arc::new(
            PgOutboxStore::new(
                service.transactions.runtime.clone(),
                super::admission::messaging_domain(),
                delivery,
            )
            .map_err(|_| Error::Unavailable(crate::Failure::CollectionQuery))?,
        );
        let readiness =
            rss_mdm_recovery_observation::Readiness::new("mdm.collection.v1", true, false);
        Ok(Self {
            read_pool,
            storage,
            relay_after: Mutex::new(None),
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
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-collection-recovery", drain);
        self.readiness.bind(status);
        task.into_registration(move |stop| async move {
            let timer = Timer::new();
            let force = tokio_util::sync::CancellationToken::new();
            let control = rss_reconcile::Control::new(&timer, Duration::MAX, &force);
            let mut after: Option<Uuid> = None;
            let result = async {
                loop {
                    if stop.is_cancelled() {
                        return Ok(());
                    }
                    let tenants: Vec<Uuid> = sqlx::query_scalar(
                        "SELECT tenant_id FROM mdm_inventory.collection_work_scopes($1)",
                    )
                    .bind(after)
                    .fetch_all(&self.read_pool)
                    .await
                    .map_err(rss_runtime::ShutdownError::new)?;
                    if tenants.is_empty() {
                        self.readiness.scan(Ok(()));
                        after = None;
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
                        let scope = super::wake::scope(tenant);
                        let turn = stop.child_token();
                        let pass = Pass {
                            worker: &self,
                            stop: &turn,
                        };
                        rss_reconcile::run_with_notify(
                            &pass,
                            self.as_ref(),
                            &scope,
                            policy,
                            &control,
                            &turn,
                            &notify,
                            |event| {
                                self.readiness.observe(&event);
                            },
                        )
                        .await
                        .map_err(rss_runtime::ShutdownError::new)?;
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
    pub fn record_relay_health(&self, result: &std::result::Result<usize, Error>) {
        self.readiness.relay(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
    /// Host polls each concrete owner once in the single existing relay loop.
    async fn relay_binding(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> std::result::Result<usize, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(
                binding,
                std::num::NonZeroUsize::MIN,
                crate::transaction::deadline(),
            )
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::CollectionQuery))?;
        let count = claims.len();
        for claim in claims {
            let message = PgOutboxStore::<()>::message(&claim);
            let id = message
                .message_id()
                .as_str()
                .strip_prefix("collection.")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(Error::Unavailable(crate::Failure::PlanningStorage))?;
            let result = self
                .service
                .accept_action_dispatch(binding, id, message.fingerprint().as_bytes().to_vec())
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
                .settle(claim, settlement, crate::transaction::deadline())
                .await
                .map_err(|_| Error::Unavailable(crate::Failure::CollectionQuery))?;
            result?;
        }
        Ok(count)
    }
}
fn permanent(e: &Error) -> bool {
    matches!(
        e,
        Error::Malformed
            | Error::Forbidden
            | Error::Unauthorized
            | Error::Unavailable(crate::Failure::PlanningStorage)
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
        if claim.target().scope().reconciler() != ("mdm.collection.v1") {
            return Err(failure(Error::Unavailable(crate::Failure::PlanningStorage)));
        }
        let service = &self.service;
        let pending = crate::transaction::inspect_budget(
            &service.transactions.runtime,
            binding,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                control.remaining(),
            ),
            (service.as_ref(), claim.target().entity()),
            |ctx, tx| Box::pin(async move { pending_in(ctx.0, tx, ctx.1).await }),
            crate::transaction::TransactionOwner::Collections,
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
        if claim.target().scope().reconciler() != ("mdm.collection.v1") {
            return Err(failure(Error::Unavailable(crate::Failure::PlanningStorage)));
        }
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("collection-recovery");
        let error = Mutex::new(None);
        let attempt = service
            .transactions
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (service, claim, &audit, &error),
                |ctx, tx| {
                    Box::pin(async move {
                        let (service, claim, audit, error) = ctx;
                        if let Err(e) = service.transactions.audit_store.bind_in(tx).await {
                            return Err(crate::transaction::rejection(
                                e.into(),
                                error,
                                crate::transaction::TransactionOwner::Collections,
                            ));
                        }
                        let ready = match prepare_in(service, tx, claim.target().entity()).await {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(crate::transaction::rejection(
                                    e,
                                    error,
                                    crate::transaction::TransactionOwner::Collections,
                                ));
                            }
                        };
                        if !matches!(ready, Prepared::Deferred) {
                            let resources = match super::wake::resources_in(
                                tx,
                                claim.target().entity(),
                            )
                            .await
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    return Err(crate::transaction::rejection(
                                        e,
                                        error,
                                        crate::transaction::TransactionOwner::Collections,
                                    ));
                                }
                            };
                            service
                                .transactions
                                .reconcile_messaging
                                .bind_in(tx, claim.target(), &resources)
                                .await?;
                        }
                        let settlement_audit = *audit;
                        let outcome = service
                            .transactions
                            .reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (service, claim.target().entity(), audit, error, ready),
                                |ctx, tx| {
                                    Box::pin(async move {
                                        let (service, entity, _audit, error, ready) = ctx;
                                        if matches!(ready, Prepared::Deferred) {
                                            return Ok(
                                                rss_reconcile_postgres::ProtectedStep::Deferred(
                                                    Duration::from_millis(50),
                                                ),
                                            );
                                        }
                                        match advance_in(binding, service, tx, entity, ready).await
                                        {
                                            Ok(delay) => Ok(match delay {
                                                Some(after) => {
                                                    rss_reconcile_postgres::ProtectedStep::Deferred(
                                                        after,
                                                    )
                                                }
                                                None => {
                                                    rss_reconcile_postgres::ProtectedStep::Ready(())
                                                }
                                            }),
                                            Err(e) => Err(crate::transaction::rejection(
                                                e,
                                                error,
                                                crate::transaction::TransactionOwner::Collections,
                                            )),
                                        }
                                    })
                                },
                            )
                            .await;
                        if outcome.is_ok() {
                            settlement_audit.mark_commit_started();
                        }
                        outcome
                    })
                },
            )
            .await;
        let result = crate::transaction::settle(
            attempt,
            &audit,
            error,
            crate::transaction::TransactionOwner::Collections,
        );
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
    Policy(Option<Box<super::policy_recovery::Prepared>>),
}
async fn prepare_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::transaction::Result<Prepared> {
    service.transactions.validate_in(tx)?;
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(Prepared::Policy(
            super::policy_recovery::prepare_in(&service.transactions, tx, id)
                .await?
                .map(Box::new),
        ));
    }
    let device = if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        let tenant = tx.tenant_id().to_string();
        Some(tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(Uuid,bool)>("SELECT device,channel='agent' FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await.and_then(|(id, agent)| Ok((crate::database::device_id(id)?, agent)))})).await?)
    } else if let Some(work) = super::scheduled::Work::parse(entity) {
        super::scheduled::device_in(&service.transactions.policy_reader, tx, &work)
            .await?
            .map(|device| (device, false))
    } else if let Some(device) = checkin(entity) {
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Uuid>("SELECT id AS device FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2").bind(tenant).bind(device.into_uuid()).fetch_optional(c).await.and_then(|id| id.map(crate::database::device_id).transpose())})).await?.map(|device| (device, false))
    } else {
        None
    };
    if let Some((device, shared)) = device {
        let tenant = tx.tenant_id().to_string();
        let locked = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(if shared {
                        rss_mdm_registration_service::lifecycle::try_lock_recovery_in(
                            c, &tenant, &device,
                        )
                        .await
                    } else {
                        rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                            rss_mdm_install_support::StorageProfile::Mdm,
                            c,
                            &tenant,
                            &[device],
                        )
                        .await
                    })
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
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    prepared: &Prepared,
) -> crate::transaction::Result<Option<Duration>> {
    if let Prepared::Policy(policy) = prepared {
        return match policy {
            Some(policy) => {
                Ok(
                    super::policy_recovery::advance_in(&service.transactions, tx, policy)
                        .await?
                        .then_some(Duration::from_millis(20)),
                )
            }
            None => Ok(None),
        };
    }
    if let Some(work) = super::scheduled::Work::parse(entity) {
        super::scheduled::advance_in(binding, service, tx, &work, Uuid::new_v4()).await?;
        return super::scheduled::delay_in(service, tx, &work).await;
    }
    if let Some(device) = checkin(entity) {
        super::checkins::step(binding, service, tx, device, Uuid::new_v4()).await?;
        let tenant = tx.tenant_id().to_string();
        let active:bool=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_inventory.collection_native_checkins WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND (active_event IS NOT NULL OR pending_event IS NOT NULL))").bind(tenant).bind(device.into_uuid()).fetch_one(c).await})).await?;
        return Ok(active.then_some(Duration::from_millis(20)));
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        super::recovery::recover_one(binding, service, tx, id).await?;
        return Ok(pending_in(service, tx, entity)
            .await?
            .then_some(Duration::from_secs(5)));
    }
    Err(Error::Unavailable(crate::Failure::PlanningStorage).into())
}
// Read durable owner facts so RSS can finish the current epoch as converged.
// A concurrent wake increments the epoch and cannot be consumed by this observation.
async fn pending_in(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::transaction::Result<bool> {
    service.transactions.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_inventory.collection_tasks t WHERE tenant_id=$1::uuid AND id=$2 AND (((channel='agent' AND agent_state->>'execution' IN('not_started','running') AND agent_state->>'cancellation'<>'confirmed') OR (channel='mdm' AND ((collection_run IS NULL AND native_delivery<>'cancelled') OR (collection_run IS NOT NULL AND NOT terminal_notified))))))")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }
    if let Some(work) = super::scheduled::Work::parse(entity) {
        return Ok(super::scheduled::delay_in(service, tx, &work)
            .await?
            .is_some());
    }
    if let Some(device) = checkin(entity) {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_inventory.collection_native_checkins WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND (active_event IS NOT NULL OR pending_event IS NOT NULL))")
                .bind(tenant).bind(device.into_uuid()).fetch_one(c).await
        })).await?);
    }
    Err(Error::Unavailable(crate::Failure::PlanningStorage).into())
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

fn checkin(entity: &str) -> Option<rss_mdm_agent_wire::DeviceId> {
    entity.strip_prefix("checkin:")?.parse().ok()
}

struct Pass<'a> {
    worker: &'a Worker,
    stop: &'a tokio_util::sync::CancellationToken,
}
impl rss_reconcile::DurableStore for Pass<'_> {
    type Claim = rss_reconcile_postgres::PgClaim;
    async fn wake<T: rss_reconcile::Timer>(
        &self,
        target: &rss_reconcile::Target,
        resources: &rss_reconcile::ResourceSet,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.worker
            .recovery_store()
            .wake(target, resources, control)
            .await
    }
    async fn bind_resources<T: rss_reconcile::Timer>(
        &self,
        target: &rss_reconcile::Target,
        resources: &rss_reconcile::ResourceSet,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.worker
            .recovery_store()
            .bind_resources(target, resources, control)
            .await
    }
    async fn claim_due<T: rss_reconcile::Timer>(
        &self,
        scope: &rss_reconcile::Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<
        rss_reconcile::ClaimBatch<rss_reconcile_postgres::PgClaim>,
        rss_reconcile::Error,
    > {
        let result = self
            .worker
            .recovery_store()
            .claim_due(scope, limit, scan_budget, lease, control)
            .await;
        self.stop.cancel();
        result
    }
    async fn renew<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        lease: Duration,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.worker
            .recovery_store()
            .renew(claim, lease, control)
            .await
    }
    async fn release<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.worker.recovery_store().release(claim, control).await
    }
    async fn finish<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.worker
            .recovery_store()
            .finish(claim, completion, control)
            .await
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
        let epoch: i64 =
            sqlx::query_scalar("SELECT mdm_inventory.collection_work_epoch($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(claim.target().entity())
                .fetch_one(&self.read_pool)
                .await
                .map_err(|_| failure(Error::Unavailable(crate::Failure::PlanningStorage)))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| failure(Error::Unavailable(crate::Failure::PlanningStorage)))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
    pub async fn relay_once(&self) -> std::result::Result<usize, Error> {
        let after = *self
            .relay_after
            .lock()
            .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
        let scopes: Vec<(Uuid,i64)> = sqlx::query_as("SELECT tenant_id,expected_epoch FROM mdm_inventory.collection_work_relay_scopes($1,$2)")
            .bind(after.map(|x|x.0)).bind(after.map(|x|x.1)).fetch_all(&self.read_pool).await.map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
        if scopes.is_empty() {
            *self
                .relay_after
                .lock()
                .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))? = None;
            return Ok(0);
        }
        let mut count = 0;
        for (tenant, epoch) in scopes {
            let t = rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
            let e = rss_transactional_messaging::fence::Epoch::new(epoch)
                .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))?;
            let result = self
                .relay_binding(rss_transactional_messaging::fence::ExecutionBinding::new(
                    self.storage,
                    t,
                    e,
                ))
                .await;
            *self
                .relay_after
                .lock()
                .map_err(|_| Error::Unavailable(crate::Failure::PlanningStorage))? =
                Some((tenant, epoch));
            self.readiness.relay_scope(
                &super::wake::scope(t),
                epoch,
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| failure(e.clone()).kind()),
            );
            if let Ok(relayed) = result {
                count += relayed;
            }
        }
        Ok(count)
    }
}
