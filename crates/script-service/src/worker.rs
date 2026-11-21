//! Durable script work uses the host's store, runtime and shared process concurrency budget.
use crate::{Error, ScriptService};
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
    service: Arc<ScriptService>,
    store: rss_reconcile_postgres::PgStore,
    outbox: Arc<PgOutboxStore<()>>,
    budget: Arc<rss_mdm_work_page::capacity::Capacity>,
}
impl Worker {
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        service: Arc<ScriptService>,
        store: rss_reconcile_postgres::PgStore,
        budget: Arc<rss_mdm_work_page::capacity::Capacity>,
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
                crate::admission::messaging_domain(),
                delivery,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        let readiness = rss_mdm_recovery_observation::Readiness::new("mdm.script.v1", true, false);
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
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-script-recovery", drain);
        self.readiness.bind(status);
        task.into_registration(move |stop| async move {
            let service = self.as_ref();
            let owner = self.clone();
            let budget = self.budget.clone();
            let result = rss_mdm_work_page::reconcile::run(
                &budget,
                policy,
                &stop,
                &notify,
                |after| async move {
                    let discovered = tokio::time::timeout(
                        Duration::from_secs(5),
                        sqlx::query_scalar("SELECT tenant_id FROM mdm_script.work_scopes($1)")
                            .bind(after)
                            .fetch_all(&service.read_pool),
                    )
                    .await
                    .map_err(|_| rss_reconcile::ErrorKind::Deadline)
                    .and_then(|page| page.map_err(|error| crate::discovery::classify(&error)));
                    service
                        .readiness
                        .discovery(discovered.as_ref().map(|_| ()).map_err(|kind| *kind));
                    discovered
                },
                move |tenant, slots, stop| {
                    let owner = owner.clone();
                    async move {
                        let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                            .map_err(|_| {
                                rss_reconcile::Error::new(rss_reconcile::ErrorKind::InvalidInput)
                            })?;
                        let scope = crate::wake::scope(tenant);
                        rss_mdm_work_page::reconcile::batch(
                            (&owner.recovery_store(), owner.as_ref()),
                            slots,
                            &scope,
                            policy,
                            &stop,
                            |event| {
                                owner.readiness.observe(&event);
                            },
                        )
                        .await
                    }
                },
            )
            .await
            .map_err(rss_runtime::ShutdownError::new);
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
    ) -> std::result::Result<
        Vec<(
            rss_mdm_recovery_observation::RelayMessage,
            impl Future<Output = std::result::Result<(), Error>> + Send + '_,
        )>,
        Error,
    > {
        let claims = self
            .outbox
            .claim_partition_heads(binding, limit, crate::transaction::deadline())
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(claims
            .into_iter()
            .map(|claim| {
                (
                    rss_mdm_recovery_observation::RelayMessage::from(PgOutboxStore::<()>::message(
                        &claim,
                    )),
                    self.relay_claim(binding, claim),
                )
            })
            .collect())
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
            .strip_prefix("script.")
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
            .settle(claim, settlement, crate::transaction::deadline())
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
        if claim.target().scope().reconciler() != "mdm.script.v1" {
            return Err(failure(Error::Invariant));
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
        let service = &self.service;
        if claim.target().scope().reconciler() != "mdm.script.v1" {
            return Err(failure(Error::Invariant));
        }
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            binding,
            "command_reconcile",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("script-recovery");
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
                            return Err(crate::transaction::rejection(e.into(), error));
                        }
                        let ready = match prepare_in(service, tx, claim.target().entity()).await {
                            Ok(v) => v,
                            Err(e) => return Err(crate::transaction::rejection(e, error)),
                        };
                        if !matches!(ready, Prepared::Deferred) {
                            let resources = match crate::wake::resources_in(
                                tx,
                                claim.target().entity(),
                            )
                            .await
                            {
                                Ok(v) => v,
                                Err(e) => return Err(crate::transaction::rejection(e, error)),
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
                                            Err(e) => Err(crate::transaction::rejection(e, error)),
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
        let result = crate::transaction::settle(attempt, &audit, error);
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
    Policy(Option<Box<crate::policy_recovery::Prepared>>),
}
async fn prepare_in(
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> crate::transaction::Result<Prepared> {
    service.transactions.validate_in(tx)?;
    if let Some(id) = entity
        .strip_prefix("policy:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(Prepared::Policy(
            crate::policy_recovery::prepare_in(&service.transactions, tx, id)
                .await?
                .map(Box::new),
        ));
    }
    let device = if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(crate::storage::read_run(tx, id).await?.target.device)
    } else {
        None
    };
    if let Some(device) = device {
        let tenant = tx.tenant_id().to_string();
        let locked = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_registration_service::lifecycle::try_lock_recovery_in(
                            c, &tenant, &device,
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
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    prepared: &Prepared,
) -> crate::transaction::Result<Option<Duration>> {
    if let Prepared::Policy(policy) = prepared {
        return match policy {
            Some(policy) => {
                Ok(
                    crate::policy_recovery::advance_in(&service.transactions, tx, policy)
                        .await?
                        .then_some(Duration::from_millis(20)),
                )
            }
            None => Ok(None),
        };
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        crate::recovery::recover_one(binding, service, tx, id).await?;
        return Ok(pending_in(service, tx, entity)
            .await?
            .then_some(Duration::from_secs(5)));
    }
    Err(Error::Invariant.into())
}
// Read durable owner facts so RSS can finish the current epoch as converged.
// A concurrent wake increments the epoch and cannot be consumed by this observation.
async fn pending_in(
    service: &ScriptService,
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
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }
    if let Some(id) = entity
        .strip_prefix("run:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_script.runs t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?);
    }

    Err(Error::Invariant.into())
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
        let epoch: i64 = sqlx::query_scalar("SELECT mdm_script.work_epoch($1::uuid,$2)")
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
        let page = self.readiness.relay_page(after);
        let result =
            sqlx::query_as("SELECT tenant_id,expected_epoch FROM mdm_script.relay_scopes($1,$2)")
                .bind(after.map(|x| x.0))
                .bind(after.map(|x| x.1))
                .fetch_all(&self.read_pool)
                .await
                .map_err(|_| Error::Unavailable);
        if let Ok(rows) = &result {
            page.confirm(rows);
        }
        self.record_relay_health(&result);
        result
    }
    pub fn relay_check(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Option<(
        rss_mdm_recovery_observation::RelayCheck<'_>,
        &rss_transactional_messaging_postgres::PgRuntime,
        &rss_transactional_messaging_postgres::PgOutboxStore<()>,
    )> {
        Some((
            self.readiness.relay_check(binding)?,
            &self.service.transactions.runtime,
            &self.outbox,
        ))
    }
    pub fn observe_relay(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        message: Option<&rss_mdm_recovery_observation::RelayMessage>,
        result: std::result::Result<(), &Error>,
    ) {
        self.readiness.relay_scope(
            &crate::wake::scope(binding.tenant()),
            binding.epoch().get(),
            message,
            result.map_err(|e| failure(e.clone()).kind()),
        );
    }
}
