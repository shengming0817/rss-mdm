//! Durable script work uses the host's store, runtime and shared process concurrency budget.
use crate::{Error, ScriptService};
use rss_mdm_audit_integration::RequestAudit;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use rss_transactional_messaging_postgres::PgTransaction;
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
    store: rss_mdm_work_page::scheduler::Scheduler,

    budget: Arc<rss_mdm_work_page::capacity::Capacity>,
}
impl Worker {
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        service: Arc<ScriptService>,
        store: rss_mdm_work_page::scheduler::Scheduler,
        budget: Arc<rss_mdm_work_page::capacity::Capacity>,
    ) -> Self {
        let readiness = rss_mdm_recovery_observation::Readiness::new(
            rss_mdm_work_page::relay::lanes::SCRIPT.domain,
            true,
            false,
        );
        Self {
            read_pool,
            storage,
            readiness,
            service,
            store,
            budget,
        }
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
        if claim.target().scope().reconciler() != rss_mdm_work_page::relay::lanes::SCRIPT.domain {
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
        if claim.target().scope().reconciler() != rss_mdm_work_page::relay::lanes::SCRIPT.domain {
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
                                        if matches!(ready, Prepared::Quarantined) {
                                            return Ok(
                                                rss_reconcile_postgres::ProtectedStep::Ready(()),
                                            );
                                        }
                                        if matches!(ready, Prepared::AwaitProjection) {
                                            return Ok(
                                                rss_reconcile_postgres::ProtectedStep::Deferred(
                                                    Duration::from_secs(5),
                                                ),
                                            );
                                        }
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
    AwaitProjection,
    Quarantined,
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
        match crate::storage::read_run(tx, id).await {
            Ok(run) => Some(run.target.device),
            Err(crate::transaction::Fault::Request(Error::Invariant)) => {
                // The relay owns an unreadable run only while its exact original has not been accepted.
                // Other corruption keeps the recovery worker's normal fault semantics.
                let status: Option<String> = tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query_scalar("SELECT o.status FROM mdm_script.runs r JOIN rss_transactional_messaging.outbox o ON o.tenant_id=r.tenant_id AND o.domain=$2 AND o.message_id='script.'||r.id::text AND o.fingerprint=r.dispatch_fingerprint WHERE r.id=$1 AND r.tenant_id=current_setting('rss.tenant_id')::uuid AND NOT r.gateway_accepted").bind(id).bind(rss_mdm_work_page::relay::lanes::SCRIPT.domain).fetch_optional(c).await
                })).await?;
                return match status.as_deref() {
                    Some("dead_letter") => Ok(Prepared::Quarantined),
                    Some("pending" | "publishing") => Ok(Prepared::AwaitProjection),
                    _ => Err(Error::Invariant.into()),
                };
            }
            Err(error) => return Err(error),
        }
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
        let row: Option<(Option<bool>,bool)> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as("SELECT state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed', NOT t.gateway_accepted AND EXISTS(SELECT FROM rss_transactional_messaging.outbox o WHERE o.tenant_id=t.tenant_id AND o.domain=$3 AND o.message_id='script.'||t.id::text AND o.fingerprint=t.dispatch_fingerprint AND o.status='dead_letter') FROM mdm_script.runs t WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).bind(rss_mdm_work_page::relay::lanes::SCRIPT.domain).fetch_optional(c).await
        })).await?;
        let Some((pending, isolated)) = row else {
            return Ok(false);
        };
        if pending != Some(false) && isolated {
            // Only a matching terminal quarantine takes over an unreadable business run.
            // A readable run still processes its ordinary cancellation and deadline.
            match crate::storage::read_run(tx, id).await {
                Err(crate::transaction::Fault::Request(Error::Invariant)) => return Ok(false),
                Err(error) => return Err(error),
                Ok(_) => {}
            }
        }
        // Missing fields need owner validation in prepare_in before they can converge.
        return Ok(pending.unwrap_or(true));
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
        after: Option<Uuid>,
    ) -> std::result::Result<
        Vec<(Uuid, i64, rss_mdm_recovery_observation::RelayWork)>,
        rss_reconcile::ErrorKind,
    > {
        let page = self.readiness.relay_page();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), sqlx::query_as("SELECT tenant_id,expected_epoch,claimable,quarantined FROM mdm_script.relay_scopes($1)")
                .bind(after)
                .fetch_all(&self.read_pool))
                .await.map_err(|_|rss_reconcile::ErrorKind::Deadline).and_then(|rows|rows.map_err(|error|crate::discovery::classify(&error)));
        self.readiness
            .relay_round(result.as_ref().map(|_| ()).map_err(|kind| *kind));
        result.map(|rows| page.bindings(rows))
    }
    pub fn relay_scope(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Option<rss_mdm_recovery_observation::RelayScope<'_>> {
        Some(self.readiness.relay_scope(binding))
    }
}
