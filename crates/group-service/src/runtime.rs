//! Group-only durable execution; the host owns the shared scheduler pool.
/// Maximum concurrent transactions scheduled by this owner worker.
pub const CONCURRENCY: usize = 2;
use super::*;
use rss_reconcile::{
    ActualState, ClaimBatch, Completion, Control, DesiredState, DurableStore,
    Error as ReconcileError, ErrorKind, ReconcileDiff, ReconcileStep, Reconciler, ResourceSet,
    Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore, ProtectedStep};
use rss_transactional_messaging_postgres::PgError;
use std::{sync::Mutex, time::Duration};

pub struct GroupWork {
    groups: Arc<Groups>,
    schedule: PgStore,
}
impl GroupWork {
    pub fn new(groups: Arc<Groups>, schedule: PgStore) -> Self {
        Self { groups, schedule }
    }
    async fn capture<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_mdm_inventory::AssetCut, ReconcileError> {
        control.check()?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
        rss_mdm_inventory_service::assets::cut::capture(
            &self.groups.audit_store,
            binding.tenant(),
            &budget,
        )
        .await
        .map_err(|e| storage(fault(e.into(), &Mutex::new(None))))
    }
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.reconciler() != "mdm.groups" {
            return Err(ReconcileError::new(ErrorKind::Invariant));
        }
        Ok(())
    }
    fn task(&self, claim: &PgClaim) -> std::result::Result<Option<Uuid>, ReconcileError> {
        self.check(claim.target().scope())?;
        if claim.target().entity() == "inputs" {
            return Ok(None);
        }
        claim
            .target()
            .entity()
            .strip_prefix("task:")
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(Some)
            .ok_or_else(|| ReconcileError::new(ErrorKind::Invariant))
    }
    async fn reject<T: Timer>(
        &self,
        claim: &PgClaim,
        id: Uuid,
        reason: &str,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        let candidate = if reason == "superseded" {
            Some(self.capture(binding, control).await?)
        } else {
            None
        };
        self.groups
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.groups, claim, reason, candidate.as_ref()),
                |(groups, claim, reason, candidate), tx| {
                    Box::pin(async move {
                        groups
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        let state = groups
                            .read_task_in(tx, id)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        tx.prepare_outbox_partitions(&[groups
                            .groups
                            .partition(tx.tenant_id(), &state.input.target().to_string())?])
                            .await?;
                        groups
                            .check_task_transaction(tx)
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        groups
                            .reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (groups, *reason, *candidate),
                                |(groups, reason, candidate), tx| {
                                    Box::pin(async move {
                                        groups
                                            .finish_task_in(binding, tx, id, Some(reason))
                                            .await
                                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                                        if *reason == "superseded" {
                                            groups
                                                .ensure_group_followup_in(
                                                    binding,
                                                    tx,
                                                    id,
                                                    candidate.ok_or_else(|| {
                                                        sqlx::Error::Protocol(
                                                            "missing group replacement input"
                                                                .into(),
                                                        )
                                                    })?,
                                                )
                                                .await
                                                .map_err(|e| fault(e, &Mutex::new(None)))?;
                                        }
                                        Ok(ProtectedStep::Ready(()))
                                    })
                                },
                            )
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(storage(e)),
                |e| Err(storage(e)),
                |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )
    }
}
fn unknown() -> ReconcileError {
    ReconcileError::new(ErrorKind::CommitUnknown)
}
fn storage(error: PgError) -> ReconcileError {
    ReconcileError::new(
        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            ErrorKind::Fenced
        } else {
            ErrorKind::Transient
        },
    )
}
fn fault(error: Fault, slot: &Mutex<Option<Error>>) -> PgError {
    match error {
        Fault::Request(error) => {
            *slot.lock().expect("failure slot") = Some(error);
            sqlx::Error::Protocol("group task rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => error.into(),
    }
}
impl Reconciler<PgClaim> for GroupWork {
    type State = bool;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<ReconcileDiff<bool>>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        control.check()?;
        let Some(id) = self.task(claim)? else {
            let pending = self.inputs_pending(binding, control).await?;
            return Ok(ReconcileStep::Ready(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(pending),
            )));
        };
        let pending = self
            .groups
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.groups,
                |groups, tx| {
                    Box::pin(async move {
                        groups
                            .read_task_in(tx, id)
                            .await
                            .map(|s| !s.completed)
                            .map_err(|e| fault(e, &Mutex::new(None)))
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(storage(e)),
                |e| Err(storage(e)),
                |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )?;
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        )))
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<bool>,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        control.check()?;
        let Some(id) = self.task(claim)? else {
            return self.apply_inputs(claim, control).await;
        };
        let candidate = self.capture(binding, control).await?;
        let failure = Mutex::new(None);
        let attempt =
            self.groups
                .runtime
                .local_tx_with_context(
                    binding,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                    (&self.groups, claim, &failure, &candidate),
                    |(groups, claim, failure, candidate), tx| {
                        Box::pin(async move {
                            groups
                                .audit_store
                                .bind_in(tx)
                                .await
                                .map_err(PgError::from)?;
                            let state = groups
                                .read_task_in(tx, id)
                                .await
                                .map_err(|e| fault(e, failure))?;
                            tx.prepare_outbox_partitions(&[groups
                                .groups
                                .partition(tx.tenant_id(), &state.input.target().to_string())?])
                                .await?;
                            groups
                                .authorize_task_in(tx, id, &state.input)
                                .await
                                .map_err(|e| fault(e, failure))?;
                            groups
                                .check_task_transaction(tx)
                                .map_err(|e| fault(e, failure))?;
                            groups
                                .reconcile_messaging
                                .protect_in(
                                    tx,
                                    claim,
                                    (groups, *failure, *candidate),
                                    |(groups, failure, candidate), tx| {
                                        Box::pin(async move {
                                            let result: Result<()> =
                                                async {
                                                    let state = groups.read_task_in(tx, id).await?;
                                                    if state.completed {
                                                        return Ok(());
                                                    }
                                                    match state.input {
                                            tasks::TaskInput::Definition { ref edit } => {
                                                groups
                                                    .advance_group_definition_in(binding,
                                                        tx,
                                                        id,
                                                        edit,
                                                        state.definition_progress,
                                                        candidate,
                                                    )
                                                    .await
                                            }
                                            ref input @ tasks::TaskInput::Calculation { .. } => {
                                                groups
                                                    .advance_group_job_in(binding,
                                                        tx,
                                                        id,
                                                        input,
                                                        state.cursor,
                                                        candidate,
                                                    )
                                                    .await
                                            }
                                        }
                                                }
                                                .await;
                                            result
                                                .map(ProtectedStep::Ready)
                                                .map_err(|e| fault(e, failure))
                                        })
                                    },
                                )
                                .await
                        })
                    },
                )
                .await;
        let rejection = attempt.fold(
            |step| Ok(Ok(step)),
            |e| Err(storage(e)),
            |e| {
                if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost
                {
                    return Err(ReconcileError::new(ErrorKind::Fenced));
                }
                failure
                    .lock()
                    .expect("failure slot")
                    .take()
                    .map(Err)
                    .ok_or_else(|| storage(e))
            },
            |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
            |_| Err(unknown()),
            |e| Err(storage(e)),
        )?;
        let reason = match rejection {
            Ok(step) => return Ok(step),
            Err(Error::Conflict) => "superseded",
            Err(Error::Malformed) => "invalid_input",
            Err(Error::Forbidden | Error::Unauthorized) => "permission_denied",
            Err(Error::Group(_) | Error::NotFound) => "source_unavailable",
            Err(Error::Unavailable(
                Failure::AssetBytesLimit | Failure::AssetObjectLimit | Failure::AssetSourceLimit,
            )) => "capacity_exceeded",
            Err(Error::CommitUnknown) => return Err(unknown()),
            Err(Error::RollbackFailed) => {
                return Err(ReconcileError::new(ErrorKind::RollbackFailed));
            }
            Err(_) => return Err(ReconcileError::new(ErrorKind::Transient)),
        };
        self.reject(claim, id, reason, control).await
    }
}
struct GroupPass<'a> {
    work: &'a GroupWork,
    stop: &'a tokio_util::sync::CancellationToken,
}
impl std::ops::Deref for GroupPass<'_> {
    type Target = GroupWork;
    fn deref(&self) -> &Self::Target {
        self.work
    }
}
impl DurableStore for GroupWork {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.check(target.scope())?;
        self.schedule.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.check(target.scope())?;
        self.schedule
            .bind_resources(target, resources, control)
            .await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<ClaimBatch<PgClaim>, ReconcileError> {
        self.check(scope)?;
        let result = self
            .schedule
            .claim_due(scope, limit, scan_budget, lease, control)
            .await;
        self.groups
            .record_scan(result.as_ref().err().map(|e| e.kind()));
        result
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.task(claim)?;
        self.schedule.renew(claim, lease, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.task(claim)?;
        self.schedule.release(claim, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        let id = self.task(claim)?;
        let settlement = control.child(Duration::from_secs(6));
        if let Some(id) = id
            && matches!(completion, Completion::Suspended { .. })
            && matches!(
                self.reject(claim, id, "automation_suspended", &settlement)
                    .await?,
                ReconcileStep::Deferred(_)
            )
        {
            return Err(ReconcileError::new(ErrorKind::BindingChanged));
        }
        if id.is_none() && !matches!(completion, Completion::Deferred(_)) {
            let failed = !matches!(completion, Completion::Converged | Completion::Reobserve(_));
            if matches!(
                self.set_input_failure(claim, failed, &settlement).await?,
                ReconcileStep::Deferred(_)
            ) {
                return Err(ReconcileError::new(ErrorKind::BindingChanged));
            }
        }
        let result = self.schedule.finish(claim, completion, &settlement).await;
        if result.is_ok() {
            self.groups.record_settled(claim.target(), completion);
        }
        result
    }
}
impl DurableStore for GroupPass<'_> {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.work.wake(target, resources, control).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.work.bind_resources(target, resources, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<ClaimBatch<PgClaim>, ReconcileError> {
        let result = self
            .work
            .claim_due(scope, limit, scan_budget, lease, control)
            .await;
        self.stop.cancel();
        result
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.work.renew(claim, lease, control).await
    }
    async fn release<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.work.release(claim, control).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.work.finish(claim, completion, control).await
    }
}

struct GroupTimer(tokio::time::Instant);
impl Timer for GroupTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "monotonic execution clock boundary"
    )]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }
}
impl GroupWork {
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-group-calculation", drain);
        let _ = self.groups.task_status.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(
                clippy::disallowed_methods,
                reason = "monotonic execution clock boundary"
            )]
            let timer = GroupTimer(tokio::time::Instant::now());
            let force = tokio_util::sync::CancellationToken::new();
            let control = Control::new(&timer, Duration::MAX, &force);
            let mut after: Option<Uuid> = None;
            let mut worked = false;
            loop {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                let tenants: Vec<Uuid> =
                    sqlx::query_scalar("SELECT tenant_id FROM mdm_assets.group_work_scopes($1)")
                        .bind(after)
                        .fetch_all(&self.groups.read_pool)
                        .await
                        .map_err(rss_runtime::ShutdownError::new)?;
                if tenants.is_empty() {
                    after = None;
                    if std::mem::take(&mut worked) {
                        continue;
                    }

                    tokio::select! { biased;
                        () = cancel.cancelled() => return Ok(()),
                        () = notify.notified() => {},
                        () = tokio::time::sleep(Duration::from_secs(5)) => {},
                    }
                    continue;
                }
                for tenant in tenants {
                    after = Some(tenant);
                    let tenant = TenantId::parse(&tenant.to_string())
                        .map_err(rss_runtime::ShutdownError::new)?;
                    let scope = Scope::new(tenant, "mdm.groups").expect("constant scope");
                    let stop = cancel.child_token();
                    let pass = GroupPass {
                        work: &self,
                        stop: &stop,
                    };
                    let report = rss_reconcile::run_with_notify(
                        &pass,
                        self.as_ref(),
                        &scope,
                        policy,
                        &control,
                        &stop,
                        &notify,
                        |event| {
                            self.groups.record_runner_failure(event);
                        },
                    )
                    .await
                    .map_err(rss_runtime::ShutdownError::new)?;
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
        })
    }
}

impl GroupWork {
    async fn inputs_pending<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<bool, ReconcileError> {
        self.groups
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.groups,
                |owner, tx| {
                    Box::pin(async move {
                        owner
                            .inputs_pending_in(tx)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(storage(e)),
                |e| Err(storage(e)),
                |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )
    }
    async fn apply_inputs<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        let candidate = self.capture(binding, control).await?;
        self.groups
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.groups, claim, &candidate),
                |(owner, claim, candidate), tx| {
                    Box::pin(async move {
                        owner.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        owner
                            .check_task_transaction(tx)
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        owner
                            .reconcile_messaging
                            .protect_in(tx, claim, (owner, *candidate), |(owner, candidate), tx| {
                                Box::pin(async move {
                                    owner
                                        .advance_inputs_in(binding, tx, candidate)
                                        .await
                                        .map(ProtectedStep::Ready)
                                        .map_err(|e| fault(e, &Mutex::new(None)))
                                })
                            })
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(storage(e)),
                |e| Err(storage(e)),
                |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )
    }
}

impl GroupWork {
    async fn set_input_failure<T: Timer>(
        &self,
        claim: &PgClaim,
        failed: bool,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        self.groups.runtime.local_tx_with_context(binding,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),
            (&self.groups,claim), |(owner,claim),tx|Box::pin(async move {
                owner.reconcile_messaging.protect_in(tx,claim,owner, |_owner,tx|Box::pin(async move {
                    let tenant=tx.tenant_id().to_string(); tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_assets.group_dispatch SET input_failed=$2 WHERE tenant_id=$1::uuid").bind(tenant).bind(failed).execute(c).await?; Ok(())})).await?;
                    Ok(ProtectedStep::Ready(()))
                })).await
            })).await.fold(Ok, |e|Err(storage(e)), |e|Err(storage(e)),
                |_|Err(ReconcileError::new(ErrorKind::RollbackFailed)), |_|Err(unknown()), |e|Err(storage(e)))
    }
}

impl GroupWork {
    async fn execution<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_transactional_messaging::fence::ExecutionBinding, ReconcileError>
    {
        control.check()?;
        let id = self.task(claim)?;
        let tenant = claim.target().scope().tenant();
        let epoch: i64 = sqlx::query_scalar("SELECT mdm_assets.group_work_epoch($1::uuid,$2)")
            .bind(tenant.to_string())
            .bind(id)
            .fetch_one(&self.groups.read_pool)
            .await
            .map_err(|e| storage(e.into()))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| ReconcileError::new(ErrorKind::Invariant))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.groups.storage,
            tenant,
            epoch,
        ))
    }
}
