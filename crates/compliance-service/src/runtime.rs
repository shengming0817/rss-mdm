//! Compliance-only durable execution; the host owns the shared scheduler pool.
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

pub struct ComplianceWork {
    compliance: Arc<Compliance>,
    schedule: PgStore,
}
impl ComplianceWork {
    async fn capture<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_mdm_inventory::AssetCut, ReconcileError> {
        control.check()?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
        rss_mdm_inventory_service::assets::cut::capture(
            &self.compliance.audit_store,
            binding.tenant(),
            &budget,
        )
        .await
        .map_err(|e| storage(fault(e.into(), &Mutex::new(None))))
    }

    pub fn new(compliance: Arc<Compliance>, schedule: PgStore) -> Self {
        Self {
            compliance,
            schedule,
        }
    }
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.reconciler() != "mdm.compliance" {
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
        self.compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim, reason),
                |(compliance, claim, reason), tx| {
                    Box::pin(async move {
                        compliance
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        compliance
                            .reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (compliance, *reason),
                                |(compliance, reason), tx| {
                                    Box::pin(async move {
                                        compliance
                                            .finish_task_in(binding, tx, id, Some(reason))
                                            .await
                                            .map_err(|e| fault(e, &Mutex::new(None)))?;
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
            sqlx::Error::Protocol("compliance task rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => error.into(),
    }
}
impl Reconciler<PgClaim> for ComplianceWork {
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
            .compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.compliance,
                |compliance, tx| {
                    Box::pin(async move {
                        compliance
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
        let attempt = self
            .compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim, &failure, &candidate),
                |(compliance, claim, failure, candidate), tx| {
                    Box::pin(async move {
                        compliance
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        compliance
                            .reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (compliance, *failure, *candidate),
                                |(compliance, failure, candidate), tx| {
                                    Box::pin(async move {
                                        let result: Result<()> = async {
                                            let state = compliance.read_task_in(tx, id).await?;
                                            if state.completed {
                                                return Ok(());
                                            }
                                            compliance.task_cursor_in(tx, id, state.cursor).await?;
                                            compliance
                                                .advance(
                                                    binding,
                                                    tx,
                                                    id,
                                                    &state.input,
                                                    state.cursor,
                                                    candidate,
                                                )
                                                .await
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
            Err(Error::NotFound) => "source_unavailable",
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
impl DurableStore for ComplianceWork {
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

        self.compliance
            .worker_health
            .lock()
            .expect("worker observation")
            .scan(
                result.as_ref().err().map(|e| e.kind()),
                self.compliance.clock.unix_seconds(),
            );
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
            self.compliance
                .worker_health
                .lock()
                .expect("worker observation")
                .settled(claim.target(), completion);
        }

        result
    }
}

struct ComplianceTimer(tokio::time::Instant);
impl Timer for ComplianceTimer {
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
impl ComplianceWork {
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-compliance-evaluation", drain);
        let _ = self.compliance.task_status.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(
                clippy::disallowed_methods,
                reason = "monotonic execution clock boundary"
            )]
            let timer = ComplianceTimer(tokio::time::Instant::now());
            let force = tokio_util::sync::CancellationToken::new();
            let control = Control::new(&timer, Duration::MAX, &force);
            let mut after: Option<Uuid> = None;
            loop {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                let tenants: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT tenant_id FROM mdm_compliance.compliance_work_scopes($1)",
                )
                .bind(after)
                .fetch_all(&self.compliance.read_pool)
                .await
                .map_err(rss_runtime::ShutdownError::new)?;
                if tenants.is_empty() {
                    after = None;
                    tokio::select! { biased;
                        () = cancel.cancelled() => return Ok(()),
                        () = notify.notified() => {},
                        () = tokio::time::sleep(Duration::from_secs(5)) => {},
                    }
                    continue;
                }
                for tenant in tenants {
                    after = Some(tenant);
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(rss_runtime::ShutdownError::new)?;
                    let scope = Scope::new(tenant, "mdm.compliance").expect("constant scope");
                    let stop = cancel.child_token();
                    let pass = Pass {
                        work: &self,
                        stop: &stop,
                    };
                    rss_reconcile::run_with_notify(
                        &pass,
                        self.as_ref(),
                        &scope,
                        policy,
                        &control,
                        &stop,
                        &notify,
                        |event| {
                            self.compliance
                                .worker_health
                                .lock()
                                .expect("worker observation")
                                .failure(event, self.compliance.clock.unix_seconds());
                        },
                    )
                    .await
                    .map_err(rss_runtime::ShutdownError::new)?;
                }
            }
        })
    }
}

impl ComplianceWork {
    async fn inputs_pending<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<bool, ReconcileError> {
        self.compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.compliance,
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
        self.compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim, &candidate),
                |(owner, claim, candidate), tx| {
                    Box::pin(async move {
                        owner.audit_store.bind_in(tx).await.map_err(PgError::from)?;
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

impl ComplianceWork {
    async fn set_input_failure<T: Timer>(
        &self,
        claim: &PgClaim,
        failed: bool,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        self.compliance
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim),
                |(owner, claim), tx| {
                    Box::pin(async move {
                        owner
                            .reconcile_messaging
                            .protect_in(tx, claim, owner, |_owner, tx| {
                                Box::pin(async move {
                                    let tenant = tx.tenant_id();
                                    tx.with_connection(move |c| {
                                        Box::pin(async move {
                                            pg::tasks::set_input_failed(c, tenant, failed).await
                                        })
                                    })
                                    .await?;
                                    Ok(ProtectedStep::Ready(()))
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

struct Pass<'a> {
    work: &'a ComplianceWork,
    stop: &'a tokio_util::sync::CancellationToken,
}
impl DurableStore for Pass<'_> {
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

impl ComplianceWork {
    async fn execution<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_transactional_messaging::fence::ExecutionBinding, ReconcileError>
    {
        control.check()?;
        let id = self.task(claim)?;
        let tenant = claim.target().scope().tenant();
        let epoch: i64 =
            sqlx::query_scalar("SELECT mdm_compliance.compliance_work_epoch($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(id)
                .fetch_one(&self.compliance.read_pool)
                .await
                .map_err(|e| storage(e.into()))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| ReconcileError::new(ErrorKind::Invariant))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.compliance.storage,
            tenant,
            epoch,
        ))
    }
}
