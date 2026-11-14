//! Scope-only RSS reconciler. App owns the shared scheduler pool and shutdown.
/// Maximum concurrent transactions scheduled by this owner worker.
pub const CONCURRENCY: usize = 2;
use crate::*;
use rss_reconcile::{
    ActualState, ClaimBatch, Completion, Control, DesiredState, DurableStore,
    Error as ReconcileError, ErrorKind, ReconcileDiff, ReconcileStep, Reconciler, ResourceSet,
    Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore, ProtectedStep};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
pub struct ScopeWork {
    pub scopes: Arc<Scopes>,
    schedule: PgStore,
}
impl ScopeWork {
    pub fn new(scopes: Arc<Scopes>, schedule: PgStore) -> Self {
        Self { scopes, schedule }
    }
    async fn capture<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_mdm_inventory::AssetCut, ReconcileError> {
        control.check()?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
        rss_mdm_inventory_service::assets::cut::capture(
            &self.scopes.audit_store,
            binding.tenant(),
            &budget,
        )
        .await
        .map_err(|_| storage(sqlx::Error::Protocol("asset input capture failed".into()).into()))
    }
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.reconciler() != crate::tasks::domain(self.scopes.profile()) {
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
        self.scopes
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim, reason),
                |(s, claim, reason), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        let task = s
                            .store
                            .task_in(tx, id)
                            .await
                            .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                        match s.store.head_in(tx, task.scope, true).await {
                            Ok(_) | Err(rss_mdm_scope_postgres::BindingError::Missing) => {}
                            Err(e) => return Err(fault(e.into(), &Mutex::new(None))),
                        }

                        s.reconcile_messaging
                            .protect_in(tx, claim, (s, *reason), |(s, reason), tx| {
                                Box::pin(async move {
                                    let task = s
                                        .store
                                        .task_in(tx, id)
                                        .await
                                        .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                                    if task.completed {
                                        return Ok(ProtectedStep::Ready(()));
                                    }
                                    if *reason == "superseded" {
                                        s.store
                                            .phase_in(tx, id, "superseded")
                                            .await
                                            .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                                    }
                                    s.finish_in(binding, tx, id, Some(reason))
                                        .await
                                        .map_err(|e| fault(e, &Mutex::new(None)))?;
                                    if *reason == "superseded" {
                                        match s.store.head_in(tx, task.scope, true).await {
                                            Ok(_) => {
                                                let new = s
                                                    .enqueue_in(
                                                        binding,
                                                        tx,
                                                        Uuid::new_v4(),
                                                        task.scope,
                                                    )
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)))?;
                                                s.store
                                                    .replace_task_in(tx, id, new)
                                                    .await
                                                    .map_err(|e| {
                                                        fault(e.into(), &Mutex::new(None))
                                                    })?;
                                            }
                                            Err(rss_mdm_scope_postgres::BindingError::Missing) => {}
                                            Err(e) => {
                                                return Err(fault(e.into(), &Mutex::new(None)));
                                            }
                                        }
                                    }
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
fn unknown() -> ReconcileError {
    ReconcileError::new(ErrorKind::CommitUnknown)
}
fn storage(e: PgError) -> ReconcileError {
    ReconcileError::new(
        if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            ErrorKind::Fenced
        } else {
            ErrorKind::Transient
        },
    )
}
fn fault(e: transaction::Fault, slot: &Mutex<Option<Error>>) -> PgError {
    match e {
        transaction::Fault::Request(e) => {
            *slot.lock().expect("failure slot") = Some(e);
            sqlx::Error::Protocol("Scope operation rejected".into()).into()
        }
        transaction::Fault::Storage(e) => e,
        transaction::Fault::Sql(e) => e.into(),
    }
}
impl Reconciler<PgClaim> for ScopeWork {
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
            .scopes
            .runtime
            .local_tx_with_context(binding, deadline(), &self.scopes, |scopes, tx| {
                Box::pin(async move {
                    scopes
                        .store
                        .task_in(tx, id)
                        .await
                        .map(|t| !t.completed)
                        .map_err(|e| fault(e.into(), &Mutex::new(None)))
                })
            })
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
            .scopes
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim, &failure, &candidate),
                |(s, claim, failure, candidate), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        let task = s
                            .store
                            .task_in(tx, id)
                            .await
                            .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                        match s.store.head_in(tx, task.scope, true).await {
                            Ok(_) | Err(rss_mdm_scope_postgres::BindingError::Missing) => {}
                            Err(e) => return Err(fault(e.into(), &Mutex::new(None))),
                        }

                        s.reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (s, failure, *candidate),
                                |(s, failure, candidate), tx| {
                                    Box::pin(async move {
                                        s.advance_in(binding, tx, id, candidate)
                                            .await
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
            Err(Error::NotFound) => "source_unavailable",
            Err(Error::Forbidden | Error::Unauthorized) => "permission_denied",
            Err(Error::Unavailable(Failure::Capacity)) => "capacity_exceeded",
            Err(Error::CommitUnknown) => return Err(unknown()),
            Err(Error::RollbackFailed) => {
                return Err(ReconcileError::new(ErrorKind::RollbackFailed));
            }
            Err(_) => return Err(ReconcileError::new(ErrorKind::Transient)),
        };
        self.reject(claim, id, reason, control).await
    }
}

impl DurableStore for ScopeWork {
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
        self.scopes
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
            self.scopes.record_settled(claim.target(), completion);
        }
        result
    }
}

struct ScopeTimer(tokio::time::Instant);
impl Timer for ScopeTimer {
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
impl ScopeWork {
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-scope-calculation", drain);
        let _ = self.scopes.task.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(
                clippy::disallowed_methods,
                reason = "monotonic execution clock boundary"
            )]
            let timer = ScopeTimer(tokio::time::Instant::now());
            let force = tokio_util::sync::CancellationToken::new();
            let control = Control::new(&timer, Duration::MAX, &force);
            let mut after: Option<Uuid> = None;
            loop {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                let tenants: Vec<Uuid> = sqlx::query_scalar(match self.scopes.profile() {
                    rss_mdm_install_support::StorageProfile::Mdm => {
                        "SELECT tenant_id FROM mdm_scope.scope_work_scopes($1)"
                    }
                    rss_mdm_install_support::StorageProfile::Da => {
                        "SELECT tenant_id FROM rss_da.scope_work_scopes($1)"
                    }
                })
                .bind(after)
                .fetch_all(&self.scopes.read_pool)
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
                    let scope = Scope::new(tenant, crate::tasks::domain(self.scopes.profile()))
                        .expect("constant scope");
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
                            self.scopes.record_runner_failure(event);
                        },
                    )
                    .await
                    .map_err(rss_runtime::ShutdownError::new)?;
                }
            }
        })
    }
}

impl ScopeWork {
    async fn inputs_pending<T: Timer>(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        control: &Control<'_, T>,
    ) -> std::result::Result<bool, ReconcileError> {
        self.scopes
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.scopes,
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
        self.scopes
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim, &candidate),
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

impl Scopes {
    async fn relation_revision_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    ) -> transaction::Result<i64> {
        let objects = self.objects.clone();
        let tenant = tx.tenant_id();
        let revision = tx
            .with_connection(move |c| Box::pin(async move { objects.change_head(c, tenant).await }))
            .await?;
        Ok(revision)
    }
    async fn inputs_pending_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    ) -> transaction::Result<bool> {
        let revision = self.relation_revision_in(tx).await?;
        Ok(self.store.inputs_pending_in(tx, revision).await?)
    }
    async fn advance_inputs_in(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> transaction::Result<()> {
        if let Some(page) = self.store.group_change_page_in(tx).await? {
            for id in &page.scopes {
                self.enqueue_in(binding, tx, Uuid::new_v4(), *id).await?;
            }
            self.store.complete_group_change_page_in(tx, &page).await?;
        }
        if let Some(page) = self.store.asset_page_in(tx, candidate).await? {
            for id in &page.scopes {
                self.enqueue_in(binding, tx, Uuid::new_v4(), *id).await?;
            }
            self.store.complete_asset_page_in(tx, &page).await?;
        }
        let revision = self.relation_revision_in(tx).await?;
        if let Some(window) = self.store.relation_window_in(tx, revision).await? {
            let reader = self.objects.clone();
            let tenant = tx.tenant_id();
            let after = window.position;
            let through = window.watermark;
            let changes = tx
                .with_connection(move |c| {
                    Box::pin(async move { reader.changes(c, tenant, after, through, 64).await })
                })
                .await?;
            let position = changes.last().map_or(through, |c| c.position);
            let more_changes = changes.len() == 64 && position < through;
            let devices = changes
                .into_iter()
                .filter(|c| {
                    c.kind == rss_mdm_inventory_service::objects::ObjectChangeKind::IdentityChanged
                })
                .flat_map(|c| c.old_devices.into_iter().chain(c.new_devices))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let scopes = self.store.relation_targets_in(tx, &window, devices).await?;
            for id in scopes.iter().take(32) {
                self.enqueue_in(binding, tx, Uuid::new_v4(), *id).await?;
            }
            self.store
                .complete_relation_page_in(tx, &window, position, more_changes, &scopes)
                .await?;
        }
        Ok(())
    }
}

impl ScopeWork {
    async fn set_input_failure<T: Timer>(
        &self,
        claim: &PgClaim,
        failed: bool,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, ReconcileError> {
        let binding = self.execution(claim, control).await?;
        self.scopes
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim),
                |(owner, claim), tx| {
                    Box::pin(async move {
                        owner
                            .reconcile_messaging
                            .protect_in(tx, claim, owner, |owner, tx| {
                                Box::pin(async move {
                                    owner
                                        .store
                                        .set_input_failed_in(tx, failed)
                                        .await
                                        .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
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
    work: &'a ScopeWork,
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

impl ScopeWork {
    async fn execution<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<rss_transactional_messaging::fence::ExecutionBinding, ReconcileError>
    {
        control.check()?;
        let id = self.task(claim)?;
        let tenant = claim.target().scope().tenant();
        let epoch: i64 = sqlx::query_scalar(match self.scopes.profile() {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT mdm_scope.scope_work_epoch($1::uuid,$2)"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT rss_da.scope_work_epoch($1::uuid,$2)"
            }
        })
        .bind(tenant.to_string())
        .bind(id)
        .fetch_one(&self.scopes.read_pool)
        .await
        .map_err(|e| storage(e.into()))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| ReconcileError::new(ErrorKind::Invariant))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.scopes.storage,
            tenant,
            epoch,
        ))
    }
}
