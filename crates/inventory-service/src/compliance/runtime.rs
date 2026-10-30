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
    pub fn new(compliance: Arc<Compliance>, schedule: PgStore) -> Self {
        Self {
            compliance,
            schedule,
        }
    }
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.tenant() != self.compliance.tenant || scope.reconciler() != "mdm.compliance" {
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
        self.compliance
            .runtime
            .local_tx_with_context(
                self.compliance.tenant,
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
                                            .finish_task_in(tx, id, Some(reason))
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
        control.check()?;
        let Some(id) = self.task(claim)? else {
            let pending = self.inputs_pending(control).await?;
            return Ok(ReconcileStep::Ready(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(pending),
            )));
        };
        let pending = self
            .compliance
            .runtime
            .local_tx_with_context(
                self.compliance.tenant,
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
        control.check()?;
        let Some(id) = self.task(claim)? else {
            return self.apply_inputs(claim, control).await;
        };
        let failure = Mutex::new(None);
        let attempt = self
            .compliance
            .runtime
            .local_tx_with_context(
                self.compliance.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim, &failure),
                |(compliance, claim, failure), tx| {
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
                                (compliance, *failure),
                                |(compliance, failure), tx| {
                                    Box::pin(async move {
                                        let result: Result<()> = async {
                                            let state = compliance.read_task_in(tx, id).await?;
                                            if state.completed {
                                                return Ok(());
                                            }
                                            compliance
                                                .task_cursor_in(tx, id, state.cursor.clone())
                                                .await?;
                                            compliance
                                                .advance(tx, id, &state.input, state.cursor)
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
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<ClaimBatch<PgClaim>, ReconcileError> {
        self.check(scope)?;
        let result = self.schedule.claim_due(scope, limit, lease, control).await;

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
        let scheduled = if id.is_none() && completion == Completion::Converged {
            Completion::Reobserve(Duration::from_secs(5))
        } else {
            completion
        };
        let result = self.schedule.finish(claim, scheduled, &settlement).await;
        if id.is_none() && (result.is_err() || !matches!(completion, Completion::Deferred(_))) {
            let healthy = result.is_ok()
                && matches!(completion, Completion::Converged | Completion::Reobserve(_));
            self.compliance.input_state.store(
                if healthy { 1 } else { 2 },
                std::sync::atomic::Ordering::Release,
            );
        }
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
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-compliance-evaluation", Duration::from_secs(20));
        let _ = self.compliance.task_status.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(clippy::disallowed_methods, reason="monotonic execution clock boundary")]
            let timer=ComplianceTimer(tokio::time::Instant::now());
            let force = tokio_util::sync::CancellationToken::new();
            let control=Control::new(&timer,Duration::MAX,&force);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:CONCURRENCY,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=Scope::new(self.compliance.tenant,"mdm.compliance").expect("constant scope");
            self.schedule.wake(&Target::new(scope.clone(), "inputs").expect("input target"), &rss_reconcile::ResourceSet::empty(scope.tenant()), &control.child(Duration::from_secs(6))).await.map_err(rss_runtime::ShutdownError::new)?;
                         rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&scope,policy,&control,&cancel,&notify,|event| {
                if !matches!(event, rss_reconcile::Observation::Deferred { .. }) {
                    eprintln!("{}",serde_json::json!({"event":"mdm_compliance_task_failure","diagnostic":format!("{event:?}")}));
                }
                self.compliance.worker_health.lock().expect("worker observation").failure(event,self.compliance.clock.unix_seconds());

            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)
        })
    }
}

impl ComplianceWork {
    async fn inputs_pending<T: Timer>(
        &self,
        control: &Control<'_, T>,
    ) -> std::result::Result<bool, ReconcileError> {
        self.compliance
            .runtime
            .local_tx_with_context(
                self.compliance.tenant,
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
        self.compliance
            .runtime
            .local_tx_with_context(
                self.compliance.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.compliance, claim),
                |(owner, claim), tx| {
                    Box::pin(async move {
                        owner.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        crate::transaction::lock(tx)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        owner
                            .reconcile_messaging
                            .protect_in(tx, claim, owner, |owner, tx| {
                                Box::pin(async move {
                                    owner
                                        .advance_inputs_in(tx)
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
