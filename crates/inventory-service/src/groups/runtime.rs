//! Group-only durable execution; the host owns the shared scheduler pool.
use super::*;
use rss_reconcile::{
    ActualState, Completion, Control, DesiredState, DurableStore, Error as ReconcileError,
    ErrorKind, ReconcileDiff, Reconciler, Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore};
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
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.tenant() != self.groups.tenant || scope.reconciler() != "mdm.groups" {
            return Err(ReconcileError::new(ErrorKind::Invariant));
        }
        Ok(())
    }
    fn task(&self, claim: &PgClaim) -> std::result::Result<Uuid, ReconcileError> {
        self.check(claim.target().scope())?;
        claim
            .target()
            .entity()
            .strip_prefix("task:")
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| ReconcileError::new(ErrorKind::Invariant))
    }
    async fn reject<T: Timer>(
        &self,
        claim: &PgClaim,
        id: Uuid,
        reason: &str,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.groups
            .runtime
            .local_tx_with_context(
                self.groups.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.groups, claim, reason),
                |(groups, claim, reason), tx| {
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
                            .partition(&state.input.target().to_string())?])
                            .await?;
                        groups
                            .lock_business_in(tx)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        groups
                            .reconcile_messaging
                            .protect_in(tx, claim, (groups, *reason), |(groups, reason), tx| {
                                Box::pin(async move {
                                    groups
                                        .finish_task_in(tx, id, Some(reason))
                                        .await
                                        .map_err(|e| fault(e, &Mutex::new(None)))?;
                                    if *reason == "superseded" {
                                        groups
                                            .retry_superseded_group_in(tx, id)
                                            .await
                                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                                    }
                                    Ok(())
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
                |_| Err(unknown()),
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
    ) -> std::result::Result<ReconcileDiff<bool>, ReconcileError> {
        control.check()?;
        let id = self.task(claim)?;
        let pending = self
            .groups
            .runtime
            .local_tx_with_context(
                self.groups.tenant,
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
                |_| Err(unknown()),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )?;
        Ok(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<bool>,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        control.check()?;
        let id = self.task(claim)?;
        let failure = Mutex::new(None);
        let attempt = self
            .groups
            .runtime
            .local_tx_with_context(
                self.groups.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.groups, claim, &failure),
                |(groups, claim, failure), tx| {
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
                            .partition(&state.input.target().to_string())?])
                            .await?;
                        groups
                            .authorize_task_in(tx, id, &state.input)
                            .await
                            .map_err(|e| fault(e, failure))?;
                        groups
                            .lock_business_in(tx)
                            .await
                            .map_err(|e| fault(e, failure))?;
                        groups
                            .reconcile_messaging
                            .protect_in(tx, claim, (groups, *failure), |(groups, failure), tx| {
                                Box::pin(async move {
                                    let result: Result<()> = async {
                                        let state = groups.read_task_in(tx, id).await?;
                                        if state.completed {
                                            return Ok(());
                                        }
                                        match state.input {
                                            tasks::TaskInput::Definition { ref edit } => {
                                                groups
                                                    .advance_group_definition_in(
                                                        tx,
                                                        id,
                                                        edit,
                                                        state.cursor,
                                                    )
                                                    .await
                                            }
                                            ref input @ tasks::TaskInput::Calculation { .. } => {
                                                groups
                                                    .advance_group_job_in(
                                                        tx,
                                                        id,
                                                        input,
                                                        state.cursor,
                                                    )
                                                    .await
                                            }
                                        }
                                    }
                                    .await;
                                    result.map_err(|e| fault(e, failure))
                                })
                            })
                            .await
                    })
                },
            )
            .await;
        let rejection = attempt.fold(
            |_| Ok(None),
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
                    .map(Some)
                    .ok_or_else(|| storage(e))
            },
            |_| Err(unknown()),
            |_| Err(unknown()),
            |e| Err(storage(e)),
        )?;
        let reason = match rejection {
            None => return Ok(()),
            Some(Error::Conflict) => "superseded",
            Some(Error::Malformed) => "invalid_input",
            Some(Error::Forbidden | Error::Unauthorized) => "permission_denied",
            Some(Error::Group(_) | Error::NotFound) => "source_unavailable",
            Some(Error::Unavailable(
                Failure::AssetBytesLimit | Failure::AssetObjectLimit | Failure::AssetSourceLimit,
            )) => "capacity_exceeded",
            Some(Error::CommitUnknown | Error::RollbackFailed) => return Err(unknown()),
            Some(_) => return Err(ReconcileError::new(ErrorKind::Transient)),
        };
        self.reject(claim, id, reason, control).await
    }
}
impl DurableStore for GroupWork {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        control: &Control<'_, T>,
    ) -> std::result::Result<(), ReconcileError> {
        self.check(target.scope())?;
        self.schedule.wake(target, control).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> std::result::Result<Vec<PgClaim>, ReconcileError> {
        self.check(scope)?;
        self.schedule.claim_due(scope, limit, lease, control).await
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
        if matches!(completion, Completion::Suspended { .. }) {
            self.reject(claim, id, "automation_suspended", &settlement)
                .await?;
        }
        self.schedule.finish(claim, completion, &settlement).await
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
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-group-calculation", Duration::from_secs(8));
        let _ = self.groups.task_status.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(clippy::disallowed_methods, reason="monotonic execution clock boundary")]
            let timer=GroupTimer(tokio::time::Instant::now());
            let control=Control::new(&timer,Duration::MAX,&cancel);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:2,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=Scope::new(self.groups.tenant,"mdm.groups").expect("constant scope");
            let runner=async {             rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&scope,policy,&control,&notify,|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_group_task_failure","diagnostic":format!("{event:?}")}));
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new) };
            let ingress=async {
                loop {
                    if cancel.is_cancelled() {return Ok::<_,rss_runtime::ShutdownError>(());}
                    let result = tokio::select! {
                        () = cancel.cancelled() => return Ok(()),
                        result = tokio::time::timeout(Duration::from_secs(6), self.reconcile_inputs()) => result.unwrap_or_else(|_| Err(unknown())),
                    };
                    // Cancellation or timeout makes no rollback claim. Durable checkpoints
                    // and the work they cover share a transaction and are read on the next pass.
                    match result {
                        Ok(true)=>{self.groups.input_state.store(1,std::sync::atomic::Ordering::Release);continue;},
                        Ok(false)=>{self.groups.input_state.store(1,std::sync::atomic::Ordering::Release);},
                        Err(error)=>{self.groups.input_state.store(2,std::sync::atomic::Ordering::Release);eprintln!("{}",serde_json::json!({"event":"mdm_group_input_failure","diagnostic":format!("{error:?}")}));},
                    }
                    tokio::select! { ()=cancel.cancelled()=>return Ok(()), ()=tokio::time::sleep(Duration::from_secs(5))=>{} }
                }
            };
            tokio::try_join!(runner,ingress).map(|_|())
        })
    }
}

impl GroupWork {
    pub async fn reconcile_inputs(&self) -> std::result::Result<bool, ReconcileError> {
        let relation_progress = self
            .groups
            .forward_relation_changes()
            .await
            .map_err(|_| ReconcileError::new(ErrorKind::Transient))?;
        let progressed = self
            .groups
            .runtime
            .local_tx_with_context(
                self.groups.tenant,
                deadline(),
                &self.groups,
                |groups, tx| {
                    Box::pin(async move {
                        groups
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        groups
                            .lock_business_in(tx)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        groups
                            .dispatch_inputs_in(tx)
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
                |_| Err(unknown()),
                |_| Err(unknown()),
                |e| Err(storage(e)),
            )?;
        Ok(progressed || relation_progress > 0)
    }
}
