//! Scope-only RSS reconciler. App owns the shared scheduler pool and shutdown.
use crate::*;
use rss_reconcile::{
    ActualState, Completion, Control, DesiredState, DurableStore, Error as ReconcileError,
    ErrorKind, ReconcileDiff, Reconciler, Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore};
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
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.tenant() != self.scopes.tenant || scope.reconciler() != "mdm.scopes" {
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
        self.scopes
            .runtime
            .local_tx_with_context(
                self.scopes.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim, reason),
                |(s, claim, reason), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        transaction::lock(tx)
                            .await
                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                        s.reconcile_messaging
                            .protect_in(tx, claim, (s, *reason), |(s, reason), tx| {
                                Box::pin(async move {
                                    let task = s
                                        .store
                                        .task_in(tx, id)
                                        .await
                                        .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                                    if *reason == "superseded" {
                                        s.store
                                            .phase_in(tx, id, "superseded")
                                            .await
                                            .map_err(|e| fault(e.into(), &Mutex::new(None)))?;
                                    }
                                    s.finish_in(tx, id, Some(reason))
                                        .await
                                        .map_err(|e| fault(e, &Mutex::new(None)))?;
                                    if *reason == "superseded" {
                                        match s.store.head_in(tx, task.scope, false).await {
                                            Ok(_) => {
                                                let new = s
                                                    .enqueue_in(tx, Uuid::new_v4(), task.scope)
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
    pub async fn reconcile_inputs(&self) -> std::result::Result<bool, ReconcileError> {
        self.scopes
            .runtime
            .local_tx_with_context(self.scopes.tenant, deadline(), &self.scopes, |s, tx| {
                Box::pin(async move {
                    s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                    transaction::lock(tx)
                        .await
                        .map_err(|e| fault(e, &Mutex::new(None)))?;
                    let result: transaction::Result<bool> = async {
                        let mut progressed = false;
                        if let Some(page) = s.store.group_change_page_in(tx).await? {
                            for id in &page.scopes {
                                s.enqueue_in(tx, Uuid::new_v4(), *id).await?;
                            }
                            s.store.complete_group_change_page_in(tx, &page).await?;
                            progressed = true;
                        }
                        if let Some(page) = s.store.asset_page_in(tx).await? {
                            for id in &page.scopes {
                                s.enqueue_in(tx, Uuid::new_v4(), *id).await?;
                            }
                            s.store.complete_asset_page_in(tx, &page).await?;
                            progressed = true;
                        }
                        Ok(progressed)
                    }
                    .await;
                    result.map_err(|e| fault(e, &Mutex::new(None)))
                })
            })
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
    ) -> std::result::Result<ReconcileDiff<bool>, ReconcileError> {
        control.check()?;
        let id = self.task(claim)?;
        let pending = self
            .scopes
            .runtime
            .local_tx_with_context(
                self.scopes.tenant,
                deadline(),
                &self.scopes,
                |scopes, tx| {
                    Box::pin(async move {
                        scopes
                            .store
                            .task_in(tx, id)
                            .await
                            .map(|t| !t.completed)
                            .map_err(|e| fault(e.into(), &Mutex::new(None)))
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
            .scopes
            .runtime
            .local_tx_with_context(
                self.scopes.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.scopes, claim, &failure),
                |(s, claim, failure), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        transaction::lock(tx).await.map_err(|e| fault(e, failure))?;
                        s.reconcile_messaging
                            .protect_in(tx, claim, (s, failure), |(s, failure), tx| {
                                Box::pin(async move {
                                    s.advance_in(tx, id).await.map_err(|e| fault(e, failure))
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
            Some(Error::NotFound) => "source_unavailable",
            Some(Error::Forbidden | Error::Unauthorized) => "permission_denied",
            Some(Error::Unavailable(Failure::Capacity)) => "capacity_exceeded",
            Some(Error::CommitUnknown | Error::RollbackFailed) => return Err(unknown()),
            Some(_) => return Err(ReconcileError::new(ErrorKind::Transient)),
        };
        self.reject(claim, id, reason, control).await
    }
}

impl DurableStore for ScopeWork {
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
        let result = self.schedule.claim_due(scope, limit, lease, control).await;
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
        if matches!(completion, Completion::Suspended { .. }) {
            self.reject(claim, id, "automation_suspended", &settlement)
                .await?;
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
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-scope-calculation", Duration::from_secs(8));
        let _ = self.scopes.task.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(clippy::disallowed_methods, reason="monotonic execution clock boundary")]
            let timer=ScopeTimer(tokio::time::Instant::now());
            let control=Control::new(&timer,Duration::MAX,&cancel);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:2,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=Scope::new(self.scopes.tenant,"mdm.scopes").expect("constant scope");
            let runner=async {             rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&scope,policy,&control,&notify,|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_scope_task_failure","diagnostic":format!("{event:?}")}));
                self.scopes.record_runner_failure(event);

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
                        Ok(true)=>{self.scopes.input_state.store(1,std::sync::atomic::Ordering::Release);continue;},
                        Ok(false)=>{self.scopes.input_state.store(1,std::sync::atomic::Ordering::Release);},
                        Err(error)=>{self.scopes.input_state.store(2,std::sync::atomic::Ordering::Release);eprintln!("{}",serde_json::json!({"event":"mdm_scope_input_failure","diagnostic":format!("{error:?}")}));},
                    }
                    tokio::select! { ()=cancel.cancelled()=>return Ok(()), ()=tokio::time::sleep(Duration::from_secs(5))=>{} }
                }
            };
            tokio::try_join!(runner,ingress).map(|_|())
        })
    }
}
