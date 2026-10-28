//! Query-only durable execution; the host owns the shared scheduler pool.
use super::*;
use rss_reconcile::{
    ActualState, Completion, Control, DesiredState, DurableStore, Error as ReconcileError,
    ErrorKind, ReconcileDiff, Reconciler, Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore};
use rss_transactional_messaging_postgres::PgError;
use std::{sync::Mutex, time::Duration};

pub struct QueryWork {
    assets: Arc<AssetService>,
    schedule: PgStore,
}
impl QueryWork {
    pub fn new(assets: Arc<AssetService>, schedule: PgStore) -> Self {
        Self { assets, schedule }
    }
    fn check(&self, scope: &Scope) -> std::result::Result<(), ReconcileError> {
        if scope.tenant() != self.assets.tenant || scope.reconciler() != "mdm.asset-queries" {
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
        self.assets
            .runtime
            .local_tx_with_context(
                self.assets.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.assets, claim, reason),
                |(assets, claim, reason), tx| {
                    Box::pin(async move {
                        assets
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        assets
                            .reconcile_messaging
                            .protect_in(tx, claim, (assets, *reason), |(assets, reason), tx| {
                                Box::pin(async move {
                                    assets
                                        .finish_query_in(tx, id, Some(reason))
                                        .await
                                        .map_err(|e| fault(e, &Mutex::new(None)))?;
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
            sqlx::Error::Protocol("query task rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => error.into(),
    }
}
impl Reconciler<PgClaim> for QueryWork {
    type State = bool;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> std::result::Result<ReconcileDiff<bool>, ReconcileError> {
        control.check()?;
        let id = self.task(claim)?;
        let pending = self
            .assets
            .runtime
            .local_tx_with_context(
                self.assets.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                &self.assets,
                |assets, tx| {
                    Box::pin(async move {
                        assets
                            .query_task_in(tx, id)
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
            .assets
            .runtime
            .local_tx_with_context(
                self.assets.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.assets, claim, &failure),
                |(assets, claim, failure), tx| {
                    Box::pin(async move {
                        assets
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        assets
                            .reconcile_messaging
                            .protect_in(tx, claim, (assets, *failure), |(assets, failure), tx| {
                                Box::pin(async move {
                                    let result: Result<()> = async {
                                        let state = assets.query_task_in(tx, id).await?;
                                        if state.completed {
                                            return Ok(());
                                        }
                                        assets
                                            .query_cursor_in(tx, id, state.cursor.clone())
                                            .await?;
                                        assets
                                            .advance_asset_query_in(
                                                tx,
                                                id,
                                                &state.input,
                                                state.cursor,
                                            )
                                            .await
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
impl DurableStore for QueryWork {
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

        self.assets
            .worker_health
            .lock()
            .expect("worker observation")
            .scan(result.is_err());
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
            self.assets
                .worker_health
                .lock()
                .expect("worker observation")
                .settled(claim.target(), completion);
        }

        result
    }
}

struct QueryTimer(tokio::time::Instant);
impl Timer for QueryTimer {
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
impl QueryWork {
    pub fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-query-calculation", Duration::from_secs(8));
        let _ = self.assets.task_status.set(status);
        task.into_registration(move |cancel| async move {
            #[allow(clippy::disallowed_methods, reason="monotonic execution clock boundary")]
            let timer=QueryTimer(tokio::time::Instant::now());
            let control=Control::new(&timer,Duration::MAX,&cancel);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:2,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(5),
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=Scope::new(self.assets.tenant,"mdm.asset-queries").expect("constant scope");
            let runner=async {             rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&scope,policy,&control,&notify,|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_query_task_failure","diagnostic":format!("{event:?}")}));
                self.assets.worker_health.lock().expect("worker observation").failure(event);

            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new) };
            runner.await
        })
    }
}
