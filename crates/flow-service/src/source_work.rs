//! The remaining Execution source-change bridge. App owns the shared scheduler resource.
use crate::{
    Error, Failure,
    transaction::{Fault, deadline},
};
use rss_reconcile::{
    ActualState, Completion, Control, DesiredState, DurableStore, Error as RError, ErrorKind,
    ReconcileDiff, Reconciler, Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgStore};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub struct SourceChanges {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub source: Arc<dyn rss_mdm_execution_service::source_authority::SourceAuthority>,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub(crate) automation_task: std::sync::OnceLock<rss_runtime::TaskStatus>,
    pub(crate) automation_observation: std::sync::Mutex<health::AutomationObservation>,
}
impl SourceChanges {
    pub fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
        source: Arc<dyn rss_mdm_execution_service::source_authority::SourceAuthority>,
        clock: Arc<dyn crate::clock::Clock>,
    ) -> Self {
        Self {
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            source,
            clock,
            automation_task: Default::default(),
            automation_observation: Default::default(),
        }
    }
    pub fn automation_state(&self) -> Option<rss_runtime::TaskState> {
        self.automation_task
            .get()
            .map(rss_runtime::TaskStatus::current)
    }
}
fn target(tenant: TenantId) -> Target {
    Target::new(
        Scope::new(tenant, "mdm.assets").expect("constant domain"),
        "changes",
    )
    .expect("constant entity")
}
pub struct SourceChangesWork {
    pub service: Arc<SourceChanges>,
    store: PgStore,
}
fn storage(e: PgError) -> RError {
    RError::new(
        if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            ErrorKind::Fenced
        } else {
            ErrorKind::Transient
        },
    )
}
fn fault(e: Fault) -> PgError {
    match e {
        Fault::Storage(e) => e,
        Fault::Sql(e) => e.into(),
        Fault::Request(_) => sqlx::Error::Protocol("source change rejected".into()).into(),
    }
}
impl SourceChangesWork {
    pub fn new(service: Arc<SourceChanges>, store: PgStore) -> Arc<Self> {
        Arc::new(Self { service, store })
    }
    fn check(&self, scope: &Scope) -> Result<(), RError> {
        if scope.tenant() != self.service.tenant || scope.reconciler() != "mdm.assets" {
            Err(RError::new(ErrorKind::Invariant))
        } else {
            Ok(())
        }
    }
    fn check_claim(&self, claim: &PgClaim) -> Result<(), RError> {
        self.check(claim.target().scope())?;
        if claim.target().entity() != "changes" {
            return Err(RError::new(ErrorKind::Invariant));
        }
        Ok(())
    }
    pub async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<ReconcileDiff<bool>, RError> {
        self.check_claim(claim)?;
        control.check()?;
        let pending = self
            .service
            .runtime
            .local_tx(self.service.tenant, deadline(), |tx| {
                Box::pin(async move {
                    rss_mdm_execution_service::source_changes::pending_in(tx)
                        .await
                        .map_err(|e| fault(e.into()))
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(storage(e)),
                |e| Err(storage(e)),
                |_| Err(RError::new(ErrorKind::RollbackFailed)),
                |_| Err(RError::new(ErrorKind::CommitUnknown)),
                |e| Err(storage(e)),
            )?;
        Ok(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        ))
    }
    pub async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<bool>,
        control: &Control<'_, T>,
    ) -> Result<(), RError> {
        self.check_claim(claim)?;
        let s = &self.service;
        s.runtime
            .local_tx_with_context(
                s.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (s, claim),
                |(s, claim), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                        crate::transaction::lock(tx).await.map_err(fault)?;
                        s.reconcile_messaging
                            .protect_in(tx, claim, s, |s, tx| {
                                Box::pin(async move {
                                    rss_mdm_execution_service::source_changes::advance_in(
                                        tx,
                                        &s.reconcile_messaging,
                                        s.source.clone(),
                                    )
                                    .await
                                    .map_err(|e| fault(e.into()))?;
                                    rss_mdm_execution_service::source_changes::clear_failure_in(tx)
                                        .await
                                        .map_err(|e| fault(e.into()))
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
                |_| Err(RError::new(ErrorKind::RollbackFailed)),
                |_| Err(RError::new(ErrorKind::CommitUnknown)),
                |e| Err(storage(e)),
            )
    }
    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-source-changes", Duration::from_secs(8));
        let _ = self.service.automation_task.set(status);
        task.into_registration(move|cancel|async move {
            let timer=crate::clock::Timer::new();let control=Control::new(&timer,Duration::MAX,&cancel);
            let config=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {concurrency:1,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:crate::worker_wake::RECOVERY,initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000}).map_err(rss_runtime::ShutdownError::new)?;
            self.store.wake(&target(self.service.tenant),&control.child(Duration::from_secs(6))).await.map_err(rss_runtime::ShutdownError::new)?;
            let scope=Scope::new(self.service.tenant,"mdm.assets").expect("constant domain");
            let runner=async {rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&scope,config,&control,signals.automation(),|event|self.service.record_runner_failure(event)).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)};
            let bridge=async {loop {
                if cancel.is_cancelled(){return Ok(());}
                let result=self.service.forward_asset_changes().await;
                self.service.record_bridge(result.as_ref().err().map(|e|match e {Error::CommitUnknown|Error::RollbackFailed=>health::AutomationFailure::SettlementUnknown,_=>health::AutomationFailure::StorageUnavailable}));
                match result {Ok(n) if n>0=>continue,Ok(_)=>crate::worker_wake::wait(signals.automation_input(),&cancel,None).await,Err(_)=>tokio::select!{()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(1))=>{}}}
            }};
            tokio::try_join!(runner,bridge).map(|_|())
        })
    }
}
impl Reconciler<PgClaim> for SourceChangesWork {
    type State = bool;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<ReconcileDiff<bool>, RError> {
        SourceChangesWork::observe(self, claim, control).await
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        diff: ReconcileDiff<bool>,
        control: &Control<'_, T>,
    ) -> Result<(), RError> {
        SourceChangesWork::apply(self, claim, diff, control).await
    }
}
impl DurableStore for SourceChangesWork {
    type Claim = PgClaim;
    async fn wake<T: Timer>(&self, t: &Target, c: &Control<'_, T>) -> Result<(), RError> {
        self.check(t.scope())?;
        if t.entity() != "changes" {
            return Err(RError::new(ErrorKind::Invariant));
        }
        self.store.wake(t, c).await
    }
    async fn claim_due<T: Timer>(
        &self,
        s: &Scope,
        n: usize,
        ttl: Duration,
        c: &Control<'_, T>,
    ) -> Result<Vec<PgClaim>, RError> {
        self.check(s)?;
        let result = self.store.claim_due(s, n, ttl, c).await;
        self.service.record_scan(s, result.as_ref().map(|_| ()));
        result
    }
    async fn renew<T: Timer>(
        &self,
        k: &PgClaim,
        ttl: Duration,
        c: &Control<'_, T>,
    ) -> Result<(), RError> {
        self.check_claim(k)?;
        self.store.renew(k, ttl, c).await
    }
    async fn release<T: Timer>(&self, k: &PgClaim, c: &Control<'_, T>) -> Result<(), RError> {
        self.check_claim(k)?;
        self.store.release(k, c).await
    }
    async fn finish<T: Timer>(
        &self,
        k: &PgClaim,
        outcome: Completion,
        c: &Control<'_, T>,
    ) -> Result<(), RError> {
        self.check_claim(k)?;
        if matches!(
            outcome,
            Completion::Suspended { .. } | Completion::Converged
        ) {
            let control = c.child(Duration::from_secs(6));
            let s = &self.service;
            s.runtime.local_tx_with_context(s.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),(s,k),|(s,k),tx|Box::pin(async move {
                s.audit_store.bind_in(tx).await.map_err(PgError::from)?;crate::transaction::lock(tx).await.map_err(fault)?;
                s.reconcile_messaging.protect_in(tx,k,s,|s,tx|Box::pin(async move {
                    if outcome==Completion::Converged {rss_mdm_execution_service::source_changes::clear_failure_in(tx).await.map_err(|e|fault(e.into()))}else{rss_mdm_execution_service::source_changes::fail_in(tx,&s.audit_store).await.map_err(|e|fault(e.into()))}
                })).await
            })).await.fold(Ok,|e|Err(storage(e)),|e|Err(storage(e)),|_|Err(RError::new(ErrorKind::RollbackFailed)),|_|Err(RError::new(ErrorKind::CommitUnknown)),|e|Err(storage(e)))?;
        }
        self.store.finish(k, outcome, c).await?;
        self.service.record_settled(k.target(), outcome);
        Ok(())
    }
}
#[path = "source_health.rs"]
pub mod health;

impl SourceChanges {
    /// A discovery read is only a hint. Wake and forwarding happen atomically;
    /// forwarded history stays until the business checkpoint consumes it.
    pub async fn forward_asset_changes(&self) -> std::result::Result<u64, Error> {
        let timer = crate::clock::Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let pending = self.runtime.local_tx(self.tenant, deadline(), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded)")
                    .bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(Ok, |_| Err(Error::Unavailable(Failure::PlanningStorage)), |_| Err(Error::Unavailable(Failure::PlanningStorage)), |_| Err(Error::RollbackFailed), |_| Err(Error::CommitUnknown), |_| Err(Error::Unavailable(Failure::PlanningStorage)))?;
        if !pending {
            return Ok(0);
        }
        self.runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (self, target(self.tenant).clone(), ()),
                |(service, target, context), tx| {
                    Box::pin(async move {
                        service
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(PgError::from)?;
                        service
                            .reconcile_messaging
                            .wake_in(tx, target, context, |_, tx| {
                                Box::pin(async move {
                                    let tenant = tx.tenant_id().to_string();
                                    tx.with_connection(move |c| {
                                        Box::pin(async move {
                                            let result = sqlx::query(
                                                r#"
                      WITH batch AS (
                        SELECT revision FROM mdm.asset_changes
                        WHERE tenant_id=$1::uuid AND NOT forwarded ORDER BY revision
                        LIMIT 1000 FOR UPDATE SKIP LOCKED
                      ) UPDATE mdm.asset_changes c SET forwarded=true FROM batch b
                        WHERE c.tenant_id=$1::uuid AND c.revision=b.revision
                    "#,
                                            )
                                            .bind(tenant)
                                            .execute(&mut *c)
                                            .await?;
                                            if result.rows_affected() > 0 {
                                                crate::worker_wake::notify(
                                                    c,
                                                    crate::worker_wake::Work::Automation,
                                                )
                                                .await?;
                                            }
                                            Ok(result.rows_affected())
                                        })
                                    })
                                    .await
                                })
                            })
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::PlanningStorage)),
            )
    }
}
