//! A single Device owner runner. RSS is the only claim, retry and lease authority.
use crate::{Associations, identity_projection, lifecycle, reconcile};
use rss_reconcile::{
    ActualState, ClaimBatch, Completion, Control, DesiredState, DurableStore, Error, ErrorKind,
    ReconcileDiff, ReconcileStep, Reconciler, ResourceSet, Scope, Target, Timer,
};
use rss_reconcile_postgres::{PgClaim, PgMessagingStore, PgStore};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub struct DeviceWork {
    owner: Arc<Associations>,
    runtime: Arc<PgRuntime>,
    schedule: PgStore,
    messaging: PgMessagingStore,
    retirement: Arc<dyn rss_mdm_registration_service::Retirement>,
    concurrency: usize,
    #[cfg(feature = "integration")]
    compute_gate: std::sync::Mutex<
        Option<(
            tokio::sync::mpsc::UnboundedSender<Computed>,
            std::collections::BTreeSet<String>,
        )>,
    >,
}
impl DeviceWork {
    pub async fn new(
        owner: Arc<Associations>,
        runtime: Arc<PgRuntime>,
        schedule: PgStore,
        retirement: Arc<dyn rss_mdm_registration_service::Retirement>,
        concurrency: usize,
        deadline: OperationDeadline,
    ) -> Result<Self, PgError> {
        let messaging = PgMessagingStore::new(runtime.clone(), owner.tenant, deadline).await?;
        // Audit bind verifies runtime provenance before the runner is exposed.
        runtime
            .local_tx_with_context(owner.tenant, deadline, &owner, |owner, tx| {
                Box::pin(async move { owner.audit.bind_in(tx).await.map_err(PgError::from) })
            })
            .await
            .fold(
                Ok,
                Err,
                Err,
                |_| {
                    Err(PgError::from(sqlx::Error::Protocol(
                        "Device startup rollback unconfirmed".into(),
                    )))
                },
                |_| {
                    Err(PgError::from(sqlx::Error::Protocol(
                        "Device startup commit unknown".into(),
                    )))
                },
                Err,
            )?;
        Ok(Self {
            owner,
            runtime,
            schedule,
            messaging,
            retirement,
            concurrency,
            #[cfg(feature = "integration")]
            compute_gate: Default::default(),
        })
    }
    fn scope(&self) -> Scope {
        Scope::new(self.owner.tenant, "mdm.devices").expect("Device scope")
    }
    fn task(&self, claim: &PgClaim) -> Result<Task, Error> {
        if claim.target().scope() != &self.scope() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        match claim.target().entity() {
            "inputs" => Ok(Task::Inputs),
            "retirements" => Ok(Task::Retirements),
            value => value
                .strip_prefix("work:")
                .and_then(|id| Uuid::parse_str(id).ok())
                .map(Task::Work)
                .ok_or_else(|| Error::new(ErrorKind::Invariant)),
        }
    }
    async fn step(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Task,
        cut: Option<&rss_mdm_inventory::AssetCut>,
    ) -> Result<(), PgError> {
        let tenant = self.owner.tenant;
        let (wake, facts) = match task {
            Task::Inputs => (
                tx.with_connection_context(&mut (cut,), move |(cut,), c| {
                    Box::pin(async move {
                        identity_projection::advance(
                            c,
                            tenant,
                            cut.ok_or_else(|| sqlx::Error::Protocol("missing asset input".into()))?,
                        )
                        .await
                        .map_err(sql_error)
                    })
                })
                .await?,
                vec![],
            ),
            Task::Retirements => {
                let participant = self.retirement.clone();
                (
                    vec![],
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            lifecycle::settle_one_in(c, tenant, participant.as_ref())
                                .await
                                .map_err(sql_error)
                        })
                    })
                    .await?,
                )
            }
            Task::Work(id) => {
                let (device, wake) = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            identity_projection::key_page(c, tenant, id)
                                .await
                                .map_err(sql_error)
                        })
                    })
                    .await?;
                let facts = if let Some((device, window)) = device {
                    let selected = device.clone();
                    let prepared = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                reconcile::prepare(c, tenant, &selected)
                                    .await
                                    .map_err(sql_error)
                            })
                        })
                        .await?;
                    #[cfg(feature = "integration")]
                    self.compute_checkpoint(&device).await;
                    let facts = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                reconcile::publish(c, tenant, prepared)
                                    .await
                                    .map_err(sql_error)
                            })
                        })
                        .await?;
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            identity_projection::complete_work(c, tenant, id, window)
                                .await
                                .map_err(sql_error)
                        })
                    })
                    .await?;
                    facts
                } else {
                    Vec::new()
                };
                (wake, facts)
            }
        };
        for id in wake {
            self.messaging
                .wake_in(
                    tx,
                    &Target::new(self.scope(), format!("work:{id}"))
                        .map_err(|_| sqlx::Error::Protocol("device work target".into()))?,
                    &rss_reconcile::ResourceSet::empty(self.scope().tenant()),
                    (),
                    |_, _| Box::pin(async { Ok(()) }),
                )
                .await?;
        }
        for fact in facts {
            self.owner
                .audit
                .append_in(tx, &fact)
                .await
                .map_err(PgError::from)?;
        }
        Ok(())
    }
    pub fn registration(
        self: Arc<Self>,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("device-associations", Duration::from_secs(30));
        let _ = self.owner.worker_status.set(status);
        task.into_registration(move |stop|async move {
            #[allow(clippy::disallowed_methods,reason="monotonic runner clock")]
            let timer=DeviceTimer(tokio::time::Instant::now());
            let force=tokio_util::sync::CancellationToken::new();
            let control=Control::new(&timer,Duration::MAX,&force);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {concurrency:self.concurrency,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(8),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(2),initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000}).map_err(rss_runtime::ShutdownError::new)?;
            for entity in ["inputs","retirements"] {self.schedule.wake(&Target::new(self.scope(),entity).expect("owner input"), &rss_reconcile::ResourceSet::empty(self.scope().tenant()),&control.child(Duration::from_secs(6))).await.map_err(rss_runtime::ShutdownError::new)?;}
            rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&self.scope(),policy,&control,&stop,&notify,|event|{
                if let Ok(mut failures)=self.owner.worker_failures.lock() {
                    let (key,kind)=match &event {
                        rss_reconcile::Observation::Deferred{..}=>return,
                        rss_reconcile::Observation::AttemptFailed{target,error,..}=>(target.entity().to_owned(),error.kind()),
                        rss_reconcile::Observation::ScanFailed{error,..}=>("!scan".to_owned(),error.kind()),
                    };
                    if failures.len()<1000 || failures.contains_key(&key) {failures.insert(key,kind);} else {failures.insert("!truncated".into(),ErrorKind::Invariant);}
                }
                eprintln!("{}",serde_json::json!({"event":"device_owner_failure","diagnostic":format!("{event:?}")}));
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)
        })
    }
}
#[derive(Clone, Copy)]
enum Task {
    Inputs,
    Retirements,
    Work(Uuid),
}
fn sql_error(_: crate::Error) -> sqlx::Error {
    sqlx::Error::Protocol("Device owner step unavailable".into())
}
fn error(e: PgError) -> Error {
    Error::new(
        if e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            ErrorKind::Fenced
        } else {
            ErrorKind::Transient
        },
    )
}
impl Reconciler<PgClaim> for DeviceWork {
    type State = bool;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<bool>>, Error> {
        let task = self.task(claim)?;
        let tenant = self.owner.tenant;
        let pending = self
            .runtime
            .local_tx(
                tenant,
                OperationDeadline::from_remaining(control.remaining()),
                move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                match task {
                                    Task::Inputs => identity_projection::pending(c, tenant).await,
                                    Task::Retirements => {
                                        lifecycle::settlement_pending(c, tenant).await
                                    }
                                    Task::Work(id) => {
                                        identity_projection::work_pending(c, tenant, id).await
                                    }
                                }
                                .map_err(sql_error)
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(error(e)),
                |e| Err(error(e)),
                |_| Err(Error::new(ErrorKind::RollbackFailed)),
                |_| Err(Error::new(ErrorKind::CommitUnknown)),
                |e| Err(error(e)),
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
    ) -> Result<ReconcileStep<()>, Error> {
        let task = self.task(claim)?;
        let cut = if matches!(task, Task::Inputs) {
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
            Some(
                rss_mdm_inventory_service::assets::cut::capture(
                    &self.owner.audit,
                    self.owner.tenant,
                    &budget,
                )
                .await
                .map_err(|_| Error::new(ErrorKind::Transient))?,
            )
        } else {
            None
        };
        self.runtime
            .local_tx_with_context(
                self.owner.tenant,
                OperationDeadline::from_remaining(control.remaining()),
                (self, claim, cut.as_ref()),
                |(owner, claim, cut), tx| {
                    Box::pin(async move {
                        owner.owner.audit.bind_in(tx).await.map_err(PgError::from)?;
                        owner
                            .messaging
                            .protect_in(tx, claim, (owner, *cut), |(owner, cut), tx| {
                                Box::pin(async move {
                                    owner
                                        .step(tx, task, *cut)
                                        .await
                                        .map(rss_reconcile_postgres::ProtectedStep::Ready)
                                })
                            })
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(error(e)),
                |e| Err(error(e)),
                |_| Err(Error::new(ErrorKind::RollbackFailed)),
                |_| Err(Error::new(ErrorKind::CommitUnknown)),
                |e| Err(error(e)),
            )
    }
}
impl DurableStore for DeviceWork {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        if target.scope() != &self.scope() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        self.schedule.wake(target, resources, c).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        if target.scope() != &self.scope() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        self.schedule.bind_resources(target, resources, c).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        if scope != &self.scope() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        let result = self.schedule.claim_due(scope, limit, lease, c).await;
        if result.is_ok()
            && let Ok(mut failures) = self.owner.worker_failures.lock()
        {
            failures.remove("!scan");
        }
        result
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.task(claim)?;
        self.schedule.renew(claim, lease, c).await
    }
    async fn release<T: Timer>(&self, claim: &PgClaim, c: &Control<'_, T>) -> Result<(), Error> {
        self.task(claim)?;
        self.schedule.release(claim, c).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        let task = self.task(claim)?;
        let scheduled = if matches!(task, Task::Inputs | Task::Retirements)
            && completion == Completion::Converged
        {
            Completion::Reobserve(Duration::from_secs(2))
        } else {
            completion
        };
        let result = self.schedule.finish(claim, scheduled, c).await;
        if matches!(task, Task::Inputs) && result.is_ok() && completion == Completion::Converged {
            self.owner
                .worker_observed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if let Ok(mut failures) = self.owner.worker_failures.lock() {
            if result.is_ok()
                && matches!(completion, Completion::Converged | Completion::Reobserve(_))
            {
                failures.remove(claim.target().entity());
            } else if result.is_err() || !matches!(completion, Completion::Deferred(_)) {
                failures.insert(
                    claim.target().entity().to_owned(),
                    result
                        .as_ref()
                        .err()
                        .map_or(ErrorKind::Transient, |e| e.kind()),
                );
            }
        }
        result
    }
}
struct DeviceTimer(tokio::time::Instant);
impl Timer for DeviceTimer {
    #[allow(clippy::disallowed_methods, reason = "monotonic runner clock")]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }
}

/// A finite integration-test synchronization point after real identity computation.
#[cfg(feature = "integration")]
pub struct Computed {
    pub device: String,
    pub resume: Arc<tokio::sync::Notify>,
}
#[cfg(feature = "integration")]
impl Drop for Computed {
    fn drop(&mut self) {
        // Dropping the receiver or a failed test must release paused transactions.
        self.resume.notify_one();
    }
}
#[cfg(feature = "integration")]
impl DeviceWork {
    /// Pause each named device once, retaining its real transaction and device fences.
    pub fn pause_after_compute(
        &self,
        devices: Vec<String>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Computed> {
        let (send, receive) = tokio::sync::mpsc::unbounded_channel();
        *self.compute_gate.lock().expect("integration gate") =
            Some((send, devices.into_iter().collect()));
        receive
    }
    async fn compute_checkpoint(&self, device: &str) {
        let send = {
            let mut gate = self.compute_gate.lock().expect("integration gate");
            gate.as_mut()
                .and_then(|(send, devices)| devices.remove(device).then(|| send.clone()))
        };
        if let Some(send) = send {
            let resume = Arc::new(tokio::sync::Notify::new());
            if send
                .send(Computed {
                    device: device.to_owned(),
                    resume: resume.clone(),
                })
                .is_ok()
            {
                resume.notified().await;
            }
        }
    }
}
