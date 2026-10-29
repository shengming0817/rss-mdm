//! A single Device owner runner. RSS is the only claim, retry and lease authority.
use crate::{Associations, identity_projection, lifecycle, reconcile};
use rss_reconcile::{
    ActualState, Completion, Control, DesiredState, DurableStore, Error, ErrorKind, ReconcileDiff,
    Reconciler, Scope, Target, Timer,
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
    async fn step(&self, tx: &mut PgTransaction<'_>, task: Task) -> Result<(), PgError> {
        let tenant = self.owner.tenant;
        let (wake, facts) = match task {
            Task::Inputs => (
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        identity_projection::advance(c, tenant)
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
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        let (device, wake) = identity_projection::key_page(c, tenant, id)
                            .await
                            .map_err(sql_error)?;
                        let facts = if let Some((device, window)) = device {
                            let facts = reconcile::advance(c, tenant, &device)
                                .await
                                .map_err(sql_error)?;
                            identity_projection::complete_work(c, tenant, id, window)
                                .await
                                .map_err(sql_error)?;
                            facts
                        } else {
                            vec![]
                        };
                        Ok((wake, facts))
                    })
                })
                .await?
            }
        };
        for id in wake {
            self.messaging
                .wake_in(
                    tx,
                    &Target::new(self.scope(), format!("work:{id}"))
                        .map_err(|_| sqlx::Error::Protocol("device work target".into()))?,
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
            rss_runtime::ManagedTask::prepare("device-associations", Duration::from_secs(20));
        let _ = self.owner.worker_status.set(status);
        task.into_registration(move |stop|async move {
            #[allow(clippy::disallowed_methods,reason="monotonic runner clock")]
            let timer=DeviceTimer(tokio::time::Instant::now());
            let control=Control::new(&timer,Duration::MAX,&stop);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {concurrency:self.concurrency,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(8),scan_interval:Duration::from_millis(20),idle_scan_interval:Duration::from_secs(2),initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000}).map_err(rss_runtime::ShutdownError::new)?;
            for entity in ["inputs","retirements"] {self.schedule.wake(&Target::new(self.scope(),entity).expect("owner input"),&control.child(Duration::from_secs(6))).await.map_err(rss_runtime::ShutdownError::new)?;}
            rss_reconcile::run_with_notify(self.as_ref(),self.as_ref(),&self.scope(),policy,&control,&notify,|event|{
                if let Ok(mut failures)=self.owner.worker_failures.lock() {
                    let (key,kind)=match &event {
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
    ) -> Result<ReconcileDiff<bool>, Error> {
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
    ) -> Result<(), Error> {
        let task = self.task(claim)?;
        self.runtime
            .local_tx_with_context(
                self.owner.tenant,
                OperationDeadline::from_remaining(control.remaining()),
                (self, claim),
                |(owner, claim), tx| {
                    Box::pin(async move {
                        owner.owner.audit.bind_in(tx).await.map_err(PgError::from)?;
                        owner
                            .messaging
                            .protect_in(tx, claim, owner, |owner, tx| {
                                Box::pin(async move { owner.step(tx, task).await })
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
    async fn wake<T: Timer>(&self, target: &Target, c: &Control<'_, T>) -> Result<(), Error> {
        if target.scope() != &self.scope() {
            return Err(Error::new(ErrorKind::Invariant));
        }
        self.schedule.wake(target, c).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<Vec<PgClaim>, Error> {
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
            } else {
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
