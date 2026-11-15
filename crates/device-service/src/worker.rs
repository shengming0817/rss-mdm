//! A single Device owner runner. RSS is the only claim, retry and lease authority.
use crate::{Associations, identity_projection, reconcile};
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
    read_pool: sqlx::PgPool,
    storage: rss_transactional_messaging::fence::StorageIdentity,
}
impl DeviceWork {
    pub async fn new(
        read_pool: sqlx::PgPool,
        probe: rss_transactional_messaging::fence::ExecutionBinding,
        owner: Arc<Associations>,
        runtime: Arc<PgRuntime>,
        schedule: PgStore,
        deadline: OperationDeadline,
    ) -> Result<Self, PgError> {
        let messaging = PgMessagingStore::new(runtime.clone(), probe, deadline).await?;
        // Audit bind verifies runtime provenance before the runner is exposed.
        runtime
            .local_tx_with_context(probe, deadline, &owner, |owner, tx| {
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
        let worker = Self {
            owner,
            runtime,
            schedule,
            messaging,
            read_pool,
            storage: probe.storage(),
        };

        Ok(worker)
    }

    // Refresh only this scope's already observed failures; no startup work enumeration.
    async fn refresh_failures<T: Timer>(
        &self,
        scope: &Scope,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        let prefix = format!("{}:", scope.tenant());
        let previous = self
            .owner
            .worker_failures
            .lock()
            .map_err(|_| Error::new(ErrorKind::Invariant))?
            .iter()
            .filter_map(|(key, failure)| {
                key.strip_prefix(&prefix)
                    .map(|entity| (entity.to_owned(), failure.clone()))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if previous.is_empty() {
            return Ok(());
        }
        let names = previous.keys().cloned().collect::<Vec<_>>();
        let tenant = scope.tenant().to_string();
        let recovered: Vec<String> = self.schedule.local_tx(scope, control, move |tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT entity FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.devices' AND entity=ANY($2) AND result='converged'")
                    .bind(tenant).bind(names).fetch_all(c).await
            })).await
        })).await?;
        let mut current = self
            .owner
            .worker_failures
            .lock()
            .map_err(|_| Error::new(ErrorKind::Invariant))?;
        for entity in recovered {
            let key = format!("{prefix}{entity}");
            if current
                .get(&key)
                .zip(previous.get(&entity))
                .is_some_and(|(now, old)| Arc::ptr_eq(now, old))
            {
                current.remove(&key);
            }
        }
        Ok(())
    }

    fn scope(tenant: rss_request_context::TenantId) -> Scope {
        Scope::new(tenant, "mdm.devices").expect("Device scope")
    }
    fn task(&self, claim: &PgClaim) -> Result<Task, Error> {
        if claim.target().scope().reconciler() != "mdm.devices" {
            return Err(Error::new(ErrorKind::Invariant));
        }
        match claim.target().entity() {
            "inputs" => Ok(Task::Inputs),
            value => value
                .strip_prefix("work:")
                .and_then(|id| Uuid::parse_str(id).ok())
                .map(Task::Work)
                .ok_or_else(|| Error::new(ErrorKind::Invariant)),
        }
    }
    async fn device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Task,
    ) -> Result<Option<rss_mdm_agent_wire::DeviceId>, PgError> {
        let Task::Work(id) = task else {
            return Ok(None);
        };
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND id=$2 AND kind='device'")
                .bind(tenant).bind(id).fetch_optional(c).await.and_then(|id| id.map(crate::device_id).transpose())
        })).await
    }
    async fn resources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Task,
    ) -> Result<ResourceSet, PgError> {
        let Some(device) = self.device_in(tx, task).await? else {
            return Ok(ResourceSet::empty(tx.tenant_id()));
        };
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move {
                let devices = crate::identity::affected_devices_on(c, tenant, &device)
                    .await
                    .map_err(sql_error)?;
                rss_mdm_registration_service::lifecycle::resources::devices(tenant, &devices)
                    .map_err(|_| sqlx::Error::Protocol("association resource budget".into()))
            })
        })
        .await
    }
    async fn step(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Task,
        prepared: Option<reconcile::Prepared>,
        cut: Option<&rss_mdm_inventory::AssetCut>,
    ) -> Result<rss_reconcile_postgres::ProtectedStep<()>, PgError> {
        let tenant = tx.tenant_id();
        let (wake, facts) = match task {
            Task::Inputs => (
                tx.with_connection_context(&mut (cut,), move |(cut,), c| {
                    Box::pin(async move {
                        identity_projection::advance(
                            c,
                            execution,
                            cut.ok_or_else(|| sqlx::Error::Protocol("missing asset input".into()))?,
                        )
                        .await
                        .map_err(sql_error)
                    })
                })
                .await?,
                vec![],
            ),
            Task::Work(id) => {
                let page = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            identity_projection::key_page(c, execution, id)
                                .await
                                .map_err(sql_error)
                        })
                    })
                    .await?;
                let Some((device, wake)) = page else {
                    return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(
                        Duration::from_millis(50),
                    ));
                };
                let facts = if let Some((_device, window)) = device {
                    let prepared = prepared.ok_or_else(|| {
                        sqlx::Error::Protocol("missing association preparation".into())
                    })?;

                    let facts = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                reconcile::publish(execution, c, tenant, prepared)
                                    .await
                                    .map_err(sql_error)
                            })
                        })
                        .await?;
                    let Some(facts) = facts else {
                        return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(
                            Duration::from_millis(50),
                        ));
                    };
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
            let resources = self.resources_in(tx, Task::Work(id)).await?;
            self.messaging
                .wake_in(
                    tx,
                    &Target::new(Self::scope(tx.tenant_id()), format!("work:{id}"))
                        .map_err(|_| sqlx::Error::Protocol("device work target".into()))?,
                    &resources,
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
        Ok(rss_reconcile_postgres::ProtectedStep::Ready(()))
    }
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        notify: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare("device-associations", drain);
        let _ = self.owner.worker_status.set(status);
        task.into_registration(move |stop|async move {
            #[allow(clippy::disallowed_methods,reason="monotonic runner clock")]
            let timer=DeviceTimer(tokio::time::Instant::now());
            let force=tokio_util::sync::CancellationToken::new();
            let control=Control::new(&timer,Duration::MAX,&force);
            let mut after:Option<Uuid>=None;
            let mut worked = false;
            loop {
                if stop.is_cancelled(){return Ok(())}
                let page:Result<Vec<Uuid>,sqlx::Error>=sqlx::query_scalar("SELECT tenant_id FROM mdm_devices.association_work_scopes($1)").bind(after).fetch_all(&self.read_pool).await;
                let tenants=match page {
                    Ok(tenants)=>{if let Ok(mut failures)=self.owner.worker_failures.lock(){failures.remove("!discovery");} self.owner.worker_observed.store(true,std::sync::atomic::Ordering::Release);tenants},
                    Err(_)=>{self.owner.record_worker_failure("!discovery".into(),ErrorKind::Transient);Vec::new()},
                };
                if tenants.is_empty(){after=None;
                    if std::mem::take(&mut worked) { continue; }
tokio::select!{biased;()=stop.cancelled()=>return Ok(()),()=notify.notified()=>{},()=tokio::time::sleep(Duration::from_secs(5))=>{}}continue}
                for tenant in tenants {
                    after=Some(tenant);
                    let tenant=rss_request_context::TenantId::parse(&tenant.to_string()).map_err(rss_runtime::ShutdownError::new)?;
                    let scope=Self::scope(tenant);
                    let report = match rss_reconcile::run_batch(self.as_ref(),
self.as_ref(),
&scope,
policy,
&control,
&stop,
|event|{
                        let (key,kind)=match &event {
                            rss_reconcile::Observation::Deferred{..}=>return,
                            rss_reconcile::Observation::AttemptFailed{target,error,..}=>(format!("{}:{}",target.scope().tenant(),target.entity()),error.kind()),
                            rss_reconcile::Observation::ScanFailed{error,..}=>(format!("!scan:{tenant}"),error.kind()),
                        };
                        self.owner.record_worker_failure(key,kind);
                    }).await {
      Ok(report) => report,
      Err(error) if control.check().is_ok() && matches!(error.kind(),
          rss_reconcile::ErrorKind::Transient | rss_reconcile::ErrorKind::Deadline | rss_reconcile::ErrorKind::CommitUnknown) => {
          // The observer retained this scope's failure. Advance the tenant cursor;
          // an unconfirmed claim is not an empty or successfully drained batch.
          continue;
      }
      Err(error) => return Err(rss_runtime::ShutdownError::new(error)),
  };
                    worked |= [report.converged, report.reobserve, report.deferred, report.retried,
                        report.suspended, report.fenced, report.execution_failed]
                        .into_iter().any(|count| count > 0);
                }
            }
        })
    }
}
#[derive(Clone, Copy)]
enum Task {
    Inputs,
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
        let execution = self.execution(claim, control).await?;
        let task = self.task(claim)?;
        let tenant = execution.tenant();
        let pending = self
            .runtime
            .local_tx(
                execution,
                OperationDeadline::from_remaining(control.remaining()),
                move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                match task {
                                    Task::Inputs => identity_projection::pending(c, tenant).await,
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
        let execution = self.execution(claim, control).await?;
        let task = self.task(claim)?;
        let cut = if matches!(task, Task::Inputs) {
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
            Some(
                rss_mdm_inventory_service::assets::cut::capture(
                    &self.owner.audit,
                    execution.tenant(),
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
                execution,
                OperationDeadline::from_remaining(control.remaining()),
                (self, claim, cut.as_ref()),
                |(owner, claim, cut), tx| {
                    Box::pin(async move {
                        owner.owner.audit.bind_in(tx).await.map_err(PgError::from)?;
                        let prepared = if let Some(device) = owner.device_in(tx, task).await? {
                            let tenant = tx.tenant_id();
                            let prepared = tx
                                .with_connection(move |c| {
                                    Box::pin(async move {
                                        reconcile::prepare(c, tenant, &device)
                                            .await
                                            .map_err(sql_error)
                                    })
                                })
                                .await?;
                            let Some(prepared) = prepared else {
                                return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
                            };
                            Some(prepared)
                        } else {
                            None
                        };
                        let resources = match &prepared {
                            Some(prepared) => {
                                prepared.resources(tx.tenant_id()).map_err(sql_error)?
                            }
                            None => ResourceSet::empty(tx.tenant_id()),
                        };
                        owner
                            .messaging
                            .bind_in(tx, claim.target(), &resources)
                            .await?;
                        owner
                            .messaging
                            .protect_in(
                                tx,
                                claim,
                                (owner, *cut, prepared),
                                |(owner, cut, prepared), tx| {
                                    Box::pin(async move {
                                        owner.step(execution, tx, task, prepared.take(), *cut).await
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
        if target.scope().reconciler() != "mdm.devices" {
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
        if target.scope().reconciler() != "mdm.devices" {
            return Err(Error::new(ErrorKind::Invariant));
        }
        self.schedule.bind_resources(target, resources, c).await
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        scan_budget: u32,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        if scope.reconciler() != "mdm.devices" {
            return Err(Error::new(ErrorKind::Invariant));
        }

        self.refresh_failures(scope, c).await?;
        let result = self
            .schedule
            .claim_due(scope, limit, scan_budget, lease, c)
            .await;
        if result.is_ok() {
            self.owner
                .worker_observed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        if result.is_ok()
            && let Ok(mut failures) = self.owner.worker_failures.lock()
        {
            failures.remove(&format!("!scan:{}", scope.tenant()));
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
        self.task(claim)?;
        let previous = self.owner.worker_failures.lock().ok().and_then(|failures| {
            failures
                .get(&format!(
                    "{}:{}",
                    claim.target().scope().tenant(),
                    claim.target().entity()
                ))
                .cloned()
        });
        let result = self.schedule.finish(claim, completion, c).await;
        if result.is_ok() && matches!(completion, Completion::Converged | Completion::Reobserve(_))
        {
            if let Ok(mut failures) = self.owner.worker_failures.lock()
                && failures
                    .get(&format!(
                        "{}:{}",
                        claim.target().scope().tenant(),
                        claim.target().entity()
                    ))
                    .zip(previous.as_ref())
                    .is_some_and(|(now, old)| Arc::ptr_eq(now, old))
            {
                failures.remove(&format!(
                    "{}:{}",
                    claim.target().scope().tenant(),
                    claim.target().entity()
                ));
            }
        } else if result.is_err() || !matches!(completion, Completion::Deferred(_)) {
            self.owner.record_worker_failure(
                format!(
                    "{}:{}",
                    claim.target().scope().tenant(),
                    claim.target().entity()
                ),
                result
                    .as_ref()
                    .err()
                    .map_or(ErrorKind::Transient, |e| e.kind()),
            );
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

/// Only asset events wake association inputs; object publication cannot wake its producer.
pub async fn wake_inputs_in(
    store: &PgMessagingStore,
    tx: &mut PgTransaction<'_>,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id();

    let t = tenant.to_string();
    let epoch = tx.expected_epoch().get();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_devices.checkpoints(tenant_id,expected_epoch) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&t).bind(epoch).execute(&mut *c).await?;
        let expected:i64=sqlx::query_scalar("SELECT expected_epoch FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid").bind(t).fetch_one(c).await?;
        if expected!=epoch{return Err(sqlx::Error::Protocol("device input epoch mismatch".into()))} Ok(())
    })).await?;
    let target = Target::new(
        Scope::new(tenant, "mdm.devices").expect("Device scope"),
        "inputs",
    )
    .expect("Device inputs");
    store
        .wake_in(tx, &target, &ResourceSet::empty(tenant), (), |_, tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT pg_notify('mdm_work','devices')")
                            .execute(c)
                            .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
}

impl DeviceWork {
    async fn execution<T: Timer>(
        &self,
        claim: &PgClaim,
        control: &Control<'_, T>,
    ) -> Result<rss_transactional_messaging::fence::ExecutionBinding, Error> {
        control.check()?;
        let task = self.task(claim)?;
        let tenant = claim.target().scope().tenant();
        let id = match task {
            Task::Inputs => None,
            Task::Work(id) => Some(id),
        };
        let epoch: i64 =
            sqlx::query_scalar("SELECT mdm_devices.association_work_epoch($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(id)
                .fetch_one(&self.read_pool)
                .await
                .map_err(|e| error(e.into()))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| Error::new(ErrorKind::Invariant))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
}
