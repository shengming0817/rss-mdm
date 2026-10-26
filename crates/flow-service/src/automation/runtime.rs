use super::*;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
use std::sync::Mutex;
#[path = "completion.rs"]
mod completion;

/// Single-step planning execution over the real claims and protected transaction.
/// It owns no Inventory/Compliance services and cannot register a background runner.
pub struct PlanningWork {
    execution: ExecutionOwner,
    service: Arc<Planning>,
    store: rss_reconcile_postgres::PgStore,
}

enum ExecutionOwner {
    Ready(Arc<rss_mdm_execution_service::ExecutionService>),
    #[cfg(feature = "integration")]
    PlanningOnly,
}

pub struct Automation {
    pub work: Arc<PlanningWork>,
    assets: Arc<assets::AssetService>,
    compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
}
impl std::ops::Deref for Automation {
    type Target = PlanningWork;
    fn deref(&self) -> &Self::Target {
        &self.work
    }
}
impl PlanningWork {
    fn execution(&self) -> Option<&Arc<rss_mdm_execution_service::ExecutionService>> {
        match &self.execution {
            ExecutionOwner::Ready(service) => Some(service),
            #[cfg(feature = "integration")]
            ExecutionOwner::PlanningOnly => None,
        }
    }
    fn check_scope(
        &self,
        scope: &rss_reconcile::Scope,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        if scope.tenant() != self.service.tenant
            || !matches!(scope.reconciler(), "mdm.assets" | jobs::EVENT_SCOPE)
            || (scope.reconciler() == jobs::EVENT_SCOPE && self.execution().is_none())
        {
            return Err(rss_reconcile::Error::new(
                rss_reconcile::ErrorKind::Invariant,
            ));
        }
        Ok(())
    }
    fn work_owner(
        &self,
        entity: &str,
    ) -> std::result::Result<
        (
            &PgRuntime,
            &rss_reconcile_postgres::PgMessagingStore,
            &rss_mdm_audit_integration::AuditStore,
        ),
        rss_reconcile::Error,
    > {
        if entity.starts_with("event:") {
            match &self.execution {
                ExecutionOwner::Ready(service) => Ok(service.event_transaction_owner()),
                #[cfg(feature = "integration")]
                ExecutionOwner::PlanningOnly => Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Invariant,
                )),
            }
        } else {
            Ok((
                &self.service.runtime,
                &self.service.reconcile_messaging,
                &self.service.audit_store,
            ))
        }
    }
    /// A production worker is complete at construction; execution cannot be attached later.
    pub async fn connect(
        service: Arc<Planning>,
        execution: Arc<rss_mdm_execution_service::ExecutionService>,
        options: sqlx::postgres::PgConnectOptions,
    ) -> std::result::Result<Arc<Self>, Error> {
        Self::open(service, ExecutionOwner::Ready(execution), options).await
    }
    /// Pure Planning integration fixtures cannot claim or execute event work.
    #[cfg(feature = "integration")]
    pub async fn connect_planning(
        service: Arc<Planning>,
        options: sqlx::postgres::PgConnectOptions,
    ) -> std::result::Result<Arc<Self>, Error> {
        Self::open(service, ExecutionOwner::PlanningOnly, options).await
    }
    async fn open(
        service: Arc<Planning>,
        execution: ExecutionOwner,
        options: sqlx::postgres::PgConnectOptions,
    ) -> std::result::Result<Arc<Self>, Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| Error::Unavailable(Failure::AutomationConnection))?;
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let store = match rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await {
            Ok(store) => store,
            Err(_) => {
                pool.close().await;
                return Err(Error::Unavailable(Failure::AutomationAdmission));
            }
        };
        Ok(Arc::new(Self {
            service,
            store,
            execution,
        }))
    }
    pub async fn close(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        match self.store.close(&control).await {
            rss_reconcile_postgres::CloseOutcome::Drained => Ok(()),
            _ => Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                "automation storage did not drain",
            ))),
        }
    }
}
impl Automation {
    pub async fn connect(
        work: Arc<PlanningWork>,
        assets: Arc<assets::AssetService>,
        compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    ) -> std::result::Result<Arc<Self>, Error> {
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        if rss_reconcile::DurableStore::wake(
            work.as_ref(),
            &asset_target(work.service.tenant),
            &control,
        )
        .await
        .is_err()
        {
            let _ = work.close().await;
            return Err(Error::Unavailable(Failure::AutomationStorage));
        }
        Ok(Arc::new(Self {
            work,
            assets,
            compliance,
        }))
    }
    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-asset-automation", Duration::from_secs(8));
        let _ = self.service.automation_task.set(status);
        task.into_registration(move |cancel|async move {
            let timer=Timer::new();let control=rss_reconcile::Control::new(&timer,Duration::MAX,&cancel);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:4,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:crate::worker_wake::RECOVERY,
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=rss_reconcile::Scope::new(self.service.tenant,"mdm.assets").expect("constant domain");
            let runner=async {rss_reconcile::run_with_notify(self.work.as_ref(),self.as_ref(),&scope,policy,&control,signals.automation(),|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_automation_failure","diagnostic":format!("{event:?}")}));
                self.service.record_runner_failure(event);
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)};
            let event_runner=async {
                if self.work.execution().is_none() {cancel.cancelled().await;return Ok(());}
                let scope=rss_reconcile::Scope::new(self.service.tenant,jobs::EVENT_SCOPE).expect("constant domain");
                rss_reconcile::run_with_notify(self.work.as_ref(),self.as_ref(),&scope,policy,&control,signals.automation(),|event| {
                    eprintln!("{}",serde_json::json!({"event":"mdm_policy_event_failure","diagnostic":format!("{event:?}")}));
                    self.service.record_runner_failure(event);
                }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)
            };
            let bridge=async {
                loop {
                    if cancel.is_cancelled() {return Ok(());}
                    let result=async {let assets=self.service.forward_asset_changes().await?;let lifecycle=self.service.forward_lifecycle_schedules().await?;let jobs=jobs::forward_jobs(&self.service.reconcile_messaging, &self.service.runtime,self.service.tenant,&self.service.audit_store).await?;Ok::<_,Error>(assets+lifecycle+jobs as u64)}.await;
                    self.service.record_bridge(match &result {
                        Ok(_) => None,
                        Err(Error::CommitUnknown | Error::RollbackFailed) => Some(crate::planning::automation::AutomationFailure::SettlementUnknown),
                        Err(Error::Unavailable(Failure::RequestDeadline)) => Some(crate::planning::automation::AutomationFailure::Deadline),
                        Err(Error::Unavailable(_)) => Some(crate::planning::automation::AutomationFailure::StorageUnavailable),
                        Err(_) => Some(crate::planning::automation::AutomationFailure::Rejected),
                    });
                    match result {
                        Ok(count) if count > 0 => continue,
                        Ok(_) => crate::worker_wake::wait(signals.automation_input(), &cancel, None).await,
                        Err(error) => {
                            eprintln!("{}",serde_json::json!({"event":"mdm_automation_bridge_failure","reason":format!("{error:?}")}));
                            tokio::select! {()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(1))=>{}}
                        }
                    }
                }
            };
            tokio::try_join!(runner,event_runner,bridge).map(|_|())
        })
    }
}
pub struct Resource(pub Arc<PlanningWork>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "asset-automation-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(8)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await
    }
}
fn reconcile_error(error: Error) -> rss_reconcile::Error {
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::Conflict => rss_reconcile::ErrorKind::Fenced,
        _ => rss_reconcile::ErrorKind::Transient,
    })
}
// Preserve provider ownership loss independently of the transaction settlement.
fn storage_error(error: PgError) -> rss_reconcile::Error {
    rss_reconcile::Error::new(
        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            rss_reconcile::ErrorKind::Fenced
        } else {
            rss_reconcile::ErrorKind::Transient
        },
    )
}
fn fault(error: Fault, reason: &Mutex<Option<Error>>) -> PgError {
    match error {
        Fault::Request(error) => {
            *reason.lock().expect("failure slot") = Some(error);
            sqlx::Error::Protocol("asset automation rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => error.into(),
    }
}
impl PlanningWork {
    pub fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            control.check()?;
            let failure = Mutex::new(None);
            let result = self
                .work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    self.service.tenant,
                    deadline(),
                    (&self.service, claim.target().entity(), &failure),
                    |ctx, tx| {
                        Box::pin(async move {
                            let result = if ctx.1 == "changes" {
                                ctx.0.asset_work_pending(tx).await
                            } else {
                                match jobs::target_job(ctx.1).and_then(|s| Uuid::parse_str(s).ok())
                                {
                                    Some(id) => crate::automation::jobs::read_in(tx, id)
                                        .await
                                        .map(|(_, done, _, _, _)| !done),
                                    None => Err(Error::Malformed.into()),
                                }
                            };
                            result.map_err(|e| fault(e, ctx.2))
                        })
                    },
                )
                .await
                .fold(
                    Ok,
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                    |_| {
                        Err(failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .unwrap_or(Error::Unavailable(Failure::AutomationStorage)))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                );
            Ok(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(result.map_err(reconcile_error)?),
            ))
        })
    }
    pub fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        self.apply_with(claim, control, None)
    }
    fn apply_with<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
        inventory: Option<(
            &assets::AssetService,
            &rss_mdm_inventory_service::compliance::Compliance,
        )>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        Box::pin(async move {
            let failure = Mutex::new(None);
            let attempt = self
                .work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    self.service.tenant,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                    (
                        &self.service,
                        claim,
                        (
                            &self.service,
                            claim.target().entity(),
                            &failure,
                            inventory,
                            self.execution(),
                        ),
                        self.work_owner(claim.target().entity())?.1,
                        self.work_owner(claim.target().entity())?.2,
                    ),
                    |(service, claim, context, messaging, audit_store), tx| {
                        Box::pin(async move {
                            audit_store.bind_in(tx).await.map_err(PgError::from)?;
                            let definition_page = if let Some(id) =
                                jobs::target_job(context.1).and_then(|s| Uuid::parse_str(s).ok())
                            {
                                let (job, _, _, cursor, _) =
                                    crate::automation::jobs::read_in(tx, id)
                                        .await
                                        .map_err(|e| fault(e, context.2))?;
                                matches!(job, JobInput::GroupDefinition { .. })
                                    && !cursor
                                        .as_deref()
                                        .and_then(|s| {
                                            serde_json::from_str::<serde_json::Value>(s).ok()
                                        })
                                        .is_some_and(|v| v["ready"] == true)
                            } else {
                                false
                            };
                            if !definition_page {
                                crate::transaction::lock(tx)
                                    .await
                                    .map_err(|e| fault(e, context.2))?;
                            }
                            let prepared: Result<_> = async {
                                if context.1 == "changes" {
                                    return Ok(None);
                                }
                                let id = Uuid::parse_str(
                                    jobs::target_job(context.1).ok_or(Error::Malformed)?,
                                )
                                .map_err(|_| Error::Malformed)?;
                                let (job, done, _, cursor, _) =
                                    crate::automation::jobs::read_in(tx, id).await?;
                                let assignment = if done {
                                    None
                                } else if let JobInput::PolicyReconcile { policy } = &job {
                                    Some(
                                        service
                                            .prepare_assignment_in(tx, *policy, cursor.clone())
                                            .await?,
                                    )
                                } else {
                                    let mut partitions = vec![];
                                    match &job {
                                        JobInput::Group { group, .. } => partitions
                                            .push(service.groups.partition(&group.to_string())?),
                                        JobInput::GroupDefinition { edit } => partitions.push(
                                            service.groups.partition(&edit.group.to_string())?,
                                        ),
                                        _ => (),
                                    }
                                    tx.prepare_outbox_partitions(&partitions).await?;
                                    None
                                };
                                Ok(Some((id, job, done, cursor, assignment)))
                            }
                            .await;
                            let prepared = prepared.map_err(|e| fault(e, context.2))?;
                            messaging
                                .protect_in(
                                    tx,
                                    claim,
                                    (context, prepared),
                                    |(ctx, prepared), tx| {
                                        let prepared = prepared.take();
                                        Box::pin(async move {
                                            let result: Result<()> = async {
                                                if ctx.1 == "changes" {
                                                    ctx.0
                                                        .dispatch_assets_in(
                                                            tx,
                                                            ctx.3
                                                                .ok_or(Error::Unavailable(
                                                                    Failure::AutomationAdmission,
                                                                ))?
                                                                .1,
                                                        )
                                                        .await?;
                                                    return ctx
                                                        .0
                                                        .clear_ingress_failure_in(tx)
                                                        .await;
                                                }
                                                let (id, job, done, cursor, assignment) =
                                                    prepared.ok_or(Error::Malformed)?;
                                                if done {
                                                    return Ok(());
                                                }
                                                match job {
                                                    JobInput::Compliance { ref input } => ctx
                                                        .3
                                                        .ok_or(Error::Unavailable(
                                                            Failure::AutomationAdmission,
                                                        ))?
                                                        .1
                                                        .advance(tx, id, input, cursor)
                                                        .await
                                                        .map_err(Into::into),
                                                    JobInput::AssetQuery { .. } => ctx
                                                        .3
                                                        .ok_or(Error::Unavailable(
                                                            Failure::AutomationAdmission,
                                                        ))?
                                                        .0
                                                        .advance_asset_query_in(
                                                            tx,
                                                            id,
                                                            &crate::transaction::stored(
                                                                serde_json::from_value(
                                                                    crate::transaction::json(&job)?,
                                                                ),
                                                            )?,
                                                            cursor,
                                                        )
                                                        .await
                                                        .map_err(Into::into),
                                                    JobInput::GroupDefinition { ref edit } => {
                                                        ctx.0
                                                            .advance_group_definition_in(
                                                                tx, id, edit, cursor,
                                                            )
                                                            .await
                                                    }
                                                    JobInput::Group { .. } => {
                                                        ctx.0
                                                            .advance_group_job_in(
                                                                tx, id, &job, cursor,
                                                            )
                                                            .await
                                                    }
                                                    JobInput::Scope { scope } => {
                                                        ctx.0
                                                            .advance_scope_job_in(
                                                                tx, id, scope, cursor,
                                                            )
                                                            .await
                                                    }
                                                    JobInput::PolicyEvent { batch } => {
                                                        ctx.0
                                                            .advance_event_in(
                                                                ctx.4.ok_or(Error::Unavailable(
                                                                    Failure::AutomationAdmission,
                                                                ))?,
                                                                tx,
                                                                batch,
                                                            )
                                                            .await
                                                    }
                                                    JobInput::PolicyReconcile { .. } => {
                                                        ctx.0
                                                            .advance_assignment_in(
                                                                tx,
                                                                id,
                                                                assignment
                                                                    .ok_or(Error::Malformed)?,
                                                            )
                                                            .await
                                                    }
                                                }
                                            }
                                            .await;
                                            result.map_err(|e| fault(e, ctx.2))
                                        })
                                    },
                                )
                                .await
                        })
                    },
                )
                .await;
            // Only a confirmed rollback may be followed by a durable terminal
            // rejection. Unknown settlement is retried under the original identity.
            let rejection = attempt
                .fold(
                    |_| Ok(None),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                    |error| {
                        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
                            return Err(Error::Conflict);
                        }
                        eprintln!("{}",serde_json::json!({"event":"mdm_automation_rollback","target":claim.target().entity(),"diagnostic":format!("{error:?}")}));
                        failure
                            .lock()
                            .expect("failure slot")
                            .take()
                            .map(Some)
                            .ok_or(Error::Unavailable(Failure::AutomationStorage))
                    },
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Conflict),
                )
                .map_err(reconcile_error)?;
            let terminal = match rejection {
                Some(Error::Conflict) => Some("superseded"),
                Some(Error::Unavailable(
                    Failure::AssetObjectLimit
                    | Failure::AssetBytesLimit
                    | Failure::AssetSourceLimit,
                )) => Some("capacity_exceeded"),
                Some(ref error) if error.is_not_found() => Some("source_unavailable"),
                Some(Error::Malformed) => Some("invalid_input"),
                Some(Error::Unsupported) => Some("capability_unknown"),
                Some(Error::Forbidden) => Some("permission_denied"),
                Some(error) => return Err(reconcile_error(error)),
                None => return Ok(()),
            };
            let Some(id) =
                jobs::target_job(claim.target().entity()).and_then(|s| Uuid::parse_str(s).ok())
            else {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Transient,
                ));
            };
            self.work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    self.service.tenant,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                    (
                        &self.service,
                        claim,
                        &self.service,
                        self.work_owner(claim.target().entity())?.1,
                        self.work_owner(claim.target().entity())?.2,
                    ),
                    |(service, claim, context, messaging, audit_store), tx| {
                        Box::pin(async move {
                            audit_store.bind_in(tx).await.map_err(PgError::from)?;
                            crate::transaction::lock(tx)
                                .await
                                .map_err(|e| fault(e, &Mutex::new(None)))?;
                            let (job, _, _, _, _) = crate::automation::jobs::read_in(tx, id)
                                .await
                                .map_err(|e| fault(e, &Mutex::new(None)))?;
                            let mut partitions = vec![];
                            if let JobInput::Group { group, .. } = &job {
                                partitions.push(service.groups.partition(&group.to_string())?);
                            }
                            tx.prepare_outbox_partitions(&partitions).await?;
                            messaging
                                .protect_in(
                                    tx,
                                    claim,
                                    (context, audit_store),
                                    |(service, audit_store), tx| {
                                        Box::pin(async move {
                                            if matches!(
                                                crate::automation::jobs::read_in(tx, id)
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)))?
                                                    .0,
                                                JobInput::PolicyEvent { .. }
                                            ) {
                                                return service
                                                    .reject_event_member_in(
                                                        audit_store,
                                                        tx,
                                                        id,
                                                        terminal.unwrap_or("rejected"),
                                                    )
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)));
                                            }
                                            crate::automation::jobs::finish_job_in(
                                                tx,
                                                audit_store,
                                                id,
                                                terminal,
                                            )
                                            .await
                                            .map_err(|e| fault(e, &Mutex::new(None)))?;
                                            if terminal == Some("superseded") {
                                                service
                                                    .retry_superseded_group_in(tx, id)
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)))?;
                                            }
                                            Ok(())
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
                    |error| Err(storage_error(error)),
                    |error| Err(storage_error(error)),
                    |_| {
                        Err(rss_reconcile::Error::new(
                            rss_reconcile::ErrorKind::CommitUnknown,
                        ))
                    },
                    |_| {
                        Err(rss_reconcile::Error::new(
                            rss_reconcile::ErrorKind::CommitUnknown,
                        ))
                    },
                    |error| Err(storage_error(error)),
                )
        })
    }
}

impl Reconciler<rss_reconcile_postgres::PgClaim> for Automation {
    type State = bool;
    fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error>,
    > + Send {
        self.work.observe(claim, control)
    }
    fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        self.work
            .apply_with(claim, control, Some((&self.assets, &self.compliance)))
    }
}
