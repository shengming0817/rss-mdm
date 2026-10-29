/// Event member workers share the Policy initiating runtime.
pub const EVENT_CONCURRENCY: usize = 2;
use super::*;
use rss_reconcile::{ActualState, DesiredState, DurableStore, ReconcileDiff, Reconciler};
use std::sync::Mutex;
#[path = "completion.rs"]
mod completion;

/// Single-step planning execution over the real claims and protected transaction.
/// It owns no Inventory/Compliance services and cannot register a background runner.
pub struct PolicyWork {
    service: Arc<Application>,
    events: Option<Arc<crate::events::Events>>,
    store: rss_reconcile_postgres::PgStore,
}
pub struct Automation {
    pub work: Arc<PolicyWork>,
    concurrency: usize,
}
impl std::ops::Deref for Automation {
    type Target = PolicyWork;
    fn deref(&self) -> &Self::Target {
        &self.work
    }
}
impl PolicyWork {
    pub fn new(
        service: Arc<Application>,
        events: Arc<crate::events::Events>,
        store: rss_reconcile_postgres::PgStore,
    ) -> Arc<Self> {
        Arc::new(Self {
            service,
            events: Some(events),
            store,
        })
    }
    #[cfg(feature = "integration")]
    pub fn management_only(
        service: Arc<Application>,
        store: rss_reconcile_postgres::PgStore,
    ) -> Arc<Self> {
        Arc::new(Self {
            service,
            events: None,
            store,
        })
    }
    fn execution(&self) -> Option<&Arc<rss_mdm_execution_service::policy_events::PolicyEvents>> {
        self.events.as_ref().map(|events| &events.execution)
    }
    fn application(
        &self,
        entity: &str,
    ) -> std::result::Result<&Arc<Application>, rss_reconcile::Error> {
        if entity.starts_with("event:") {
            self.events
                .as_ref()
                .map(|events| &events.application)
                .ok_or_else(|| rss_reconcile::Error::new(rss_reconcile::ErrorKind::Invariant))
        } else {
            Ok(&self.service)
        }
    }
    fn check_scope(
        &self,
        scope: &rss_reconcile::Scope,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        if scope.tenant() != self.service.tenant
            || !matches!(scope.reconciler(), "mdm.policy" | jobs::EVENT_SCOPE)
            || (scope.reconciler() == jobs::EVENT_SCOPE && self.execution().is_none())
        {
            return Err(rss_reconcile::Error::new(
                rss_reconcile::ErrorKind::Invariant,
            ));
        }
        Ok(())
    }
    fn check_claim(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.check_scope(claim.target().scope())?;
        if matches!(claim.target().entity(), "inputs" | "schedules")
            && claim.target().scope().reconciler() == "mdm.policy"
        {
            return Ok(());
        }
        if claim.target().entity().starts_with("event:")
            != (claim.target().scope().reconciler() == jobs::EVENT_SCOPE)
            || jobs::target_job(claim.target().entity())
                .and_then(|id| Uuid::parse_str(id).ok())
                .is_none()
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
        let service = self.application(entity)?;
        Ok((
            &service.runtime,
            &service.reconcile_messaging,
            &service.audit_store,
        ))
    }
}

impl Automation {
    pub fn new(work: Arc<PolicyWork>, concurrency: usize) -> Arc<Self> {
        Arc::new(Self { work, concurrency })
    }
    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-policy-work", Duration::from_secs(20));
        let _ = self.service.automation_task.set(status);
        task.into_registration(move |cancel|async move {
            let cancel = cancel.child_token();
            let force=tokio_util::sync::CancellationToken::new();
            let timer=Timer::new();let control=rss_reconcile::Control::new(&timer,Duration::MAX,&force);
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:self.concurrency,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:crate::worker_wake::RECOVERY,
                initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let event_policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
                concurrency:EVENT_CONCURRENCY,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_millis(20),idle_scan_interval:crate::worker_wake::RECOVERY,initial_backoff:Duration::from_secs(1),max_backoff:Duration::from_secs(30),max_attempts:1000,
            }).map_err(rss_runtime::ShutdownError::new)?;
            let scope=rss_reconcile::Scope::new(self.service.tenant,"mdm.policy").expect("constant domain");
            for entity in ["inputs", "schedules"] {
                self.store.wake(&rss_reconcile::Target::new(scope.clone(),entity).expect("input target"), &control.child(Duration::from_secs(6))).await.map_err(rss_runtime::ShutdownError::new)?;
            }
            let runner=async {rss_reconcile::run_with_notify(self.work.as_ref(),self.as_ref(),&scope,policy,&control,&cancel,signals.automation(),|event| {
                eprintln!("{}",serde_json::json!({"event":"mdm_automation_failure","diagnostic":format!("{event:?}")}));
                self.service.record_runner_failure(event);
            }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)};
            let event_runner=async {
                if self.work.execution().is_none() {cancel.cancelled().await;return Ok(());}
                let scope=rss_reconcile::Scope::new(self.service.tenant,jobs::EVENT_SCOPE).expect("constant domain");
                rss_reconcile::run_with_notify(self.work.as_ref(),self.as_ref(),&scope,event_policy,&control,&cancel,signals.events(),|event| {
                    eprintln!("{}",serde_json::json!({"event":"mdm_policy_event_failure","diagnostic":format!("{event:?}")}));
                    self.service.record_runner_failure(event);
                }).await.map(|_|()).map_err(rss_runtime::ShutdownError::new)
            };
            tokio::pin!(runner, event_runner);
            let stopped = tokio::select! {
                result = &mut runner => { cancel.cancel(); (result, event_runner.await) },
                result = &mut event_runner => { cancel.cancel(); (result, runner.await) },
            };
            stopped.0.and(stopped.1)
        })
    }
}
fn reconcile_error(error: Error) -> rss_reconcile::Error {
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::RollbackFailed => rss_reconcile::ErrorKind::RollbackFailed,
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
impl PolicyWork {
    pub fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            self.check_claim(claim)?;
            control.check()?;
            if matches!(claim.target().entity(), "inputs" | "schedules") {
                return self.observe_inputs(claim, control).await;
            }
            let failure = Mutex::new(None);
            let result = self
                .work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    self.service.tenant,
                    deadline(),
                    (
                        self.application(claim.target().entity())?,
                        claim.target().entity(),
                        &failure,
                    ),
                    |ctx, tx| {
                        Box::pin(async move {
                            let result = match jobs::target_job(ctx.1)
                                .and_then(|s| Uuid::parse_str(s).ok())
                            {
                                Some(id) => {
                                    jobs::read_in(tx, id).await.map(|(_, done, _, _, _)| !done)
                                }
                                None => Err(Error::Malformed.into()),
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
                    |_| Err(Error::RollbackFailed),
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
        self.apply_with(claim, control)
    }
    fn apply_with<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        Box::pin(async move {
            self.check_claim(claim)?;
            if matches!(claim.target().entity(), "inputs" | "schedules") {
                return self.apply_inputs(claim, control).await;
            }
            let failure = Mutex::new(None);
            let attempt =
                self.work_owner(claim.target().entity())?
                    .0
                    .local_tx_with_context(
                        self.service.tenant,
                        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                            control.remaining(),
                        ),
                        (
                            self.application(claim.target().entity())?,
                            claim,
                            (
                                self.application(claim.target().entity())?,
                                claim.target().entity(),
                                &failure,
                                self.execution(),
                            ),
                            self.work_owner(claim.target().entity())?.1,
                            self.work_owner(claim.target().entity())?.2,
                        ),
                        |(service, claim, context, messaging, audit_store), tx| {
                            Box::pin(async move {
                                audit_store.bind_in(tx).await.map_err(PgError::from)?;
                                let prepared: Result<_> = async {
                                    let id = Uuid::parse_str(
                                        jobs::target_job(context.1).ok_or(Error::Malformed)?,
                                    )
                                    .map_err(|_| Error::Malformed)?;
                                    let (job, done, _, cursor, _) =
                                        crate::worker::jobs::read_in(tx, id).await?;
                                    if !matches!(job,Work::Lifecycle{..}|Work::PolicyEvent{..}) {}
                                    let assignment = if done {
                                        None
                                    } else if let Work::PolicyReconcile { policy } = &job {
                                        Some(
                                            service
                                                .prepare_assignment_in(tx, *policy, cursor.clone())
                                                .await?,
                                        )
                                    } else {
                                        tx.prepare_outbox_partitions(&[]).await?;
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
                                                    let (id, job, done, cursor, assignment) =
                                                        prepared.ok_or(Error::Malformed)?;
                                                    if done {
                                                        return Ok(());
                                                    }
                                                    match job {
                                                        ref input @ Work::Lifecycle{..}=>ctx.0.advance_lifecycle_work_in(tx,id,input).await,
                                                        Work::PolicyScope { scope, .. } => crate::management::scope_changes::advance_in(tx,&ctx.0.audit_store,id,scope,cursor).await,
                                                        Work::PolicyEvent { batch } => ctx
                                                            .0
                                                            .advance_event_in(
                                                                ctx.3.ok_or(Error::Unavailable(
                                                                    Failure::AutomationAdmission,
                                                                ))?,
                                                                tx,
                                                                batch,
                                                            )
                                                            .await,
                                                        Work::PolicyReconcile { .. } => {
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
                        let reason = failure.lock().expect("failure slot").take();
                        eprintln!("{}",serde_json::json!({"event":"mdm_automation_rollback","target":claim.target().entity(),"diagnostic":format!("{error:?}"),"reason":reason}));
                        reason.map(Some)
                            .ok_or(Error::Unavailable(Failure::AutomationStorage))
                    },
                    |_| Err(Error::RollbackFailed),
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
                    |(_service, claim, context, messaging, audit_store), tx| {
                        Box::pin(async move {
                            audit_store.bind_in(tx).await.map_err(PgError::from)?;

                            tx.prepare_outbox_partitions(&[]).await?;
                            messaging
                                .protect_in(
                                    tx,
                                    claim,
                                    (context, audit_store),
                                    |(service, audit_store), tx| {
                                        Box::pin(async move {
                                            if matches!(
                                                crate::worker::jobs::read_in(tx, id)
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)))?
                                                    .0,
                                                Work::PolicyEvent { .. }
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
                                            crate::worker::jobs::finish_job_in(
                                                tx,
                                                audit_store,
                                                id,
                                                terminal,
                                            )
                                            .await
                                            .map_err(|e| fault(e, &Mutex::new(None)))?;
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
                            rss_reconcile::ErrorKind::RollbackFailed,
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
        self.work.apply_with(claim, control)
    }
}

impl PolicyWork {
    async fn observe_inputs<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error> {
        let now = self.service.clock.unix_seconds().map_err(reconcile_error)?;
        let schedules = claim.target().entity() == "schedules";
        let pending = self
            .service
            .runtime
            .local_tx_with_context(
                self.service.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (),
                |_, tx| {
                    Box::pin(async move {
                        if schedules {
                            rss_mdm_policy_postgres::schedules::scan_due_in(tx, now).await
                        } else {
                            rss_mdm_policy_postgres::work::inputs_pending_in(tx).await
                        }
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(storage_error(e)),
                |e| Err(storage_error(e)),
                |_| Err(reconcile_error(Error::RollbackFailed)),
                |_| Err(reconcile_error(Error::CommitUnknown)),
                |e| Err(storage_error(e)),
            )?;
        Ok(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        ))
    }
    async fn apply_inputs<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<(), rss_reconcile::Error> {
        self.service
            .runtime
            .local_tx_with_context(
                self.service.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.service, claim),
                |(s, claim), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;

                        s.reconcile_messaging
                            .protect_in(
                                tx,
                                claim,
                                (s, claim.target().entity()),
                                |(s, entity), tx| {
                                    Box::pin(async move {
                                        let result = if *entity == "schedules" {
                                            s.advance_lifecycle_schedules_in(tx).await
                                        } else {
                                            jobs::forward_jobs_in(&s.reconcile_messaging, tx).await
                                        };
                                        result.map_err(|e| fault(e, &Mutex::new(None)))
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
                |e| Err(storage_error(e)),
                |e| Err(storage_error(e)),
                |_| Err(reconcile_error(Error::RollbackFailed)),
                |_| Err(reconcile_error(Error::CommitUnknown)),
                |e| Err(storage_error(e)),
            )
    }
}
