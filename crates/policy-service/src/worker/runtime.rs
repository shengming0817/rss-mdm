use super::*;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use rss_reconcile_postgres::ProtectedStep;
use std::sync::Mutex;
#[path = "completion.rs"]
mod completion;
#[path = "configuration.rs"]
mod configuration;

/// Single-step planning execution over the real claims and protected transaction.
/// It owns no Inventory/Compliance services and cannot register a background runner.
pub struct PolicyWork {
    read_pool: sqlx::PgPool,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    service: Arc<Application>,
    events: Option<Arc<crate::events::Events>>,
    store: rss_mdm_work_page::scheduler::Scheduler,
}
pub struct Automation {
    pub work: Arc<PolicyWork>,
}
impl std::ops::Deref for Automation {
    type Target = PolicyWork;
    fn deref(&self) -> &Self::Target {
        &self.work
    }
}
impl PolicyWork {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.service.profile()
    }
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        service: Arc<Application>,
        events: Arc<crate::events::Events>,
        store: rss_mdm_work_page::scheduler::Scheduler,
    ) -> Arc<Self> {
        Arc::new(Self {
            read_pool,
            storage,
            service,
            events: Some(events),
            store,
        })
    }

    fn member_owners(&self) -> Option<&crate::events::participants::MemberOwners> {
        self.events.as_ref().map(|events| events.members.as_ref())
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
        if ![
            jobs::domain(self.profile()),
            jobs::event_domain(self.profile()),
        ]
        .contains(&scope.reconciler())
            || (scope.reconciler() == jobs::event_domain(self.profile())
                && self.member_owners().is_none())
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
        if (claim.target().entity() == "schedules"
            || (self.service.configuration.is_some()
                && crate::configuration::recovery::owns_entity(claim.target().entity())))
            && claim.target().scope().reconciler() == jobs::domain(self.profile())
        {
            return Ok(());
        }
        if claim.target().entity().starts_with("event:")
            != (claim.target().scope().reconciler() == jobs::event_domain(self.profile()))
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
    pub fn new(work: Arc<PolicyWork>) -> Arc<Self> {
        Arc::new(Self { work })
    }
    pub fn registration(
        self: Arc<Self>,
        event_policy: rss_reconcile::Policy,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        signals: Arc<crate::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare("mdm-policy-work", drain);
        let _ = self.service.automation_task.set(status);
        task.into_registration(move |cancel| async move {
            let cancel = cancel.child_token();
            let runner = self
                .work
                .run_domain(false, policy, &cancel, signals.automation());
            let events = self
                .work
                .run_domain(true, event_policy, &cancel, signals.events());
            tokio::pin!(runner, events);
            let stopped = tokio::select! {
                result = &mut runner => { cancel.cancel(); (result, events.await) },
                result = &mut events => { cancel.cancel(); (result, runner.await) },
            };
            stopped.0.and(stopped.1)
        })
    }
}
fn reconcile_error(error: Error) -> rss_reconcile::Error {
    let reason = match &error {
        Error::Unavailable(Failure::NativeInputIntegrity) => Some("native_input_integrity"),
        Error::Unavailable(Failure::CommandInvariant) => Some("command_invariant"),
        _ => None,
    };
    if let Some(reason) = reason {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_policy_integrity_failure","reason":reason})
        );
    }
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::RollbackFailed => rss_reconcile::ErrorKind::RollbackFailed,
        Error::Conflict | Error::ReadConflict => rss_reconcile::ErrorKind::Fenced,
        Error::Unavailable(Failure::RequestDeadline) => rss_reconcile::ErrorKind::Deadline,
        Error::Unavailable(Failure::NativeInputIntegrity | Failure::CommandInvariant)
        | Error::Unsupported
        | Error::Malformed
        | Error::Forbidden
        | Error::Unauthorized => rss_reconcile::ErrorKind::Permanent,
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
enum JobRejection {
    Request(Error),
    LockUnavailable,
}
impl JobRejection {
    fn request(self) -> Option<Error> {
        match self {
            Self::Request(error) => Some(error),
            Self::LockUnavailable => None,
        }
    }
}
fn fault(error: Fault, reason: &Mutex<Option<JobRejection>>) -> PgError {
    match error {
        Fault::Request(error) => {
            *reason.lock().expect("failure slot") = Some(JobRejection::Request(error));
            sqlx::Error::Protocol("asset automation rejected".into()).into()
        }
        Fault::Storage(error) => error,
        Fault::Sql(error) => {
            if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("55P03") {
                *reason.lock().expect("failure slot") = Some(JobRejection::LockUnavailable);
            }
            error.into()
        }
    }
}
impl PolicyWork {
    pub fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error>,
    > + Send {
        let profile = self.profile();

        Box::pin(async move {
            let binding = self.binding_for(claim, control).await?;
            self.check_claim(claim)?;
            control.check()?;
            if crate::configuration::recovery::owns_entity(claim.target().entity()) {
                return self.observe_configuration(claim, control).await;
            }
            if claim.target().entity() == "schedules" {
                return self.observe_schedules(claim, control).await;
            }
            let failure = Mutex::new(None);
            let result = self
                .work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    binding,
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
                                Some(id) => jobs::read_in(profile, tx, id)
                                    .await
                                    .map(|(_, done, _, _, _)| !done),
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
                            .and_then(JobRejection::request)
                            .unwrap_or(Error::Unavailable(Failure::AutomationStorage)))
                    },
                    |_| Err(Error::RollbackFailed),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                );
            Ok(ReconcileStep::Ready(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(result.map_err(reconcile_error)?),
            )))
        })
    }
    pub fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<()>, rss_reconcile::Error>,
    > + Send {
        self.apply_with(claim, control)
    }
    fn apply_with<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<()>, rss_reconcile::Error>,
    > + Send {
        let profile = self.profile();

        Box::pin(async move {
            let binding = self.binding_for(claim, control).await?;
            self.check_claim(claim)?;
            if crate::configuration::recovery::owns_entity(claim.target().entity()) {
                return self.apply_configuration(claim, control).await;
            }
            if claim.target().entity() == "schedules" {
                return self.apply_schedules(claim, control).await;
            }
            let failure = Mutex::new(None);
            let attempt = self
                .work_owner(claim.target().entity())?
                .0
                .local_tx_with_context(
                    binding,
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
                            self.member_owners(),
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
                                    crate::worker::jobs::read_in(profile, tx, id).await?;
                                let assignment = if done {
                                    None
                                } else if let Work::PolicyReconcile { policy } = &job {
                                    Some(service.prepare_assignment_in(tx, *policy, cursor).await?)
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
                                            let result: Result<ProtectedStep<()>> = async {
                                                let (id, job, done, cursor, assignment) =
                                                    prepared.ok_or(Error::Malformed)?;
                                                if done {
                                                    return Ok(ProtectedStep::Ready(()));
                                                }
                                                rss_mdm_policy_postgres::work::started_in(
                                                    profile, tx, id,
                                                )
                                                .await?;
                                                match job {
                                                    ref input @ Work::Lifecycle { .. } => {
                                                        ctx.0
                                                            .advance_lifecycle_work_in(
                                                                binding, tx, id, input,
                                                            )
                                                            .await
                                                    }
                                                    Work::RetirementPage { policy, version, occurrence, .. } => {
                                                        match ctx.0.retirement_policy_in(tx, policy, version).await? {
                                                            Some(p) => ctx.0.advance_retirement_page_in(binding, tx, id, &p, occurrence, cursor).await,
                                                            None => ctx.0.finish_retirement_in(binding, tx, id, serde_json::json!({"state":"superseded"})).await.map(ProtectedStep::Ready),
                                                        }
                                                    }
                                                    Work::RetirementRefresh { policy, version, page } => {
                                                        match ctx.0.retirement_policy_in(tx, policy, version).await? {
                                                            Some(p) => ctx.0.refresh_retirement_in(binding, tx, id, &p, Some(page)).await,
                                                            None => ctx.0.finish_retirement_in(binding, tx, id, serde_json::json!({"state":"superseded"})).await,
                                                        }.map(ProtectedStep::Ready)
                                                    }
                                                    Work::PolicyEvent { batch } => {
                                                        ctx.0
                                                            .advance_event_in(
                                                                binding,
                                                                ctx.3.ok_or(Error::Unavailable(
                                                                    Failure::AutomationAdmission,
                                                                ))?,
                                                                tx,
                                                                batch,
                                                            )
                                                            .await.map(ProtectedStep::Ready)
                                                    }
                                                    Work::PolicyReconcile { .. } => {
                                                        ctx.0
                                                            .advance_assignment_in(
                                                                binding,
                                                                tx,
                                                                id,
                                                                assignment
                                                                    .ok_or(Error::Malformed)?,
                                                            )
                                                            .await.map(ProtectedStep::Ready)
                                                    }
                                                }
                                            }
                                            .await;
                                            result
                                                .map_err(|e| fault(e, ctx.2))
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
                    |step| Ok(Ok(step)),
                    |_| Err(Error::Unavailable(Failure::AutomationStorage)),
                    |error| {
                        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
                            return Err(Error::Conflict);
                        }
                        let reason = match failure.lock().expect("failure slot").take() {
                            Some(JobRejection::LockUnavailable) => {
                                return Ok(Ok(ReconcileStep::Deferred(Duration::from_millis(50))));
                            }
                            Some(JobRejection::Request(error)) => Some(error),
                            None => None,
                        };
                        eprintln!("{}",serde_json::json!({"event":"mdm_automation_rollback","target":claim.target().entity(),"diagnostic":format!("{error:?}"),"reason":reason}));
                        reason.map(Err)
                            .ok_or(Error::Unavailable(Failure::AutomationStorage))
                    },
                    |_| Err(Error::RollbackFailed),
                    |_| Err(Error::CommitUnknown),
                    |_| Err(Error::Conflict),
                )
                .map_err(reconcile_error)?;
            let terminal = match rejection {
                Err(Error::Conflict) => Some("superseded"),
                Err(Error::Unavailable(
                    Failure::AssetObjectLimit
                    | Failure::AssetBytesLimit
                    | Failure::AssetSourceLimit,
                )) => Some("capacity_exceeded"),
                Err(ref error) if error.is_not_found() => Some("source_unavailable"),
                Err(Error::Malformed) => Some("invalid_input"),
                Err(Error::Unsupported) => Some("capability_unknown"),
                Err(Error::Forbidden) => Some("permission_denied"),
                Err(error) => return Err(reconcile_error(error)),
                Ok(step) => return Ok(step),
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
                    binding,
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
                                                crate::worker::jobs::read_in(profile, tx, id)
                                                    .await
                                                    .map_err(|e| fault(e, &Mutex::new(None)))?
                                                    .0,
                                                Work::PolicyEvent { .. }
                                            ) {
                                                return service
                                                    .reject_event_member_in(
                                                        binding,
                                                        audit_store,
                                                        tx,
                                                        id,
                                                        terminal.unwrap_or("rejected"),
                                                    )
                                                    .await
                                                    .map(ProtectedStep::Ready)
                                                    .map_err(|e| fault(e, &Mutex::new(None)));
                                            }
                                            crate::worker::jobs::finish_job_in(
                                                binding,
                                                profile,
                                                tx,
                                                audit_store,
                                                id,
                                                terminal,
                                            )
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
        Output = std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error>,
    > + Send {
        self.work.observe(claim, control)
    }
    fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<()>, rss_reconcile::Error>,
    > + Send {
        self.work.apply_with(claim, control)
    }
}

impl PolicyWork {
    async fn observe_schedules<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error> {
        let binding = self.binding_for(claim, control).await?;
        let profile = self.profile();

        let now = self.service.clock.unix_seconds().map_err(reconcile_error)?;

        let pending = self
            .service
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (),
                |_, tx| {
                    Box::pin(async move {
                        rss_mdm_policy_postgres::schedules::scan_due_in(profile, tx, now).await
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
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(false),
            ActualState::present(pending),
        )))
    }
    async fn apply_schedules<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, rss_reconcile::Error> {
        let binding = self.binding_for(claim, control).await?;
        self.service
            .runtime
            .local_tx_with_context(
                binding,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (&self.service, claim),
                move |(s, claim), tx| {
                    Box::pin(async move {
                        s.audit_store.bind_in(tx).await.map_err(PgError::from)?;

                        s.reconcile_messaging
                            .protect_in(tx, claim, s, move |s, tx| {
                                Box::pin(async move {
                                    let result = s.advance_lifecycle_schedules_in(tx).await;
                                    result
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
                |e| Err(storage_error(e)),
                |e| Err(storage_error(e)),
                |_| Err(reconcile_error(Error::RollbackFailed)),
                |_| Err(reconcile_error(Error::CommitUnknown)),
                |e| Err(storage_error(e)),
            )
    }
}

impl PolicyWork {
    async fn binding_for<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<
        rss_transactional_messaging::fence::ExecutionBinding,
        rss_reconcile::Error,
    > {
        control.check()?;
        let query = if crate::configuration::recovery::owns_entity(claim.target().entity()) {
            "SELECT mdm_planning.configuration_work_epoch($1::uuid,$2)"
        } else {
            match self.profile() {
                rss_mdm_install_support::StorageProfile::Mdm => {
                    "SELECT mdm_policy.policy_work_epoch($1::uuid,$2)"
                }
                rss_mdm_install_support::StorageProfile::Da => {
                    "SELECT rss_da.policy_work_epoch($1::uuid,$2)"
                }
            }
        };
        let tenant = claim.target().scope().tenant();
        let epoch: i64 = sqlx::query_scalar(query)
            .bind(tenant.to_string())
            .bind(claim.target().entity())
            .fetch_one(&self.read_pool)
            .await
            .map_err(|_| reconcile_error(Error::Unavailable(Failure::PolicyStorage)))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| reconcile_error(Error::Malformed))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
    async fn run_domain(
        self: &Arc<Self>,
        events: bool,
        policy: rss_reconcile::Policy,
        cancel: &tokio_util::sync::CancellationToken,
        notify: &tokio::sync::Notify,
    ) -> std::result::Result<(), rss_runtime::ShutdownError> {
        if events && self.member_owners().is_none() {
            cancel.cancelled().await;
            return Ok(());
        }
        let service = self.as_ref();
        let owner = self.clone();
        let budget = rss_mdm_work_page::capacity::Capacity::new(
            std::num::NonZeroUsize::new(policy.concurrency()).expect("validated policy"),
        );
        let domain = if events {
            jobs::event_domain(self.profile())
        } else {
            jobs::domain(self.profile())
        };
        let query = match self.profile() {
            rss_mdm_install_support::StorageProfile::Mdm => {
                "SELECT tenant_id FROM (SELECT tenant_id FROM mdm_policy.policy_work_scopes($1) UNION SELECT tenant_id FROM mdm_planning.configuration_work_scopes($1)) work ORDER BY tenant_id LIMIT 32"
            }
            rss_mdm_install_support::StorageProfile::Da => {
                "SELECT tenant_id FROM rss_da.policy_work_scopes($1)"
            }
        };
        rss_mdm_work_page::reconcile::run(
            &budget,
            policy,
            cancel,
            notify,
            |after| async move {
                let fetch = sqlx::query_scalar(query)
                    .bind(after)
                    .fetch_all(&service.read_pool);
                let discovered = tokio::time::timeout(Duration::from_secs(5), fetch)
                    .await
                    .map_err(|_| rss_reconcile::ErrorKind::Deadline)
                    .and_then(|page| page.map_err(|error| crate::discovery::classify(&error)));
                service.service.record_discovery(
                    domain,
                    discovered.as_ref().map(|_| ()).map_err(|kind| *kind),
                );
                discovered
            },
            move |tenant, slots, stop| {
                let owner = owner.clone();
                async move {
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(|_| {
                            rss_reconcile::Error::new(rss_reconcile::ErrorKind::InvalidInput)
                        })?;
                    let scope = rss_reconcile::Scope::new(tenant, domain).expect("constant domain");
                    rss_mdm_work_page::reconcile::batch(
                        (owner.as_ref(), owner.as_ref()),
                        slots,
                        &scope,
                        policy,
                        &stop,
                        |event| owner.service.record_runner_failure(event),
                    )
                    .await
                }
            },
        )
        .await
        .map_err(rss_runtime::ShutdownError::new)
    }
    pub async fn relay_page(
        &self,
        after: Option<Uuid>,
    ) -> std::result::Result<
        Vec<(Uuid, i64, rss_mdm_recovery_observation::RelayWork)>,
        rss_reconcile::ErrorKind,
    > {
        if self.service.configuration.is_none() {
            return Ok(Vec::new());
        }
        let page = rss_mdm_recovery_observation::RelayPage::begin(
            &self.service.automation_observation,
            crate::worker::jobs::domain(self.profile()),
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), sqlx::query_as(
            "SELECT tenant_id,expected_epoch,claimable,quarantined FROM mdm_planning.configuration_relay_scopes($1)",
        )
        .bind(after)
        .fetch_all(&self.read_pool))
        .await.map_err(|_|rss_reconcile::ErrorKind::Deadline).and_then(|rows|rows.map_err(|error|crate::discovery::classify(&error)));
        self.service
            .automation_observation
            .lock()
            .expect("relay observations")
            .relay_round(
                crate::worker::jobs::domain(self.profile()),
                result.as_ref().map(|_| ()).map_err(|kind| *kind),
                self.service.clock.unix_seconds().ok(),
            );
        result.map(|rows| page.bindings(rows))
    }
    pub fn relay_scope(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Option<rss_mdm_recovery_observation::RelayScope<'_>> {
        self.service.configuration.as_ref()?;
        let check = rss_mdm_recovery_observation::RelayScope::new(
            &self.service.automation_observation,
            crate::worker::jobs::domain(self.profile()),
            binding,
            self.service.clock.unix_seconds().ok(),
        );
        Some(check)
    }
}

impl Reconciler<rss_reconcile_postgres::PgClaim> for PolicyWork {
    type State = bool;
    async fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error> {
        PolicyWork::observe(self, claim, control).await
    }
    async fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        diff: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<ReconcileStep<()>, rss_reconcile::Error> {
        PolicyWork::apply(self, claim, diff, control).await
    }
}

#[cfg(test)]
mod error_regression {
    use super::*;
    #[test]
    fn configuration_corruption_is_permanent_and_settlement_remains_uncertain() {
        use rss_reconcile::ErrorKind as K;
        for failure in [Failure::NativeInputIntegrity, Failure::CommandInvariant] {
            assert_eq!(
                reconcile_error(Error::Unavailable(failure)).kind(),
                K::Permanent
            );
        }
        assert_eq!(
            reconcile_error(Error::Unavailable(Failure::RequestDeadline)).kind(),
            K::Deadline
        );
        assert_eq!(
            reconcile_error(Error::CommitUnknown).kind(),
            K::CommitUnknown
        );
        assert_eq!(
            reconcile_error(Error::RollbackFailed).kind(),
            K::RollbackFailed
        );
    }
}
