use super::*;
use rss_mdm_audit_integration::Fact;
use rss_mdm_audit_integration::activity::ActivityDelivery;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use sqlx::Row;
use std::sync::Mutex;

fn failure(error: Error) -> rss_reconcile::Error {
    if matches!(error, Error::Unavailable(Failure::NativeInputIntegrity)) {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_registration_installation_recovery_integrity_failure","reason":"native_input_integrity"})
        );
    }
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::RollbackFailed => rss_reconcile::ErrorKind::RollbackFailed,
        Error::Unavailable(Failure::CommandInvariant | Failure::NativeInputIntegrity) => {
            rss_reconcile::ErrorKind::Permanent
        }
        Error::Conflict => rss_reconcile::ErrorKind::Fenced,
        Error::Malformed | Error::Forbidden | Error::Unauthorized => {
            rss_reconcile::ErrorKind::Permanent
        }
        _ => rss_reconcile::ErrorKind::Transient,
    })
}
fn diagnostic(event: rss_reconcile::Observation) {
    let (phase, error, target) = match event {
        rss_reconcile::Observation::Deferred { .. } => return,
        rss_reconcile::Observation::AttemptFailed {
            target,
            stage,
            error,
        } => (
            format!("{stage:?}"),
            error,
            Some(target.entity().to_owned()),
        ),
        rss_reconcile::Observation::ScanFailed { error, .. } => ("scan".to_owned(), error, None),
    };
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_registration_installation_recovery_failure","phase":phase,"target":target,"reason":format!("{:?}",error.kind())})
    );
}
impl Service {
    /// Register the durable input scan while resources are admitted, before exposing a runner.
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        signals: Arc<tokio::sync::Notify>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-registration-installation-recovery", drain);
        self.readiness.bind(status);
        task.into_registration(move |cancel| async move {
            self.run_worker(policy, &cancel, &signals).await
        })
    }
    pub async fn run_worker(
        self: &Arc<Self>,
        policy: rss_reconcile::Policy,
        cancel: &tokio_util::sync::CancellationToken,
        signals: &tokio::sync::Notify,
    ) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let service = self.as_ref();
        let owner = self.clone();
        let budget = self.worker_budget.clone();
        let result = rss_mdm_work_page::reconcile::run(
            &budget,
            policy,
            cancel,
            signals,
            |after| async move {
                let discovered = tokio::time::timeout(
                    Duration::from_secs(5),
                    sqlx::query_scalar(
                        "SELECT tenant_id FROM mdm_registration_tasks.native_work_scopes($1)",
                    )
                    .bind(after)
                    .fetch_all(&service.read_pool),
                )
                .await
                .map_err(|_| rss_reconcile::ErrorKind::Deadline)
                .and_then(|page| page.map_err(|error| crate::discovery::classify(&error)));
                service
                    .readiness
                    .discovery(discovered.as_ref().map(|_| ()).map_err(|kind| *kind));
                discovered
            },
            move |tenant, slots, stop| {
                let owner = owner.clone();
                async move {
                    let tenant = TenantId::parse(&tenant.to_string()).map_err(|_| {
                        rss_reconcile::Error::new(rss_reconcile::ErrorKind::InvalidInput)
                    })?;
                    let scope = recovery_scope(tenant);
                    rss_mdm_work_page::reconcile::batch(
                        (&owner.recovery_store(), owner.as_ref()),
                        slots,
                        &scope,
                        policy,
                        &stop,
                        |event| {
                            owner.readiness.observe(&event);
                            diagnostic(event);
                        },
                    )
                    .await
                }
            },
        )
        .await
        .map_err(rss_runtime::ShutdownError::new);
        self.readiness.stop();
        result
    }

    pub async fn project_native_in(
        tx: &mut PgTransaction<'_>,
        dispatch: &rss_mdm_work_page::relay::Dispatch<'_>,
        store: &rss_mdm_audit_integration::AuditStore,
        protection: &rss_mdm_native_protection::Protector,
    ) -> Result<bool> {
        use rss_mdm_audit_integration::operation::OperationOwner;
        let id = dispatch.id;
        let audit = rss_mdm_audit_integration::command_transaction::dispatch_audit(
            rss_mdm_audit_integration::StorageProfile::Mdm,
            dispatch.binding,
            OperationOwner::Installation,
            id,
            "command-dispatch",
        );
        store.bind_in(tx).await?;
        if !dispatch.accept_in(tx, "UPDATE mdm_registration_tasks.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND NOT gateway_accepted").await? {
            audit.finalize(None);
            return Ok(false);
        }
        let operation = match storage::load(tx, protection, id).await {
            Err(crate::installation::transaction::Fault::Request(Error::Unavailable(
                Failure::CommandInvariant | Failure::NativeInputIntegrity,
            ))) => return Ok(false),
            other => other?,
        };
        let stored = dispatch
            .native_status_in(tx, operation.scope.device().as_uuid())
            .await?;
        let Some(status) = stored.and_then(|value| dc::Status::restore(&value).ok()) else {
            return Ok(false);
        };
        let mut activity = crate::installation::timeline::native_activity(
            &operation,
            status,
            rss_mdm_audit_integration::activity::ActivityPhase::Dispatched,
        );
        activity.delivery = Some(ActivityDelivery::Dispatched);
        let fact = Fact::business(
            &audit,
            OperationOwner::Installation,
            &format!("command:{id}:dispatch"),
            200,
            "success",
            None,
        )?
        .with_activity(&activity)?;
        store.append_in(tx, &fact).await?;
        if matches!(
            &operation.request.task,
            crate::installation::Task::Windows { .. }
        ) {
            crate::installation::worker_wake::notify_in(
                tx,
                crate::installation::worker_wake::Work::WindowsPush,
            )
            .await?;
        }
        crate::installation::worker_wake::notify_in(
            tx,
            crate::installation::worker_wake::Work::Apple,
        )
        .await?;
        audit.finalize(None);
        Ok(true)
    }
}
async fn device(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<Option<rss_mdm_agent_wire::DeviceId>> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(device)=$2").bind(tenant).bind(entity).fetch_optional(c).await.and_then(|id| id.map(crate::database::device_id).transpose())})).await?)
}

pub(crate) async fn resources_in(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<rss_reconcile::ResourceSet> {
    Ok(match device(tx, entity).await? {
        Some(device) => crate::lifecycle::resources::device(
            tx.tenant_id(),
            &device,
            crate::lifecycle::resources::Work::Exclusive,
        ),
        None => rss_reconcile::ResourceSet::empty(tx.tenant_id()),
    })
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, entity: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_registration_tasks.device_recovery WHERE tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(device)=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM mdm_registration_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(o.device)=$2 AND (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device))) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_registration_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(a.device)=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
            .bind(tenant).bind(entity).bind(messaging_domain().as_str().to_owned()).fetch_one(c).await
    })).await?)
}
pub(crate) enum PreparedRecovery {
    Empty,

    Device(rss_mdm_agent_wire::DeviceId),
}
/// Discover only this bounded operation under existing owner fences. No effect precedes claim validation.
/// None is normal endpoint contention; a prepared value retains its business locks for apply.
pub(crate) async fn prepare(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    audit: &RequestAudit,
) -> Result<Option<PreparedRecovery>> {
    let Some(device) = device(tx, entity).await? else {
        return Ok(Some(PreparedRecovery::Empty));
    };
    if !try_lock_device(tx, &device).await? {
        return Ok(None);
    }
    crate::installation::transaction::prepare_audit_in(
        &service.transactions.audit_store,
        tx,
        audit,
        &[],
    )
    .await?;
    Ok(Some(PreparedRecovery::Device(device)))
}
pub(crate) async fn apply_prepared(
    service: &Service,
    tx: &mut PgTransaction<'_>,
    prepared: PreparedRecovery,
    audit: &RequestAudit,
) -> Result<bool> {
    match prepared {
        PreparedRecovery::Empty => Ok(false),
        PreparedRecovery::Device(name) => {
            service
                .transactions
                .recover_bootstrap_in(tx, &name, audit)
                .await?;
            service
                .transactions
                .cleanup_bootstrap_in(tx, &name, audit)
                .await?;
            let tenant = tx.tenant_id().to_string();
            let key = name;
            let registration =
                storage::current_registration(tx, &name, crate::Purpose::Primary).await;
            if registration.is_ok() {
                crate::command_authority::resolve_in(&service.transactions.store, tx, &name)
                    .await?;
            }
            let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT CAST(a.command_device AS text), a.generation, a.epoch, CASE WHEN r.authority_epoch = a.epoch THEN r.recovery_after END AS recovery_after FROM mdm_access.command_authorities AS a LEFT JOIN mdm_registration_tasks.device_recovery AS r USING (tenant_id, device) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = $2 FOR UPDATE OF a").bind(tenant).bind(key.into_uuid()).fetch_one(c).await})).await?;
            let scope = dc::Scope::new(
                tx.tenant_id(),
                stored(dc::DeviceId::parse(
                    &row.try_get::<String, _>("command_device")?,
                ))?,
            );
            let after = row
                .try_get::<Option<String>, _>("recovery_after")?
                .map(|s| stored(dc::CommandId::parse(&s)))
                .transpose()?;
            let candidates =
                command_candidates_in(tx, scope, &name, after.as_ref(), service.recovery_batch)
                    .await?;
            let ids = candidates
                .operations
                .iter()
                .map(|(id, _)| dc::CommandId::parse(&id.to_string()))
                .collect::<std::result::Result<Vec<_>, _>>();
            let ids = stored(ids)?;
            let page = stored(dc::ExactCommandIds::new(&ids))?;
            let mut commands = service
                .transactions
                .store
                .recover_exact(tx, scope, page)
                .await?
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            // Registration can cancel the page before its originally live operations are reauthorized.
            let mut active: Vec<_> = commands
                .iter_mut()
                .filter(|c| !c.status().is_terminal())
                .collect();
            if matches!(registration, Err(Fault::Request(Error::Conflict))) {
                for command in &mut active {
                    let transition = service
                        .transactions
                        .store
                        .cancel(tx, scope, command.spec().id(), command.spec().coordinate())
                        .await?;
                    if transition.outcome == dc::Outcome::OutOfOrder {
                        return Err(Error::Conflict.into());
                    }
                    **command = transition.command;
                }
            } else {
                registration?;
            }
            for command in active {
                let operation = storage::load(
                    tx,
                    &service.transactions.protection,
                    stored(Uuid::parse_str(command.spec().id().as_str()))?,
                )
                .await?;
                let _now = storage::now(tx).await?;
                if !storage::authority_valid(service.transactions.materials.clone(), tx, &operation)
                    .await?
                    && !command.status().is_terminal()
                {
                    let transition = service
                        .transactions
                        .store
                        .cancel(tx, scope, command.spec().id(), command.spec().coordinate())
                        .await?;
                    if transition.outcome == dc::Outcome::OutOfOrder {
                        return Err(Error::Conflict.into());
                    }
                    *command = transition.command;
                }
            }
            for ((id, previous_version), command) in candidates.operations.into_iter().zip(commands)
            {
                let operation = storage::load(tx, &service.transactions.protection, id).await?;
                if operation.scope != command.spec().scope()
                    || operation.command_id()? != *command.spec().id()
                {
                    return Err(Error::Unavailable(Failure::CommandInvariant).into());
                }
                if command.version() == previous_version {
                    continue;
                }
                if command.status().is_terminal() {
                    crate::installation::wake::wake_native_in(
                        &service.transactions.reconcile_messaging,
                        tx,
                        &operation.device,
                    )
                    .await?;
                }
                let fact_audit = audit.transaction_copy();
                fact_audit.identify_service("command-recovery");
                fact_audit.owned_operation(
                    rss_mdm_audit_integration::operation::OperationOwner::Installation,
                    id,
                    "command_reconcile",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                fact_audit.target_device(&operation.device);
                let fact = Fact::business(&fact_audit, rss_mdm_audit_integration::operation::OperationOwner::Installation, &format!("command:{id}:recover:{}", command.version()), 200, "success", None)?
                    .with_details(serde_json::json!({"previousVersion":previous_version,"after":service::status(command.status()),"version":command.version()}))?
                    .with_activity(&crate::installation::timeline::native_activity(&operation, command.status(), rss_mdm_audit_integration::activity::ActivityPhase::Reconciled))?;
                fact_audit.finalize(None);
                service
                    .transactions
                    .audit_store
                    .append_in(tx, &fact)
                    .await?;
                let tenant = tx.tenant_id().to_string();
                let version = command.version();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("UPDATE mdm_registration_tasks.operations SET observed_command_version=$3 WHERE tenant_id=$1::uuid AND id=$2")
                        .bind(tenant).bind(id).bind(version).execute(c).await?;
                    Ok(())
                })).await?;
            }
            let cursor = candidates.after;
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_registration_tasks.device_recovery r SET authority_epoch=a.epoch,recovery_after=$3 FROM mdm_access.command_authorities a WHERE r.tenant_id=$1::uuid AND r.device=$2 AND (a.tenant_id,a.device)=(r.tenant_id,r.device)").bind(tenant).bind(name.into_uuid()).bind(cursor).execute(c).await?;Ok(())})).await?;
            Ok(false)
        }
    }
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for Service {
    type State = bool;
    fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<ReconcileDiff<bool>>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            let execution = self.binding_for(claim, control).await?;
            control.check()?;
            if claim.target().scope().reconciler() != DOMAIN {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Invariant,
                ));
            }
            let audit = RequestAudit::new(
                rss_mdm_audit_integration::Origin::Background,
                rss_mdm_audit_integration::StorageProfile::Mdm,
                execution,
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            let active=crate::installation::transaction::inspect(&self.transactions.runtime,execution,(self,claim.target().entity()),|ctx,tx|Box::pin(async move {
            let (_,entity) = *ctx;
            let Some(device)=device(tx,entity).await? else{return Ok(false)};
            let tenant=tx.tenant_id().to_string();
            Ok(tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_registration_tasks.device_recovery WHERE tenant_id=$1::uuid AND device=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM mdm_registration_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device)))) OR EXISTS(SELECT FROM mdm_access.agent_bootstraps b WHERE b.tenant_id=$1::uuid AND (b.installation_facts->>'device')::uuid=$2 AND NOT b.cleanup_complete) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_registration_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND a.device=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
                    .bind(tenant).bind(device.into_uuid()).bind(messaging_domain().as_str().to_owned()).fetch_one(c).await
            })).await?)
        })).await;
            audit.finalize(
                active
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            Ok(ReconcileStep::Ready(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(active.map_err(failure)?),
            )))
        })
    }
    fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileStep<()>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            let execution = self.binding_for(claim, control).await?;

            if claim.target().scope().reconciler() != DOMAIN {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Invariant,
                ));
            }
            {
                let audit = RequestAudit::new(
                    rss_mdm_audit_integration::Origin::Background,
                    rss_mdm_audit_integration::StorageProfile::Mdm,
                    execution,
                    "management_write",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                let error = Mutex::new(None);
                control.check()?;
                let attempt = self
                    .transactions
                    .runtime
                    .local_tx_with_context(
                        execution,
                        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                            control.remaining(),
                        ),
                        (self, claim, (self, claim.target().entity(), &audit, &error)),
                        |(service, claim, context), tx| {
                            Box::pin(async move {
                                if let Err(e) = service.transactions.audit_store.bind_in(tx).await {
                                    return Err(rejection(Fault::Request(e.into()), context.3));
                                }
                                let prepared =
                                    match prepare(service, tx, context.1, context.2).await {
                                        Ok(prepared) => prepared,
                                        Err(error) => return Err(rejection(error, context.3)),
                                    };

                                if prepared.is_some() {
                                    let resources = resources_in(tx, claim.target().entity())
                                        .await
                                        .map_err(|e| rejection(e, context.3))?;
                                    service
                                        .transactions
                                        .reconcile_messaging
                                        .bind_in(tx, claim.target(), &resources)
                                        .await?;
                                }
                                let settlement_audit = context.2;
                                let outcome = service
                                    .transactions
                                    .reconcile_messaging
                                    .protect_in(tx, claim, (context, prepared), |ctx, tx| {
                                        Box::pin(async move {
                                            let ((service, _, audit, failure), prepared) = ctx;
                                            let Some(prepared) = prepared.take() else {
                                                // Normal endpoint contention yields without counting a failed attempt.
                                                return Ok(
                                                    rss_reconcile_postgres::ProtectedStep::Deferred(
                                                        Duration::from_millis(50),
                                                    ),
                                                );
                                            };
                                            match apply_prepared(service, tx, prepared, audit).await
                                            {
                                                Ok(more) => Ok(
                                                    rss_reconcile_postgres::ProtectedStep::Ready(
                                                        more,
                                                    ),
                                                ),
                                                Err(e) => Err(rejection(e, failure)),
                                            }
                                        })
                                    })
                                    .await;
                                if outcome.is_ok() {
                                    settlement_audit.mark_commit_started();
                                }
                                outcome
                            })
                        },
                    )
                    .await;
                let result = settle(attempt, &audit, error);
                audit.finalize(
                    result
                        .as_ref()
                        .err()
                        .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
                );
                result.map_err(failure).map(|step| match step {
                    ReconcileStep::Ready(_) => ReconcileStep::Ready(()),
                    ReconcileStep::Deferred(after) => ReconcileStep::Deferred(after),
                })
            }
        })
    }
}

async fn try_lock_device(
    tx: &mut PgTransaction<'_>,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    if !crate::lifecycle::try_lock_devices_in(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        &tenant,
                        std::slice::from_ref(&device),
                    )
                    .await?
                    {
                        return Ok(false);
                    }
                    crate::device::store::lock_channel(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        &tenant,
                        &device,
                        rss_mdm_inventory::Channel::Mdm,
                    )
                    .await?;
                    Ok::<_, crate::Error>(true)
                }
                .await)
            })
        })
        .await??)
}

struct CommandCandidates {
    operations: Vec<(Uuid, i64)>,
    after: Option<String>,
}
/// Both directions are bounded in the owner's command-ID order. Missing or mismatched
/// relationships reject the original transaction; recovery never repairs orphan commands.
async fn command_candidates_in(
    tx: &mut PgTransaction<'_>,
    scope: dc::Scope,
    device: &rss_mdm_agent_wire::DeviceId,
    after: Option<&dc::CommandId>,
    limit: rss_device_command::BatchLimit,
) -> Result<CommandCandidates> {
    let rows_limit = i64::from(limit.get()) + 1;
    let limit = usize::from(limit.get());
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let after = after.map(|id| id.as_str().to_owned());
    let command_device = scope.device().as_uuid();
    let domain = messaging_domain().as_str().to_owned();
    let mut rows: Vec<(String, Option<Uuid>, Option<i64>)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as(r#"WITH candidates AS (
          (SELECT o.id::text AS command_id, CASE WHEN c.device_id=$4 AND c.outbox_domain=$5 THEN o.id END AS operation, o.observed_command_version AS observed
           FROM mdm_registration_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text)
           WHERE o.tenant_id=$1::uuid AND o.device=$2 AND ($3::text IS NULL OR o.id::text COLLATE "C">$3 COLLATE "C")
             AND (c.terminal_at IS NULL OR c.version<>o.observed_command_version OR c.device_id IS DISTINCT FROM $4 OR c.outbox_domain IS DISTINCT FROM $5)
           ORDER BY o.id::text COLLATE "C" LIMIT $6)
          UNION ALL
          (SELECT c.command_id,NULL::uuid,NULL::bigint FROM rss_device_command.commands c
           LEFT JOIN mdm_registration_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,$2)
           WHERE c.tenant_id=$1::uuid AND c.device_id=$4 AND c.outbox_domain=$5 AND o.id IS NULL
             AND ($3::text IS NULL OR c.command_id COLLATE "C">$3 COLLATE "C")
           ORDER BY c.command_id COLLATE "C" LIMIT $6)
        ) SELECT command_id,operation,observed FROM candidates ORDER BY command_id COLLATE "C" LIMIT $6"#)
        .bind(tenant).bind(device.into_uuid()).bind(after).bind(command_device).bind(domain).bind(rows_limit).fetch_all(c).await
    })).await?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let after = if more {
        rows.last().map(|r| r.0.clone())
    } else {
        None
    };
    let operations = rows
        .into_iter()
        .map(|(_, id, observed)| {
            Ok((
                id.ok_or(Error::Unavailable(Failure::CommandInvariant))?,
                observed.ok_or(Error::Unavailable(Failure::CommandInvariant))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CommandCandidates { operations, after })
}

impl Service {
    pub(super) async fn binding_for<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<
        rss_transactional_messaging::fence::ExecutionBinding,
        rss_reconcile::Error,
    > {
        control.check()?;
        let tenant = claim.target().scope().tenant();
        let epoch: i64 =
            sqlx::query_scalar("SELECT mdm_registration_tasks.native_work_epoch($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(claim.target().entity())
                .fetch_one(&self.read_pool)
                .await
                .map_err(|_| failure(Error::Unavailable(Failure::CommandStorage)))?;
        let epoch = rss_transactional_messaging::fence::Epoch::new(epoch)
            .map_err(|_| failure(Error::Unavailable(Failure::CommandInvariant)))?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
    pub async fn relay_page(
        &self,
        after: Option<Uuid>,
    ) -> std::result::Result<
        Vec<(Uuid, i64, rss_mdm_recovery_observation::RelayWork)>,
        rss_reconcile::ErrorKind,
    > {
        let page = self.readiness.relay_page();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), sqlx::query_as("SELECT tenant_id,expected_epoch,claimable,quarantined FROM mdm_registration_tasks.native_work_relay_scopes($1)").bind(after).fetch_all(&self.read_pool)).await.map_err(|_|rss_reconcile::ErrorKind::Deadline).and_then(|rows|rows.map_err(|error|crate::discovery::classify(&error)));
        self.readiness
            .relay_round(result.as_ref().map(|_| ()).map_err(|kind| *kind));
        result.map(|rows| page.bindings(rows))
    }
    pub fn relay_scope(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Option<rss_mdm_recovery_observation::RelayScope<'_>> {
        Some(self.readiness.relay_scope(binding))
    }
}
