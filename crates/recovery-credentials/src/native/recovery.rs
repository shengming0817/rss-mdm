use super::*;
use rss_mdm_audit_integration::Fact;
use rss_mdm_audit_integration::activity::ActivityDelivery;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use sqlx::Row;
use std::sync::Mutex;

pub struct Timer(tokio::time::Instant);
impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // Concrete monotonic injection boundary shared by all command controls.
    pub fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl rss_reconcile::Timer for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete monotonic clock implementation"
    )]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        match self.0.checked_add(at) {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            // An unbounded controller still races this wait against cancellation.
            None => std::future::pending().await,
        }
    }
}
fn failure(error: Error) -> rss_reconcile::Error {
    if matches!(error, Error::Unavailable(Failure::NativeInputIntegrity)) {
        eprintln!(
            "{}",
            serde_json::json!({"event":"mdm_recovery_native_recovery_integrity_failure","reason":"native_input_integrity"})
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
        serde_json::json!({"event":"mdm_recovery_native_recovery_failure","phase":phase,"target":target,"reason":format!("{:?}",error.kind())})
    );
}
fn permanent(error: &Error) -> bool {
    matches!(
        error,
        Error::Unavailable(Failure::CommandInvariant | Failure::NativeInputIntegrity)
            | Error::Malformed
            | Error::Forbidden
            | Error::Unauthorized
    )
}
fn provider(error: PgError) -> Error {
    use rss_transactional_messaging::error::MessagingErrorKind;
    match error.kind() {
        MessagingErrorKind::Permanent
        | MessagingErrorKind::Invariant
        | MessagingErrorKind::Conflict => Error::Unavailable(Failure::CommandInvariant),
        _ => Error::Unavailable(Failure::CommandStorage),
    }
}
fn relay_diagnostic_value(
    phase: &str,
    message_id: Option<&str>,
    error: &Error,
) -> serde_json::Value {
    serde_json::json!({"event":"mdm_recovery_native_relay_failure","phase":phase,"messageId":message_id,"reason":if permanent(error){"invariant"}else if matches!(error, Error::CommitUnknown){"commit_unknown"}else{"transient"}})
}
fn relay_diagnostic(phase: &str, message_id: Option<&str>, error: &Error) {
    eprintln!("{}", relay_diagnostic_value(phase, message_id, error));
}
impl Service {
    /// Register the durable input scan while resources are admitted, before exposing a runner.
    pub fn registration(
        self: Arc<Self>,
        policy: rss_reconcile::Policy,
        drain: std::time::Duration,
        signals: Arc<crate::native::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-recovery-native-recovery", drain);
        self.readiness.bind(status);
        task.into_registration(move |cancel| async move {
            self.run_worker(policy, &cancel, &signals).await
        })
    }
    pub async fn run_worker(
        &self,
        policy: rss_reconcile::Policy,
        cancel: &tokio_util::sync::CancellationToken,
        signals: &crate::native::worker_wake::Signals,
    ) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = Timer::new();
        let force = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::MAX, &force);
        let mut after: Option<Uuid> = None;
        let mut worked = false;
        loop {
            if cancel.is_cancelled() {
                self.readiness.stop();
                return Ok(());
            }
            let discovered = tokio::select! { biased;
                    () = cancel.cancelled() => { self.readiness.stop(); return Ok(()); },
                    result = tokio::time::timeout(Duration::from_secs(5), sqlx::query_scalar(
                "SELECT tenant_id FROM mdm_recovery_tasks.native_work_scopes($1)",
            )
            .bind(after)
            .fetch_all(&self.read_pool)) =>
                        result.map_err(|_| rss_reconcile::ErrorKind::Deadline)
                            .and_then(|page| page.map_err(|error| crate::discovery::classify(&error))),
                };
            if cancel.is_cancelled() {
                {
                    self.readiness.stop();
                    return Ok(());
                }
            }
            self.readiness
                .discovery(discovered.as_ref().map(|_| ()).map_err(|kind| *kind));
            let tenants: Vec<Uuid> = match discovered {
                Ok(page) => page,
                Err(rss_reconcile::ErrorKind::Transient | rss_reconcile::ErrorKind::Deadline) => {
                    // A failed page is not empty. Keep its cursor and rate-limit retries even under wake storms.
                    tokio::select! { biased;
                        () = cancel.cancelled() => { self.readiness.stop(); return Ok(()); },
                        () = tokio::time::sleep(Duration::from_secs(5)) => {},
                    }
                    continue;
                }
                Err(kind) => {
                    return Err(rss_runtime::ShutdownError::new(rss_reconcile::Error::new(
                        kind,
                    )));
                }
            };
            if tenants.is_empty() {
                after = None;
                if std::mem::take(&mut worked) {
                    continue;
                }

                tokio::select! {()=cancel.cancelled()=>{self.readiness.stop();return Ok(())},()=signals.command_recovery().notified()=>{},()=tokio::time::sleep(Duration::from_secs(5))=>{}}
                continue;
            }
            for tenant in tenants {
                after = Some(tenant);
                let tenant = TenantId::parse(&tenant.to_string())
                    .map_err(rss_runtime::ShutdownError::new)?;
                let scope = recovery_scope(tenant);

                let report = match rss_reconcile::run_batch(
                    &self.recovery_store(),
                    self,
                    &scope,
                    policy,
                    &control,
                    cancel,
                    |event| {
                        self.readiness.observe(&event);
                        diagnostic(event);
                    },
                )
                .await
                {
                    Ok(report) => report,
                    Err(error)
                        if control.check().is_ok()
                            && matches!(
                                error.kind(),
                                rss_reconcile::ErrorKind::Transient
                                    | rss_reconcile::ErrorKind::Deadline
                                    | rss_reconcile::ErrorKind::CommitUnknown
                            ) =>
                    {
                        // The observer retained this scope's failure. Advance the tenant cursor;
                        // an unconfirmed claim is not an empty or successfully drained batch.
                        continue;
                    }
                    Err(error) => return Err(rss_runtime::ShutdownError::new(error)),
                };
                worked |= [
                    report.converged,
                    report.reobserve,
                    report.deferred,
                    report.retried,
                    report.suspended,
                    report.fenced,
                    report.execution_failed,
                ]
                .into_iter()
                .any(|count| count > 0);
            }
        }
    }

    pub async fn run_recovery<T: rss_reconcile::Timer>(
        &self,
        scope: &rss_reconcile::Scope,
        policy: rss_reconcile::Policy,
        control: &rss_reconcile::Control<'_, T>,
        stop: &tokio_util::sync::CancellationToken,
        notify: &tokio::sync::Notify,
    ) -> std::result::Result<rss_reconcile::Report, rss_reconcile::Error> {
        let result = Box::pin(rss_reconcile::run_with_notify(
            &self.recovery_store(),
            self,
            scope,
            policy,
            control,
            stop,
            notify,
            |event| {
                // The runner can expire and drop the claim future before the store returns.
                self.readiness.observe(&event);
                diagnostic(event);
            },
        ))
        .await;
        if let Err(error) = &result {
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_recovery_native_recovery_failure","phase":"runner","scope":scope.reconciler(),"reason":format!("{:?}",error.kind())})
            );
        }
        result
    }
    pub fn record_relay_health<T>(&self, result: &std::result::Result<T, Error>) {
        self.readiness.relay_round(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
    pub async fn claim_relay(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        limit: std::num::NonZeroUsize,
    ) -> std::result::Result<Vec<impl Future<Output = std::result::Result<(), Error>> + Send + '_>, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(execution, limit, deadline())
            .await
            .map_err(|e| {
                let e = provider(e.into());
                relay_diagnostic("claim", None, &e);
                e
            })?;
        Ok(claims.into_iter().map(|claim| self.relay_claim(execution, claim)).collect())
    }
    async fn relay_claim(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        claim: rss_transactional_messaging_postgres::PgOutboxClaim,
    ) -> std::result::Result<(), Error> {
        let message = PgOutboxStore::<()>::message(&claim);
        let message_id = message.message_id().as_str().to_owned();
        let id = message_id
            .strip_prefix("dispatch.")
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                let e = Error::Unavailable(Failure::CommandInvariant);
                relay_diagnostic("identity", Some(&message_id), &e);
                e
            })?;
        let fingerprint = message.fingerprint().as_bytes().to_vec();
        let result = self.accept_dispatch(execution, id, fingerprint).await;
        if let Err(e) = &result {
            relay_diagnostic("accept", Some(&message_id), e);
            // Preserve the claim and original message for repair; never retry poisoned facts.
            if permanent(e) {
                return result;
            }
        }
        // Only a confirmed gateway commit can authorize a published settlement.
        let settlement = if result.is_ok() {
            OutboxSettlement::Published(())
        } else {
            OutboxSettlement::Retry
        };
        self.outbox
            .settle(claim, settlement, deadline())
            .await
            .map_err(|e| {
                let e = provider(e.into());
                relay_diagnostic("settle", Some(&message_id), &e);
                e
            })?;
        result?;
        Ok(())
    }
    pub async fn accept_dispatch(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), Error> {
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            execution,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand,
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-dispatch");
        let result=crate::native::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,execution,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move {
            let (service,id,fingerprint,audit) = ctx;
            crate::native::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let operation_id=*id;
            let tenant=tx.tenant_id().to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_recovery_tasks.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false) {sqlx::query("UPDATE mdm_recovery_tasks.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            if old {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            if !old {
                let operation=storage::load(tx,&service.transactions.protection,operation_id).await?;
                let mut activity=crate::native::timeline::native_activity(&operation,service.transactions.required_command(tx,&operation).await?.status(),rss_mdm_audit_integration::activity::ActivityPhase::Dispatched);
                activity.delivery=Some(ActivityDelivery::Dispatched);
                let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand, &format!("command:{}:dispatch",operation.id), 200, "success", None)?.with_activity(&activity)?;
                service.transactions.audit_store.append_in(tx, &fact).await?;
            }
            if !old { crate::native::worker_wake::notify_in(tx, crate::native::worker_wake::Work::Apple).await?; }
            Ok(())
        })).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
async fn device(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<Option<rss_mdm_agent_wire::DeviceId>> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND mdm_recovery_tasks.recovery_key(device)=$2").bind(tenant).bind(entity).fetch_optional(c).await.and_then(|id| id.map(crate::storage::device_id).transpose())})).await?)
}

pub(crate) async fn resources_in(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<rss_reconcile::ResourceSet> {
    Ok(match device(tx, entity).await? {
        Some(device) => rss_mdm_registration_service::lifecycle::resources::device(
            tx.tenant_id(),
            &device,
            rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
        ),
        None => rss_reconcile::ResourceSet::empty(tx.tenant_id()),
    })
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, entity: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_recovery_tasks.device_recovery WHERE tenant_id=$1::uuid AND mdm_recovery_tasks.recovery_key(device)=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM mdm_recovery_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND mdm_recovery_tasks.recovery_key(o.device)=$2 AND (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device))) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_recovery_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND mdm_recovery_tasks.recovery_key(a.device)=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
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
    crate::native::transaction::prepare_audit_in(&service.transactions.audit_store, tx, audit, &[])
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
            let tenant = tx.tenant_id().to_string();
            let key = name;
            let registration = storage::current_registration(tx, &name).await;
            if registration.is_ok() {
                rss_mdm_registration_service::command_authority::resolve_in(
                    &service.transactions.store,
                    tx,
                    &name,
                )
                .await?;
            }
            let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT CAST(a.command_device AS text), a.generation, a.epoch, CASE WHEN r.authority_epoch = a.epoch THEN r.recovery_after END AS recovery_after FROM mdm_access.command_authorities AS a LEFT JOIN mdm_recovery_tasks.device_recovery AS r USING (tenant_id, device) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = $2 FOR UPDATE OF a").bind(tenant).bind(key.into_uuid()).fetch_one(c).await})).await?;
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
            let mut commands = Vec::with_capacity(candidates.operations.len());
            for (id, _) in &candidates.operations {
                let id = stored(dc::CommandId::parse(&id.to_string()))?;
                commands.push(
                    service
                        .transactions
                        .store
                        .recover_exact(tx, scope, &id)
                        .await?
                        .ok_or(Error::Unavailable(Failure::CommandInvariant))?,
                );
            }
            if matches!(registration, Err(Fault::Request(Error::Conflict))) {
                for command in &commands {
                    if !command.status().is_terminal() {
                        let transition = service
                            .transactions
                            .store
                            .cancel(tx, scope, command.spec().id(), command.spec().coordinate())
                            .await?;
                        if transition.outcome == dc::Outcome::OutOfOrder {
                            return Err(Error::Conflict.into());
                        }
                    }
                }
            } else {
                registration?;
            }
            for command in &commands {
                if !command.status().is_terminal() {
                    let operation = storage::load(
                        tx,
                        &service.transactions.protection,
                        stored(Uuid::parse_str(command.spec().id().as_str()))?,
                    )
                    .await?;
                    let _now = storage::now(tx).await?;
                    if !storage::authority_valid(
                        service.transactions.materials.clone(),
                        tx,
                        &operation,
                    )
                    .await?
                        && service
                            .transactions
                            .store
                            .cancel(tx, scope, command.spec().id(), command.spec().coordinate())
                            .await?
                            .outcome
                            == dc::Outcome::OutOfOrder
                    {
                        return Err(Error::Conflict.into());
                    }
                }
            }
            // Observe every selected owner's version, including terminal transitions and unchanged live work.
            for (id, previous_version) in candidates.operations {
                let operation = storage::load(tx, &service.transactions.protection, id).await?;
                let command = service
                    .transactions
                    .required_command(tx, &operation)
                    .await?;
                if command.version() == previous_version {
                    continue;
                }
                if command.status().is_terminal() {
                    crate::native::wake::wake_native_in(
                        &service.transactions.reconcile_messaging,
                        tx,
                        &operation.device,
                    )
                    .await?;
                }
                let fact_audit = audit.transaction_copy();
                fact_audit.identify_service("command-recovery");
                fact_audit.owned_operation(
                    rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand,
                    id,
                    "command_reconcile",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                fact_audit.target_device(&operation.device);
                let fact = Fact::business(&fact_audit, rss_mdm_audit_integration::operation::OperationOwner::RecoveryCommand, &format!("command:{id}:recover:{}", command.version()), 200, "success", None)?
                    .with_details(serde_json::json!({"previousVersion":previous_version,"after":service::status(command.status()),"version":command.version()}))?
                    .with_activity(&crate::native::timeline::native_activity(&operation, command.status(), rss_mdm_audit_integration::activity::ActivityPhase::Reconciled))?;
                fact_audit.finalize(None);
                service
                    .transactions
                    .audit_store
                    .append_in(tx, &fact)
                    .await?;
                let tenant = tx.tenant_id().to_string();
                let version = command.version();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("UPDATE mdm_recovery_tasks.operations SET observed_command_version=$3 WHERE tenant_id=$1::uuid AND id=$2")
                        .bind(tenant).bind(id).bind(version).execute(c).await?;
                    Ok(())
                })).await?;
            }
            let cursor = candidates.after;
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_recovery_tasks.device_recovery r SET authority_epoch=a.epoch,recovery_after=$3 FROM mdm_access.command_authorities a WHERE r.tenant_id=$1::uuid AND r.device=$2 AND (a.tenant_id,a.device)=(r.tenant_id,r.device)").bind(tenant).bind(name.into_uuid()).bind(cursor).execute(c).await?;Ok(())})).await?;
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
            let active=crate::native::transaction::inspect(&self.transactions.runtime,execution,(self,claim.target().entity()),|ctx,tx|Box::pin(async move {
            let (_,entity) = *ctx;
            let Some(device)=device(tx,entity).await? else{return Ok(false)};
            let tenant=tx.tenant_id().to_string();
            Ok(tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_recovery_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device)))) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_recovery_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND a.device=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
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
            let Ok(_permit) = self.worker_budget.try_acquire() else {
                return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
            };

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
                    if !rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        &tenant,
                        std::slice::from_ref(&device),
                    )
                    .await?
                    {
                        return Ok(false);
                    }
                    rss_mdm_registration_service::device::store::lock_channel(
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
           FROM mdm_recovery_tasks.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text)
           WHERE o.tenant_id=$1::uuid AND o.device=$2 AND ($3::text IS NULL OR o.id::text COLLATE "C">$3 COLLATE "C")
             AND (c.terminal_at IS NULL OR c.version<>o.observed_command_version OR c.device_id IS DISTINCT FROM $4 OR c.outbox_domain IS DISTINCT FROM $5)
           ORDER BY o.id::text COLLATE "C" LIMIT $6)
          UNION ALL
          (SELECT c.command_id,NULL::uuid,NULL::bigint FROM rss_device_command.commands c
           LEFT JOIN mdm_recovery_tasks.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,$2)
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
            sqlx::query_scalar("SELECT mdm_recovery_tasks.native_work_epoch($1::uuid,$2)")
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
        after: Option<(Uuid, i64)>,
    ) -> std::result::Result<Vec<(Uuid, i64)>, Error> {
        let result = sqlx::query_as("SELECT tenant_id,expected_epoch FROM mdm_recovery_tasks.native_work_relay_scopes($1,$2)").bind(after.map(|x|x.0)).bind(after.map(|x|x.1)).fetch_all(&self.read_pool).await.map_err(|_|Error::Unavailable(Failure::CommandStorage));
        self.record_relay_health(&result);
        result
    }
    pub fn observe_relay(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        result: &std::result::Result<usize, Error>,
    ) {
        self.readiness.relay_scope(
            &recovery_scope(binding.tenant()),
            binding.epoch().get(),
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
}
