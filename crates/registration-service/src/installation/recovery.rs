use super::*;
use rss_mdm_audit_integration::Fact;
use rss_mdm_audit_integration::activity::ActivityDelivery;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, ReconcileStep, Reconciler};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use sqlx::Row;

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
    serde_json::json!({"event":"mdm_registration_installation_relay_failure","phase":phase,"messageId":message_id,"reason":if permanent(error){"invariant"}else if matches!(error, Error::CommitUnknown){"commit_unknown"}else{"transient"}})
}
fn relay_diagnostic(phase: &str, message_id: Option<&str>, error: &Error) {
    eprintln!("{}", relay_diagnostic_value(phase, message_id, error));
}
impl Service {
    /// Register the durable input scan while resources are admitted, before exposing a runner.

    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::installation::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) = rss_runtime::ManagedTask::prepare(
            "mdm-registration-installation-recovery",
            Duration::from_secs(20),
        );
        self.readiness.bind(status);
        task.into_registration(
            move |cancel| async move { self.run_worker(&cancel, &signals).await },
        )
    }
    pub async fn run_worker(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
        signals: &crate::installation::worker_wake::Signals,
    ) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = Timer::new();
        let stopped = cancel.child_token();
        let force = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::MAX, &force);
        let scope = recovery_scope(self.transactions.tenant);
        let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: self.worker_concurrency,
            lease_ttl: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(6),
            scan_interval: Duration::from_millis(20),
            idle_scan_interval: Duration::from_secs(5),
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
            max_attempts: 1000,
        })
        .map_err(rss_runtime::ShutdownError::new)?;
        let recovery = async {
            self.run_recovery(
                &scope,
                policy,
                &control,
                &stopped,
                signals.command_recovery(),
            )
            .await
            .map(|_| ())
            .map_err(rss_runtime::ShutdownError::new)
        };
        tokio::pin!(recovery);
        let result = tokio::select! {result=&mut recovery=>result,()=cancel.cancelled()=>{stopped.cancel();recovery.await}};
        self.readiness.stop();
        result
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
                if let rss_reconcile::Observation::ScanFailed { error, .. } = &event {
                    self.readiness.scan(Err(error.kind()));
                }
                if let rss_reconcile::Observation::AttemptFailed { target, error, .. } = &event {
                    self.readiness.failed_attempt(target, error.kind());
                }
                diagnostic(event);
            },
        ))
        .await;
        if let Err(error) = &result {
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_registration_installation_recovery_failure","phase":"runner","scope":scope.reconciler(),"reason":format!("{:?}",error.kind())})
            );
        }
        result
    }
    pub fn record_relay_health(&self, result: &std::result::Result<usize, Error>) {
        self.readiness.relay(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| failure(e.clone()).kind()),
        );
    }
    pub async fn relay_once(&self) -> std::result::Result<usize, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await
            .map_err(|e| {
                let e = provider(e.into());
                relay_diagnostic("claim", None, &e);
                e
            })?;
        let count = claims.len();
        for claim in claims {
            self.relay_claim(claim).await?;
        }
        Ok(count)
    }
    pub async fn relay_claim(
        &self,
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
        let result = self.accept_dispatch(id, fingerprint).await;
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
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), Error> {
        let audit = RequestAudit::new(
            self.transactions.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.operation(
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-dispatch");
        let result=crate::installation::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move {
            let (service,id,fingerprint,audit) = ctx;
            crate::installation::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let operation_id=*id;
            let tenant=service.transactions.tenant.to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_registration_tasks.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false) {sqlx::query("UPDATE mdm_registration_tasks.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            if old {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            if !old {
                let operation=storage::load(tx,&service.transactions.protection,operation_id).await?;
                let mut activity=crate::installation::timeline::native_activity(&operation,service.transactions.required_command(tx,&operation).await?.status(),rss_mdm_audit_integration::activity::ActivityPhase::Dispatched);
                activity.delivery=Some(ActivityDelivery::Dispatched);
                let fact=Fact::business(audit, &format!("command:{}:dispatch",operation.id), 200, "success", None)?.with_activity(&activity)?;
                service.transactions.audit_store.append_in(tx, &fact).await?;
                if matches!(&operation.request.task, crate::installation::Task::Windows { .. }) {
                    crate::installation::worker_wake::notify_in(tx, crate::installation::worker_wake::Work::WindowsPush).await?;
                }
            }
            if !old { crate::installation::worker_wake::notify_in(tx, crate::installation::worker_wake::Work::Apple).await?; }
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
async fn device(tx: &mut PgTransaction<'_>, entity: &str) -> Result<Option<String>> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(device)=$2").bind(tenant).bind(entity).fetch_optional(c).await})).await?)
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, entity: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_registration_tasks.device_recovery WHERE tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(device)=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM mdm_registration_tasks.operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND mdm_registration_tasks.recovery_key(o.device)=$2 AND c.version<>o.observed_command_version)")
            .bind(tenant).bind(entity).fetch_one(c).await
    })).await?)
}
pub(crate) enum PreparedRecovery {
    Empty,

    Device(String),
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
            let tenant = service.transactions.tenant.to_string();
            let key = name.clone();
            let registration =
                storage::current_registration(tx, &name, crate::Purpose::Primary).await;
            if let Ok((id, generation)) = registration {
                crate::command_authority::resolve_in(
                    &service.transactions.store,
                    tx,
                    &name,
                    id,
                    generation,
                )
                .await?;
            }
            let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.command_device::text,a.generation,a.epoch,CASE WHEN r.authority_epoch=a.epoch THEN r.recovery_after END AS recovery_after FROM mdm_access.command_authorities a LEFT JOIN mdm_registration_tasks.device_recovery r USING(tenant_id,device) WHERE a.tenant_id=$1::uuid AND a.device=$2 FOR UPDATE OF a").bind(tenant).bind(key).fetch_one(c).await})).await?;
            let scope = dc::Scope::new(
                service.transactions.tenant,
                stored(dc::DeviceId::parse(
                    &row.try_get::<String, _>("command_device")?,
                ))?,
            );
            let after = row
                .try_get::<Option<String>, _>("recovery_after")?
                .map(|s| stored(dc::CommandId::parse(&s)))
                .transpose()?;
            let page = service
                .transactions
                .store
                .recover(
                    tx,
                    scope,
                    checked_input(dc::BatchLimit::new(64))?,
                    after.as_ref(),
                )
                .await?;
            if matches!(registration, Err(Fault::Request(Error::Conflict))) {
                for command in &page.commands {
                    let id = stored(Uuid::parse_str(command.spec().id().as_str()))?;
                    if !storage::owns_in(tx, id).await? {
                        continue;
                    }
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
            for command in &page.commands {
                let id = stored(Uuid::parse_str(command.spec().id().as_str()))?;
                if !storage::owns_in(tx, id).await? {
                    continue;
                }
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
            // RSS recovery is shared by business owners. Observe our own durable versions
            // independently of its nonterminal cursor, including transitions committed by Policy.
            let tenant = tx.tenant_id().to_string();
            let device = name.clone();
            let unobserved = tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_as::<_, (Uuid, i64)>("SELECT o.id,o.observed_command_version FROM mdm_registration_tasks.operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND c.version<>o.observed_command_version ORDER BY o.id LIMIT 64")
                    .bind(tenant).bind(device).fetch_all(c).await
            })).await?;
            for (id, previous_version) in unobserved {
                let operation = storage::load(tx, &service.transactions.protection, id).await?;
                let command = service
                    .transactions
                    .required_command(tx, &operation)
                    .await?;
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
                fact_audit.operation(
                    id,
                    "command_reconcile",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                fact_audit.target_device(&operation.device);
                fact_audit.registration(operation.registration);
                let fact = Fact::business(&fact_audit, &format!("command:{id}:recover:{}", command.version()), 200, "success", None)?
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
            let cursor = page.after.map(|s| s.as_str().to_owned());
            let tenant = service.transactions.tenant.to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_registration_tasks.device_recovery(tenant_id,device,authority_epoch,recovery_after) SELECT tenant_id,device,epoch,$3 FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2 ON CONFLICT(tenant_id,device) DO UPDATE SET authority_epoch=excluded.authority_epoch,recovery_after=excluded.recovery_after").bind(tenant).bind(name).bind(cursor).execute(c).await?;Ok(())})).await?;
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
            control.check()?;
            if claim.target().scope() != &recovery_scope(self.transactions.tenant) {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Invariant,
                ));
            }
            let audit = RequestAudit::new(
                self.transactions.tenant.to_string(),
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            let active=crate::installation::transaction::inspect(&self.transactions.runtime,self.transactions.tenant,(self,claim.target().entity()),|ctx,tx|Box::pin(async move {
            let (service,entity) = *ctx;
            let Some(device)=device(tx,entity).await? else{return Ok(false)};
            let tenant=service.transactions.tenant.to_string();
            Ok(tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_registration_tasks.operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR c.version<>o.observed_command_version)) OR EXISTS(SELECT FROM mdm_access.agent_bootstraps b WHERE b.tenant_id=$1::uuid AND b.installation_facts->>'device'=$2 AND NOT b.cleanup_complete)")
                    .bind(tenant).bind(device).fetch_one(c).await
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
            let Ok(_permit) = self.worker_budget.try_acquire() else {
                return Ok(ReconcileStep::Deferred(Duration::from_millis(50)));
            };

            if claim.target().scope() != &recovery_scope(self.transactions.tenant) {
                return Err(rss_reconcile::Error::new(
                    rss_reconcile::ErrorKind::Invariant,
                ));
            }
            {
                let audit = RequestAudit::new(
                    self.transactions.tenant.to_string(),
                    "management_write",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                let error = Mutex::new(None);
                control.check()?;
                let attempt = self
                    .transactions
                    .runtime
                    .local_tx_with_context(
                        self.transactions.tenant,
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

                                service
                                    .transactions
                                    .reconcile_messaging
                                    .protect_in(tx, claim, (context, prepared), |ctx, tx| {
                                        Box::pin(async move {
                                            let ((service, _, audit, failure), prepared) = ctx;
                                            let Some(prepared) = prepared.take() else {
                                                // Normal endpoint contention yields without counting a failed attempt.
                                                audit.mark_commit_started();
                                                return Ok(rss_reconcile_postgres::ProtectedStep::Deferred(Duration::from_millis(50)));
                                            };
                                            match apply_prepared(
                                                service,
                                                tx,
                                                prepared,
                                                audit,
                                            )
                                            .await
                                            {
                                                Ok(more) => {
                                                    audit.mark_commit_started();
                                                    Ok(rss_reconcile_postgres::ProtectedStep::Ready(more))
                                                }
                                                Err(e) => Err(rejection(e, failure)),
                                            }
                                        })
                                    })
                                    .await
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

async fn try_lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    if !crate::lifecycle::try_lock_devices_in(c, &tenant, &[device.clone()]).await?
                    {
                        return Ok(false);
                    }
                    crate::device::store::lock_channel(
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
