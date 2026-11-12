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
            serde_json::json!({"event":"mdm_command_recovery_integrity_failure","reason":"native_input_integrity"})
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
        serde_json::json!({"event":"mdm_command_recovery_failure","phase":phase,"target":target,"reason":format!("{:?}",error.kind())})
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
    serde_json::json!({"event":"mdm_command_relay_failure","phase":phase,"messageId":message_id,"reason":if permanent(error){"invariant"}else if matches!(error, Error::CommitUnknown){"commit_unknown"}else{"transient"}})
}
fn relay_diagnostic(phase: &str, message_id: Option<&str>, error: &Error) {
    eprintln!("{}", relay_diagnostic_value(phase, message_id, error));
}
impl SoftwareService {
    /// Register the durable input scan while resources are admitted, before exposing a runner.
    pub async fn initialize_recovery(&self) -> std::result::Result<(), rss_reconcile::Error> {
        use rss_reconcile::DurableStore;
        let timer = Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        self.reconcile
            .wake(
                &crate::deployment::source_changes::target(self.transactions.tenant),
                &rss_reconcile::ResourceSet::empty(self.transactions.tenant),
                &control,
            )
            .await
    }
    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::deployment::worker_wake::Signals>,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, status) =
            rss_runtime::ManagedTask::prepare("mdm-command-recovery", Duration::from_secs(20));
        self.readiness.bind(status);
        task.into_registration(
            move |cancel| async move { self.run_worker(&cancel, &signals).await },
        )
    }
    pub async fn run_worker(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
        signals: &crate::deployment::worker_wake::Signals,
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
                self.readiness.observe(&event);
                if let rss_reconcile::Observation::AttemptFailed { target, error, .. } = &event
                    && target
                        == &crate::deployment::source_changes::target(self.transactions.tenant)
                {
                    self.readiness.inputs(Err(error.kind()));
                }
                diagnostic(event);
            },
        ))
        .await;
        if let Err(error) = &result {
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_command_recovery_failure","phase":"runner","scope":scope.reconciler(),"reason":format!("{:?}",error.kind())})
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
        let action = message_id.starts_with("action.");
        let id = message_id
            .strip_prefix(if action { "action." } else { "dispatch." })
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                let e = Error::Unavailable(Failure::CommandInvariant);
                relay_diagnostic("identity", Some(&message_id), &e);
                e
            })?;
        let fingerprint = message.fingerprint().as_bytes().to_vec();
        let result = if action {
            self.accept_action_dispatch(id, fingerprint).await
        } else {
            self.accept_dispatch(id, fingerprint).await
        };
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
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.transactions.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::SoftwareDeployment,
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("command-dispatch");
        let result=crate::deployment::transaction::run(&self.transactions.audit_store,&self.transactions.runtime,self.transactions.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move {
            let (service,id,fingerprint,audit) = ctx;
            crate::deployment::transaction::prepare_audit_in(&service.transactions.audit_store,tx,audit,&[]).await?;
            let operation_id=*id;
            let tenant=service.transactions.tenant.to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_software_deployment.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false) {sqlx::query("UPDATE mdm_software_deployment.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            if old {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            if !old {
                let operation=storage::load(tx,&service.transactions.protection,operation_id).await?;
                let mut activity=crate::deployment::timeline::native_activity(&operation,service.transactions.required_command(tx,&operation).await?.status(),rss_mdm_audit_integration::activity::ActivityPhase::Dispatched);
                activity.delivery=Some(ActivityDelivery::Dispatched);
                let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::SoftwareDeployment, &format!("command:{}:dispatch",operation.id), 200, "success", None)?.with_activity(&activity)?;
                service.transactions.audit_store.append_in(tx, &fact).await?;
                if matches!(&operation.request.task, crate::deployment::Task::Windows { .. }) {
                    crate::deployment::worker_wake::notify_in(tx, crate::deployment::worker_wake::Work::WindowsPush).await?;
                }
            }
            if !old { crate::deployment::worker_wake::notify_in(tx, crate::deployment::worker_wake::Work::Apple).await?; }
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
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND mdm_software_deployment.recovery_key(device)=$2").bind(tenant).bind(entity).fetch_optional(c).await})).await?)
}
async fn agent_install_device(tx: &mut PgTransaction<'_>, digest: &str) -> Result<Option<String>> {
    let tenant = tx.tenant_id().to_string();
    let digest = digest.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT device FROM mdm_software_deployment.agent_install_inputs WHERE tenant_id=$1::uuid AND mdm_software_deployment.recovery_key(device)=$2")
            .bind(tenant).bind(digest).fetch_optional(c).await
    })).await?)
}
pub(crate) async fn resources_in(
    tx: &mut PgTransaction<'_>,
    entity: &str,
) -> Result<rss_reconcile::ResourceSet> {
    use rss_mdm_registration_service::lifecycle::resources::{self, Work};
    if let Some(id) = entity
        .strip_prefix("retirement:")
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        let tenant = tx.tenant_id().to_string();
        let devices: Vec<String> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY device")
                .bind(tenant).bind(id).fetch_all(c).await
        })).await?;
        return Ok(resources::devices(tx.tenant_id(), &devices)?);
    }
    if let Some(actions::run_recovery::Work::Run(id)) = actions::run_recovery::Work::parse(entity) {
        let tenant = tx.tenant_id().to_string();
        let device: String = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        return Ok(resources::device(tx.tenant_id(), &device, Work::Exclusive));
    }
    if let Some(work) = actions::scheduled::Work::parse(entity) {
        return Ok(resources::device(
            tx.tenant_id(),
            &work.device,
            Work::Exclusive,
        ));
    }
    if let Some(digest) = entity.strip_prefix("agent-install:") {
        return Ok(match agent_install_device(tx, digest).await? {
            Some(device) => resources::device(tx.tenant_id(), &device, Work::Exclusive),
            None => rss_reconcile::ResourceSet::empty(tx.tenant_id()),
        });
    }
    if entity == "inputs" || actions::recovery::policy_id(entity).is_some() {
        return Ok(rss_reconcile::ResourceSet::empty(tx.tenant_id()));
    }
    Ok(match device(tx, entity).await? {
        Some(device) => resources::device(tx.tenant_id(), &device, Work::Exclusive),
        None => rss_reconcile::ResourceSet::empty(tx.tenant_id()),
    })
}

pub(crate) async fn backlog_in(tx: &mut PgTransaction<'_>, entity: &str) -> Result<bool> {
    if let Some(digest) = entity.strip_prefix("agent-install:") {
        return match agent_install_device(tx, digest).await? {
            Some(device) => crate::deployment::agent_install::inputs_pending(tx, &device).await,
            None => Ok(false),
        };
    }
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_deployment.device_recovery WHERE tenant_id=$1::uuid AND mdm_software_deployment.recovery_key(device)=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM mdm_software_deployment.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND mdm_software_deployment.recovery_key(o.device)=$2 AND (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device))) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_software_deployment.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND mdm_software_deployment.recovery_key(a.device)=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
            .bind(tenant).bind(entity).bind(messaging_domain().as_str().to_owned()).fetch_one(c).await
    })).await?)
}
pub(crate) enum PreparedRecovery {
    Empty,

    Native(actions::run_recovery::Work, Uuid),
    Policy(Uuid),
    Scheduled(actions::scheduled::Work, Uuid),
    AgentInstall(String),
    Device(String),
}
/// Discover only this bounded operation under existing owner fences. No effect precedes claim validation.
/// None is normal endpoint contention; a prepared value retains its business locks for apply.
#[expect(
    clippy::cognitive_complexity,
    reason = "preparation keeps current authorization and protocol state in one bounded transaction"
)]
pub(crate) async fn prepare(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    entity: &str,
    audit: &RequestAudit,
) -> Result<Option<PreparedRecovery>> {
    if entity.starts_with("scheduled:") && actions::scheduled::Work::parse(entity).is_none() {
        return Err(Error::Unavailable(Failure::CommandInvariant).into());
    }
    let tenant = tx.tenant_id();
    // Independent devices do not take an unrelated tenant-wide read/write fence.
    // Device locks precede the claim lock; asset-producing callbacks use the
    // commit-ordered history owner and abort rather than wait in reverse order.
    let partitions = [];
    let prepared = if let Some(work) = actions::run_recovery::Work::parse(entity) {
        let t = tenant.to_string();
        let device: String = tx.with_connection(move |c| Box::pin(async move {
            match work {
                actions::run_recovery::Work::Run(id) => sqlx::query_scalar("SELECT device FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(id).fetch_one(c).await,
            }
        })).await?;
        if !actions::run_recovery::try_lock_device(tx, &device).await? {
            return Ok(None);
        }
        {
            let actions::run_recovery::Work::Run(id) = work;
            actions::storage::load_run(tx, id).await?;
        }
        let run_id = Uuid::new_v4();

        PreparedRecovery::Native(work, run_id)
    } else if let Some(work) = actions::scheduled::Work::parse(entity) {
        if let Some(device) =
            actions::scheduled::device_in(&service.transactions.policy_reader, tx, &work).await?
        {
            if !actions::run_recovery::try_lock_device(tx, &device).await? {
                return Ok(None);
            }
            PreparedRecovery::Scheduled(work, Uuid::new_v4())
        } else {
            PreparedRecovery::Empty
        }
    } else if let Some(id) = actions::recovery::policy_id(entity) {
        crate::deployment::sources::storage::lock(tx, id).await?;
        PreparedRecovery::Policy(id)
    } else {
        let installation = entity.strip_prefix("agent-install:");
        let device = match installation {
            Some(digest) => agent_install_device(tx, digest).await?,
            None => device(tx, entity).await?,
        };
        if let Some(device) = device {
            if !actions::run_recovery::try_lock_device(tx, &device).await? {
                return Ok(None);
            }

            if installation.is_some() {
                // Input dispatch updates this row before waking the target. Keep
                // that owner order before protecting the same target here.
                let tenant = tx.tenant_id().to_string();
                let selected = device.clone();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("SELECT input_revision FROM mdm_software_deployment.agent_install_inputs WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE")
                        .bind(tenant).bind(selected).fetch_one(c).await?;
                    Ok(())
                })).await?;
                PreparedRecovery::AgentInstall(device)
            } else {
                PreparedRecovery::Device(device)
            }
        } else {
            PreparedRecovery::Empty
        }
    };

    crate::deployment::transaction::prepare_audit_in(
        &service.transactions.audit_store,
        tx,
        audit,
        &partitions,
    )
    .await?;
    Ok(Some(prepared))
}
#[expect(
    clippy::cognitive_complexity,
    reason = "closed native recovery transitions preserve original claim, epoch and settlement outcomes"
)]
pub(crate) async fn apply_prepared(
    service: &SoftwareService,
    tx: &mut PgTransaction<'_>,
    prepared: PreparedRecovery,
    audit: &RequestAudit,
) -> Result<bool> {
    match prepared {
        PreparedRecovery::Empty => Ok(false),

        PreparedRecovery::Native(work, run_id) => {
            actions::run_recovery::step(service, tx, work, run_id).await
        }
        PreparedRecovery::Policy(id) => actions::recovery::discover_in(service, tx, id)
            .await
            .map(|()| false),
        PreparedRecovery::Scheduled(work, run) => {
            actions::scheduled::advance_in(service, tx, &work, run)
                .await
                .map(|()| false)
        }
        PreparedRecovery::AgentInstall(device) => {
            service
                .transactions
                .reconcile_agent_install_in(tx, &device, audit)
                .await?;
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_software_deployment.agent_install_inputs SET observed_revision=input_revision WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(device).execute(c).await?;Ok(())})).await?;
            Ok(false)
        }
        PreparedRecovery::Device(name) => {
            let tenant = service.transactions.tenant.to_string();
            let key = name.clone();
            let registration = storage::current_registration(
                tx,
                &name,
                rss_mdm_registration_service::Purpose::Primary,
            )
            .await;
            if registration.is_ok() {
                rss_mdm_registration_service::command_authority::resolve_in(
                    &service.transactions.store,
                    tx,
                    &name,
                )
                .await?;
            }
            let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT CAST(a.command_device AS text), a.generation, a.epoch, CASE WHEN r.authority_epoch = a.epoch THEN r.recovery_after END AS recovery_after FROM mdm_access.command_authorities AS a LEFT JOIN mdm_software_deployment.device_recovery AS r USING (tenant_id, device) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = $2 FOR UPDATE OF a").bind(tenant).bind(key).fetch_one(c).await})).await?;
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
            let candidates = command_candidates_in(tx, scope, &name, after.as_ref()).await?;
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
                    let now = storage::now(tx).await?;
                    if !storage::authority_decision(
                        &service.transactions.source,
                        &service.transactions.lifecycle,
                        &service.transactions.protection,
                        tx,
                        &operation,
                        now,
                    )
                    .await?
                    .is_authorized()
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
                    crate::deployment::wake::wake_native_in(
                        &service.transactions.reconcile_messaging,
                        service.transactions.source.clone(),
                        tx,
                        &operation.device,
                    )
                    .await?;
                }
                let fact_audit = audit.transaction_copy();
                fact_audit.identify_service("command-recovery");
                fact_audit.owned_operation(
                    rss_mdm_audit_integration::operation::OperationOwner::SoftwareDeployment,
                    id,
                    "command_reconcile",
                    rss_mdm_audit_integration::AuditIntent::Management,
                );
                fact_audit.target_device(&operation.device);
                let fact = Fact::business(&fact_audit, rss_mdm_audit_integration::operation::OperationOwner::SoftwareDeployment, &format!("command:{id}:recover:{}", command.version()), 200, "success", None)?
                    .with_details(serde_json::json!({"previousVersion":previous_version,"after":service::status(command.status()),"version":command.version()}))?
                    .with_activity(&crate::deployment::timeline::native_activity(&operation, command.status(), rss_mdm_audit_integration::activity::ActivityPhase::Reconciled))?;
                fact_audit.finalize(None);
                service
                    .transactions
                    .audit_store
                    .append_in(tx, &fact)
                    .await?;
                let tenant = tx.tenant_id().to_string();
                let version = command.version();
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("UPDATE mdm_software_deployment.operations SET observed_command_version=$3 WHERE tenant_id=$1::uuid AND id=$2")
                        .bind(tenant).bind(id).bind(version).execute(c).await?;
                    Ok(())
                })).await?;
            }
            let cursor = candidates.after;
            let tenant = service.transactions.tenant.to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_software_deployment.device_recovery(tenant_id,device,authority_epoch,recovery_after) SELECT tenant_id,device,epoch,$3 FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2 ON CONFLICT(tenant_id,device) DO UPDATE SET authority_epoch=excluded.authority_epoch,recovery_after=excluded.recovery_after").bind(tenant).bind(name).bind(cursor).execute(c).await?;Ok(())})).await?;
            Ok(false)
        }
    }
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for SoftwareService {
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
                rss_mdm_audit_integration::Origin::Background,
                rss_mdm_audit_integration::StorageProfile::Mdm,
                self.transactions.tenant.to_string(),
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            let active=crate::deployment::transaction::inspect(&self.transactions.runtime,self.transactions.tenant,(self,claim.target().entity()),|ctx,tx|Box::pin(async move {
            let (service,entity) = *ctx;
            if entity.starts_with("scheduled:") && actions::scheduled::Work::parse(entity).is_none() { return Err(Error::Unavailable(Failure::CommandInvariant).into()); }
            if entity == "inputs" { return crate::deployment::source_changes::pending_in(tx, service.transactions.source.clone()).await; }
            if let Some(work)=actions::run_recovery::Work::parse(entity) { return actions::run_recovery::needs_step(service,tx,work).await; }
            if let Some(work)=actions::scheduled::Work::parse(entity) { return Ok(actions::scheduled::device_in(&service.transactions.policy_reader, tx,&work).await?.is_some()); }
            if let Some(id)=actions::recovery::policy_id(entity){return actions::recovery::active(tx,id).await;}
            if let Some(digest)=entity.strip_prefix("agent-install:") {
                let Some(device)=agent_install_device(tx,digest).await? else {return Ok(false)};
                return crate::deployment::agent_install::inputs_pending(tx,&device).await;
            }
            let Some(device)=device(tx,entity).await? else{return Ok(false)};
            let tenant=service.transactions.tenant.to_string();
            Ok(tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_deployment.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device)))) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_software_deployment.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND a.device=$2 AND c.outbox_domain=$3 AND o.id IS NULL)")
                    .bind(tenant).bind(device).bind(messaging_domain().as_str().to_owned()).fetch_one(c).await
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
            if claim.target().entity() == "inputs" {
                return self.apply_inputs(claim, control).await;
            }
            {
                let audit = RequestAudit::new(
                    rss_mdm_audit_integration::Origin::Background,
                    rss_mdm_audit_integration::StorageProfile::Mdm,
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

struct CommandCandidates {
    operations: Vec<(Uuid, i64)>,
    after: Option<String>,
}
/// Both directions are bounded in the owner's command-ID order. Missing or mismatched
/// relationships reject the original transaction; recovery never repairs orphan commands.
async fn command_candidates_in(
    tx: &mut PgTransaction<'_>,
    scope: dc::Scope,
    device: &str,
    after: Option<&dc::CommandId>,
) -> Result<CommandCandidates> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let after = after.map(|id| id.as_str().to_owned());
    let command_device = scope.device().as_uuid();
    let domain = messaging_domain().as_str().to_owned();
    let mut rows: Vec<(String, Option<Uuid>, Option<i64>)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as(r#"WITH candidates AS (
          (SELECT o.id::text AS command_id, CASE WHEN c.device_id=$4 AND c.outbox_domain=$5 THEN o.id END AS operation, o.observed_command_version AS observed
           FROM mdm_software_deployment.operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text)
           WHERE o.tenant_id=$1::uuid AND o.device=$2 AND ($3::text IS NULL OR o.id::text COLLATE "C">$3 COLLATE "C")
             AND (c.terminal_at IS NULL OR c.version<>o.observed_command_version OR c.device_id IS DISTINCT FROM $4 OR c.outbox_domain IS DISTINCT FROM $5)
           ORDER BY o.id::text COLLATE "C" LIMIT 65)
          UNION ALL
          (SELECT c.command_id,NULL::uuid,NULL::bigint FROM rss_device_command.commands c
           LEFT JOIN mdm_software_deployment.operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,$2)
           WHERE c.tenant_id=$1::uuid AND c.device_id=$4 AND c.outbox_domain=$5 AND o.id IS NULL
             AND ($3::text IS NULL OR c.command_id COLLATE "C">$3 COLLATE "C")
           ORDER BY c.command_id COLLATE "C" LIMIT 65)
        ) SELECT command_id,operation,observed FROM candidates ORDER BY command_id COLLATE "C" LIMIT 65"#)
        .bind(tenant).bind(device).bind(after).bind(command_device).bind(domain).fetch_all(c).await
    })).await?;
    let more = rows.len() > 64;
    rows.truncate(64);
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

impl SoftwareService {
    /// Calibrate every existing declaration before runners start, including delayed
    /// and suspended work. Binding preserves wake identity and recovery history.
    pub fn initialize_resource_bindings(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<(), Error>> + Send + '_>,
    > {
        Box::pin(async move {
            let transactions = &self.transactions;
            let tenant = transactions.tenant;
            let scope = recovery_scope(tenant);
            let mut after = String::new();
            loop {
                let page = crate::deployment::transaction::inspect(
                &transactions.runtime, tenant, (transactions, scope.clone(), after.clone()),
                move |(transactions, scope, after), tx| Box::pin(async move {
                    let t = tx.tenant_id().to_string();
                    let domain = scope.reconciler().to_owned();
                    let after = after.clone();
                    let page: Vec<String> = tx.with_connection(move |c| Box::pin(async move {
                        sqlx::query_scalar("SELECT entity FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity>$3 ORDER BY entity LIMIT 64")
                            .bind(t).bind(domain).bind(after).fetch_all(c).await
                    })).await?;
                    for entity in &page {
                        let target = rss_reconcile::Target::new(scope.clone(), entity).map_err(|_| Error::Malformed)?;
                        let resources = resources_in(tx, entity).await?;
                        transactions.reconcile_messaging.bind_in(tx, &target, &resources).await?;
                    }
                    Ok(page)
                }),
            ).await?;
                if page.len() < 64 {
                    return Ok(());
                }
                after = page.last().expect("nonempty page").clone();
            }
        })
    }
}
