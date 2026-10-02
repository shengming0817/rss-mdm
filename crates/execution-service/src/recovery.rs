use super::*;
use rss_mdm_audit_integration::Fact;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
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
impl ExecutionService {
    pub fn registration(
        self: Arc<Self>,
        signals: Arc<crate::worker_wake::Signals>,
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
        signals: &crate::worker_wake::Signals,
    ) -> std::result::Result<(), rss_runtime::ShutdownError> {
        let timer = Timer::new();
        let stopped = cancel.child_token();
        let control = rss_reconcile::Control::new(&timer, Duration::MAX, &stopped);
        let scope = recovery_scope(self.tenant);
        let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 1,
            lease_ttl: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(6),
            scan_interval: Duration::from_secs(5),
            idle_scan_interval: Duration::from_secs(5),
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
            max_attempts: 1000,
        })
        .map_err(rss_runtime::ShutdownError::new)?;
        let recovery = async {
            self.run_recovery(&scope, policy, &control, signals.command_recovery())
                .await
                .map(|_| ())
                .map_err(rss_runtime::ShutdownError::new)
        };
        let relay = async {
            self.relay(&stopped, signals.command_relay())
                .await
                .map_err(rss_runtime::ShutdownError::new)
        };
        tokio::pin!(recovery, relay);
        // Stop new claims when either branch exits, then let the other owner settle.
        // Claim, gateway transaction and outbox settlement each have a six-second limit.
        let (first, remaining) = tokio::select! {
            result = &mut recovery => { self.readiness.stop(); stopped.cancel(); (result, relay.await) },
            result = &mut relay => { self.readiness.stop(); stopped.cancel(); (result, recovery.await) },
            () = cancel.cancelled() => { self.readiness.stop(); stopped.cancel(); (recovery.await, relay.await) },
        };
        first.and(remaining)
    }

    pub async fn run_recovery<T: rss_reconcile::Timer>(
        &self,
        scope: &rss_reconcile::Scope,
        policy: rss_reconcile::Policy,
        control: &rss_reconcile::Control<'_, T>,
        notify: &tokio::sync::Notify,
    ) -> std::result::Result<rss_reconcile::Report, rss_reconcile::Error> {
        let result = Box::pin(rss_reconcile::run_with_notify(
            &health::ObservedStore(self),
            self,
            scope,
            policy,
            control,
            notify,
            |event| {
                // The runner can expire and drop the claim future before the store returns.
                if let rss_reconcile::Observation::ScanFailed { error, .. } = &event {
                    self.readiness.scan(Err(error.kind()));
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
    async fn relay(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
        notify: &tokio::sync::Notify,
    ) -> std::result::Result<(), Error> {
        let mut delay = 1;
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let result = self.relay_once().await;
            self.readiness.relay(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| failure(e.clone()).kind()),
            );
            match result {
                Ok(count) => {
                    delay = 1;
                    if count == 0 {
                        crate::worker_wake::wait(notify, cancel, None).await;
                    }
                }
                Err(error) if permanent(&error) => return Err(error),
                Err(_) => {
                    delay = (delay * 2).min(60);
                    tokio::select! { () = cancel.cancelled() => return Ok(()), () = tokio::time::sleep(Duration::from_secs(delay)) => {} }
                }
            }
        }
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
        let audit = RequestAudit::new(self.tenant.to_string(), "command_dispatch");
        audit.operation(id, "command_dispatch");
        audit.identify_service("command-dispatch");
        let result=crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move {
            let (service,id,fingerprint,audit) = ctx;
            let fact=Fact::business(audit,&format!("command:{id}:dispatch"),fingerprint,200,"success",None)?;
            let tenant=service.tenant.to_string();let id=id.to_string();let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false) {sqlx::query("UPDATE mdm_commands.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            if old {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            service.audit_store.append_in(tx,&fact,old).await?;
            if !old { crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Apple).await?; }
            Ok(())
        }),crate::transaction::TransactionOwner::Execution).await;
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
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_commands.devices WHERE tenant_id=$1::uuid AND encode(sha256(convert_to(device,'UTF8')),'hex')=$2").bind(tenant).bind(entity).fetch_optional(c).await})).await?)
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for ExecutionService {
    type State = bool;
    fn observe<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ReconcileDiff<bool>, rss_reconcile::Error>,
    > + Send {
        Box::pin(async move {
            control.check()?;
            let audit = RequestAudit::new(self.tenant.to_string(), "management_read");
            let active=crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,claim.target().entity()),|ctx,tx|Box::pin(async move {
            let (service,entity) = *ctx;
            if let Some(id)=remote_execution::operation_id(entity){return remote_execution::active(tx,id).await;}
            if let Some(id)=actions::recovery::policy_id(entity){return actions::recovery::active(tx,id).await;}
            if let Some(device)=entity.strip_prefix("configuration:") {return native_configuration::pending(tx,device).await;}
            let Some(device)=device(tx,entity).await? else{return Ok(false)};
            let mut after=Uuid::nil();
            loop {
                let tenant=service.tenant.to_string();let name=device.clone();
                let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND device=$2 AND id>$3::uuid ORDER BY id LIMIT 64").bind(tenant).bind(name).bind(after.to_string()).fetch_all(c).await})).await?;
                if ids.is_empty(){return Ok(false);}
                for id in ids {
                    after=stored(Uuid::parse_str(&id))?;let op=storage::load(tx,&service.protection,after).await?;
                    if service.required_command(tx,&op).await?.status().is_terminal(){continue;}
                    return Ok(true);
                }
            }
        }),crate::transaction::TransactionOwner::Execution).await;
            audit.finalize(
                active
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            Ok(ReconcileDiff::between(
                DesiredState::present(false),
                ActualState::present(active.map_err(failure)?),
            ))
        })
    }
    fn apply<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<bool>,
        control: &rss_reconcile::Control<'_, T>,
    ) -> impl std::future::Future<Output = std::result::Result<(), rss_reconcile::Error>> + Send
    {
        Box::pin(async move {
            let audit = RequestAudit::new(self.tenant.to_string(), "management_write");
            let error = Mutex::new(None);
            control.check()?;
            let attempt=self.runtime.local_tx_with_context(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),(self,claim,(self,claim.target().entity(),&audit,&error)),|(service,claim,context),tx|Box::pin(async move {
                if let Err(e)=service.audit_store.lock_in(tx).await {return Err(rejection(Fault::Request(e.into()),context.3,crate::transaction::TransactionOwner::Execution));}
                rss_reconcile_postgres::messaging::protect_in(tx,claim,context,|ctx,tx|Box::pin(async move {
            let (service,entity,audit,failure) = *ctx;
            let result:Result<()>=async {
                storage::admit(tx).await?;
                if let Some(id)=remote_execution::operation_id(entity){return service.advance_remote_in(tx,id,audit).await;}
                if let Some(id)=actions::recovery::policy_id(entity){return actions::recovery::recover(service,tx,id).await;}
                if let Some(device)=entity.strip_prefix("configuration:") {return service.reconcile_configuration(tx,device,audit).await;}
                let Some(name)=device(tx,entity).await? else{return Ok(())};
                storage::lock(tx,&name).await?;
                let tenant=service.tenant.to_string();let key=name.clone();
                let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT command_device::text,generation,epoch,recovery_after FROM mdm_commands.devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(key).fetch_one(c).await})).await?;
                let scope=dc::Scope::new(service.tenant,stored(dc::DeviceId::parse(&row.try_get::<String,_>("command_device")?))?);
                let after=row.try_get::<Option<String>,_>("recovery_after")?.map(|s|stored(dc::CommandId::parse(&s))).transpose()?;
                let registration=storage::current_registration(tx,&name).await;
                if let Ok((id,generation))=registration {storage::authority(service,tx,&name,id,generation).await?;}
                let tenant=service.tenant.to_string();let command_device=scope.device().as_uuid().to_string();let cursor=after.as_ref().map(|v|v.as_str().to_owned());
                let previous=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(String,i64,String)>("SELECT command_id,version,status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND terminal_at IS NULL AND ($3::text IS NULL OR command_id COLLATE \"C\">$3 COLLATE \"C\") ORDER BY command_id COLLATE \"C\" LIMIT 64").bind(tenant).bind(command_device).bind(cursor).fetch_all(c).await})).await?;
                let page=service.store.recover(tx,scope,checked_input(dc::BatchLimit::new(64))?,after.as_ref()).await?;
                if matches!(registration,Err(Fault::Request(Error::Conflict))) {
                    for command in &page.commands {if !command.status().is_terminal(){let transition=service.store.cancel(tx,scope,command.spec().id(),command.spec().coordinate()).await?;if transition.outcome==dc::Outcome::OutOfOrder{return Err(Error::Conflict.into());}}}
                } else {registration?;}
                for command in &page.commands {
                    if !command.status().is_terminal(){
                        let operation=storage::load(tx,&service.protection,stored(Uuid::parse_str(command.spec().id().as_str()))?).await?;
                        let now=storage::now(tx).await?;
                        if !storage::approval_valid(&service.source, &service.protection,tx,&operation,now).await? && service.store.cancel(tx,scope,command.spec().id(),command.spec().coordinate()).await?.outcome==dc::Outcome::OutOfOrder {return Err(Error::Conflict.into());}

                    }
                }
                for (id,version,status) in previous {
                    let operation=storage::load(tx,&service.protection,stored(Uuid::parse_str(&id))?).await?;
                    let command=service.required_command(tx,&operation).await?;
                    if command.version()!=version {
                        if command.status().is_terminal() {crate::wake::wake_native_in(tx,&operation.device).await?;}
                        let fact_audit=audit.transaction_copy();fact_audit.identify_service("command-recovery");fact_audit.operation(operation.id,"command_reconcile");fact_audit.target(&operation.device);fact_audit.registration(operation.registration);
                        let details=serde_json::json!({"before":status,"after":service::status(command.status()),"version":command.version()});
                        let fingerprint=checked_input(serde_json::to_vec(&details))?;
                        let fact=Fact::business(&fact_audit,&format!("command:{id}:recover:{}",command.version()),&fingerprint,200,"success",None)?.with_details(details)?;
                        fact_audit.finalize(None);
                        service.audit_store.append_in(tx,&fact,false).await?;
                    }
                }
                let cursor=page.after.map(|s|s.as_str().to_owned());let tenant=service.tenant.to_string();
                tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.devices SET recovery_after=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(name).bind(cursor).execute(c).await?;Ok(())})).await?;
                Ok(())
            }.await;
            match result {Ok(())=>{audit.mark_commit_started();Ok(())},Err(e)=>Err(rejection(e,failure,crate::transaction::TransactionOwner::Execution))}
        })).await
            })).await;
            let result = settle(
                attempt,
                &audit,
                error,
                crate::transaction::TransactionOwner::Execution,
            );
            audit.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result.map_err(failure)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_input_corruption_is_terminal_but_storage_outage_can_retry() {
        let integrity = Error::Unavailable(Failure::NativeInputIntegrity);
        assert!(permanent(&integrity));
        assert_eq!(
            failure(integrity).kind(),
            rss_reconcile::ErrorKind::Permanent
        );
        let outage = Error::Unavailable(Failure::CommandStorage);
        assert!(!permanent(&outage));
        assert_eq!(failure(outage).kind(), rss_reconcile::ErrorKind::Transient);
    }
}
