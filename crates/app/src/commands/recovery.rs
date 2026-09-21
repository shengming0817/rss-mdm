use super::*;
use rss_reconcile::{ActualState, DesiredState, ReconcileDiff, Reconciler};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use sqlx::Row;

pub(super) struct Timer(tokio::time::Instant);
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // Concrete monotonic injection boundary shared by all command controls.
    pub(super) fn new() -> Self {
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
        tokio::time::sleep_until(self.0 + at).await;
    }
}
fn failure(error: Error) -> rss_reconcile::Error {
    rss_reconcile::Error::new(match error {
        Error::CommitUnknown => rss_reconcile::ErrorKind::CommitUnknown,
        Error::Conflict => rss_reconcile::ErrorKind::Fenced,
        Error::Malformed | Error::Forbidden | Error::Unauthorized => {
            rss_reconcile::ErrorKind::Permanent
        }
        _ => rss_reconcile::ErrorKind::Transient,
    })
}
fn diagnostic(event: rss_reconcile::Observation) {
    let (phase, error) = match event {
        rss_reconcile::Observation::AttemptFailed { stage, error, .. } => {
            (format!("{stage:?}"), error)
        }
        rss_reconcile::Observation::ScanFailed { error, .. } => ("scan".to_owned(), error),
    };
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_command_recovery_failure","phase":phase,"reason":format!("{:?}",error.kind())})
    );
}
impl Commands {
    pub(crate) fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("mdm-command-recovery", Duration::from_secs(8));
        task.into_registration(move|cancel|async move {
            let timer=Timer::new();let control=rss_reconcile::Control::new(&timer,Duration::MAX,&cancel);
            let scope=rss_reconcile::Scope::new(self.tenant,"mdm.commands.v1").map_err(rss_runtime::ShutdownError::new)?;
            let policy=rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {concurrency:1,lease_ttl:Duration::from_secs(30),attempt_timeout:Duration::from_secs(6),scan_interval:Duration::from_secs(5),initial_backoff:Duration::from_secs(5),max_backoff:Duration::from_secs(60),max_attempts:1000}).map_err(rss_runtime::ShutdownError::new)?;
            tokio::select! {
                result=Box::pin(rss_reconcile::run(&self.reconcile,self.as_ref(),&scope,policy,&control, diagnostic))=>{result.map_err(rss_runtime::ShutdownError::new)?;},
                ()=self.relay(&cancel)=>{},
            }
            Ok(())
        })
    }
    async fn relay(&self, cancel: &tokio_util::sync::CancellationToken) {
        loop {
            tokio::select! {biased;
                ()=cancel.cancelled()=>return,
                result=async {tokio::time::sleep(Duration::from_secs(1)).await;self.relay_once().await}=>{
                    if result.is_err(){tracing::warn!(reason="command_relay","command delivery deferred");}
                }
            }
        }
    }
    pub(super) async fn relay_once(&self) -> std::result::Result<(), Error> {
        let claims = self
            .outbox
            .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::CommandStorage))?;
        for claim in claims {
            let message = PgOutboxStore::<()>::message(&claim);
            let id = message
                .message_id()
                .as_str()
                .strip_prefix("dispatch.")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(Error::Conflict)?;
            let fingerprint = message.fingerprint().as_bytes().to_vec();
            let result = self.accept_dispatch(id, fingerprint).await;
            // Only a confirmed gateway commit can authorize a published settlement.
            let settlement = if result.is_ok() {
                OutboxSettlement::Published(())
            } else {
                OutboxSettlement::Retry
            };
            self.outbox
                .settle(claim, settlement, deadline())
                .await
                .map_err(|_| Error::CommitUnknown)?;
            result?;
        }
        Ok(())
    }
    pub(super) async fn accept_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
    ) -> std::result::Result<(), Error> {
        let audit = Audit::new(self.tenant.to_string(), "command_dispatch");
        audit.operation(id, "command_dispatch");
        let result=self.transact((self,id,fingerprint,&audit),&audit,|ctx,tx|Box::pin(async move {
            let tenant=ctx.0.tenant.to_string();let id=ctx.1.to_string();let fingerprint=ctx.2.clone();
            let old=tx.with_connection(move|c|Box::pin(async move {
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(&id).bind(&fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false) {sqlx::query("UPDATE mdm_commands.operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Conflict)?;
            if old {ctx.3.management_result(crate::audit::ManagementResult::Replayed);}
            storage::audit(tx,ctx.3,200).await?;Ok(())
        })).await;
        audit.finalize(None);
        result
    }
}
async fn device(tx: &mut PgTransaction<'_>, entity: &str) -> Result<Option<String>> {
    let tenant = tx.tenant_id().to_string();
    let entity = entity.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT device FROM mdm_commands.devices WHERE tenant_id=$1::uuid AND encode(sha256(convert_to(device,'UTF8')),'hex')=$2").bind(tenant).bind(entity).fetch_optional(c).await})).await?)
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for Commands {
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
            let audit = Audit::new(self.tenant.to_string(), "management_read");
            let active=self.transact((self,claim.target().entity()),&audit,|ctx,tx|Box::pin(async move {
            let Some(device)=device(tx,ctx.1).await? else{return Ok(false)};
            let mut after=Uuid::nil();
            loop {
                let tenant=ctx.0.tenant.to_string();let name=device.clone();
                let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND device=$2 AND id>$3::uuid ORDER BY id LIMIT 64").bind(tenant).bind(name).bind(after.to_string()).fetch_all(c).await})).await?;
                if ids.is_empty(){return Ok(false);}
                for id in ids {
                    after=corrupt(Uuid::parse_str(&id))?;let op=storage::load(tx,after).await?;
                    if ctx.0.store.load(tx,op.scope,&op.command_id()?).await?.ok_or(Error::NotFound)?.status().is_terminal(){continue;}
                    return Ok(true);
                }
            }
        })).await;
            audit.finalize(None);
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
            let audit = Audit::new(self.tenant.to_string(), "management_write");
            let error = Mutex::new(None);
            let attempt=rss_reconcile_postgres::messaging::protect(&self.runtime,claim,control,(self,claim.target().entity(),&audit,&error),|ctx,tx|Box::pin(async move {
            let result:Result<()>=async {
                storage::admit(tx).await?;
                let Some(name)=device(tx,ctx.1).await? else{return Ok(())};
                storage::lock(tx,&name).await?;
                let tenant=ctx.0.tenant.to_string();let key=name.clone();
                let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT command_device::text,generation,epoch,recovery_after FROM mdm_commands.devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(key).fetch_one(c).await})).await?;
                let scope=dc::Scope::new(ctx.0.tenant,corrupt(dc::DeviceId::parse(&row.try_get::<String,_>("command_device")?))?);
                let after=row.try_get::<Option<String>,_>("recovery_after")?.map(|s|corrupt(dc::CommandId::parse(&s))).transpose()?;
                let registration=storage::current_registration(tx,&name).await;
                if let Ok((id,generation))=registration {storage::authority(ctx.0,tx,&name,id,generation).await?;}
                let page=ctx.0.store.recover(tx,scope,invalid(dc::BatchLimit::new(64))?,after.as_ref()).await?;
                if matches!(registration,Err(Fault::Request(Error::Conflict))) {
                    for command in &page.commands {if !command.status().is_terminal(){let transition=ctx.0.store.cancel(tx,scope,command.spec().id(),command.spec().coordinate()).await?;if transition.outcome==dc::Outcome::OutOfOrder{return Err(Error::Conflict.into());}}}
                } else {registration?;}
                let cursor=page.after.map(|s|s.as_str().to_owned());let tenant=ctx.0.tenant.to_string();
                tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.devices SET recovery_after=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(name).bind(cursor).execute(c).await?;Ok(())})).await?;
                Ok(())
            }.await;
            match result {Ok(())=>{ctx.2.mark_commit_started();Ok(())},Err(e)=>Err(rejection(e,ctx.3))}
        })).await;
            let result = settle(attempt, &audit, error);
            audit.finalize(None);
            result.map_err(failure)
        })
    }
}
