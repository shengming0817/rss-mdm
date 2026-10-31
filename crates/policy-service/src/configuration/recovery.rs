//! Configuration work shares the Policy runner budget and preserves owner-local command decoding.
use super::*;
use rss_mdm_audit_integration::{Fact, activity::*};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use rss_transactional_messaging_postgres::PgOutboxStore;
pub(crate) fn owns_entity(entity: &str) -> bool {
    matches!(entity, "configuration-inputs" | "configuration-relay")
        || entity
            .strip_prefix("configuration:")
            .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
impl Transactions {
    pub(crate) async fn device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
    ) -> Result<Option<String>> {
        let digest = entity
            .strip_prefix("configuration:")
            .ok_or(Error::Malformed)?
            .to_owned();
        let tenant = tx.tenant_id().to_string();
        Ok(tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT device FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND mdm_planning.configuration_device_key(device)=$2").bind(tenant).bind(digest).fetch_optional(c).await
        })).await?)
    }
    pub(crate) async fn work_pending_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
    ) -> Result<bool> {
        if entity == "configuration-relay" {
            return Ok(true);
        }
        if entity == "configuration-inputs" {
            return source_changes::pending_in(tx, self.source.clone()).await;
        }
        let Some(device) = self.device_in(tx, entity).await? else {
            return Ok(false);
        };
        let tenant = tx.tenant_id().to_string();
        Ok(tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 AND input_revision>observed_revision) OR EXISTS(SELECT 1 FROM mdm_planning.configuration_operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR c.version<>o.observed_command_version)) OR EXISTS(SELECT 1 FROM mdm_planning.configuration_recovery WHERE tenant_id=$1::uuid AND device=$2 AND recovery_after IS NOT NULL)").bind(tenant).bind(device).fetch_one(c).await
        })).await?)
    }
    pub(crate) async fn prepare_work_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
        audit: &RequestAudit,
    ) -> Result<Option<String>> {
        let device = if entity.starts_with("configuration:") {
            let device = self.device_in(tx, entity).await?;
            if let Some(device) = &device {
                storage::lock_device(tx, device).await?;
                let tenant = tx.tenant_id().to_string();
                let name = device.clone();
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT input_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name).fetch_one(c).await?;Ok(())})).await?;
            }
            device
        } else {
            None
        };
        self.audit_store.prepare_in(tx, audit, &[]).await?;
        Ok(device)
    }
    pub(crate) async fn advance_work_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
        device: Option<&str>,
        cut: Option<&rss_mdm_inventory::AssetCut>,
        audit: &RequestAudit,
    ) -> Result<()> {
        if entity == "configuration-inputs" {
            source_changes::advance_in(tx, self, self.source.clone(), cut.ok_or(Error::Malformed)?)
                .await?;
            return source_changes::clear_failure_in(tx).await;
        }
        if let Some(device) = device {
            if claims::pending(tx, device).await? {
                self.reconcile_in(tx, device, audit).await?;
            }
            self.recover_device_in(tx, device, audit).await?;
        }
        Ok(())
    }
    async fn recover_device_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        match storage::current_registration(
            tx,
            device,
            rss_mdm_registration_service::Purpose::Primary,
        )
        .await
        {
            Ok((registration, generation)) => {
                rss_mdm_registration_service::command_authority::resolve_in(
                    &self.store,
                    tx,
                    device,
                    registration,
                    generation,
                )
                .await?;
            }
            Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => {}
            Err(e) => return Err(e),
        }
        let tenant = tx.tenant_id();
        let name = device.to_owned();
        let Some((command_device,_generation,epoch,cursor))=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_as::<_,(Uuid,i64,i64,Option<String>)>("SELECT a.command_device,a.generation,a.epoch,CASE WHEN r.authority_epoch=a.epoch THEN r.recovery_after END FROM mdm_access.command_authorities a LEFT JOIN mdm_planning.configuration_recovery r USING(tenant_id,device) WHERE a.tenant_id=$1::uuid AND a.device=$2 FOR UPDATE OF a").bind(tenant.to_string()).bind(name).fetch_optional(c).await
        })).await? else{return Ok(())};
        let scope = dc::Scope::new(
            tenant,
            stored(dc::DeviceId::parse(&command_device.to_string()))?,
        );
        let after = cursor
            .as_deref()
            .map(dc::CommandId::parse)
            .transpose()
            .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
        let page = self
            .store
            .recover(
                tx,
                scope,
                checked_input(dc::BatchLimit::new(64))?,
                after.as_ref(),
            )
            .await?;
        for command in &page.commands {
            let id = stored(Uuid::parse_str(command.spec().id().as_str()))?;
            if !storage::owns_in(tx, id).await? {
                continue;
            }
            let operation = storage::load(tx, &self.protection, id).await?;
            if !command.status().is_terminal() {
                let now = storage::now(tx).await?;
                if !storage::authority_decision(&self.source, &self.protection, tx, &operation, now)
                    .await?
                    .is_authorized()
                {
                    if self
                        .store
                        .cancel(
                            tx,
                            operation.scope,
                            &operation.command_id()?,
                            operation.coordinate,
                        )
                        .await?
                        .outcome
                        == dc::Outcome::OutOfOrder
                    {
                        return Err(Error::Conflict.into());
                    }
                }
            }
        }
        // Observe transitions made by RSS recovery regardless of which owner's scan encountered them.
        let name = device.to_owned();
        let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT o.id FROM mdm_planning.configuration_operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND c.version<>o.observed_command_version ORDER BY o.id LIMIT 64").bind(tenant.to_string()).bind(name).fetch_all(c).await
        })).await?;
        for id in ids {
            let operation = storage::load(tx, &self.protection, id).await?;
            let command = self.required_command(tx, &operation).await?;
            let context = audit.transaction_copy();
            context.identify_service("configuration-recovery");
            context.operation(
                id,
                "command_reconcile",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            context.target_device(device);
            context.registration(operation.registration);
            let fact = Fact::business(
                &context,
                &format!("command:{id}:recover:{}", command.version()),
                200,
                "success",
                None,
            )?
            .with_details(serde_json::json!({"version":command.version()}))?
            .with_activity(&activity(
                &operation,
                command.status(),
                ActivityPhase::Reconciled,
            ))?;
            context.finalize(None);
            self.audit_store.append_in(tx, &fact).await?;
            let version = command.version();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.configuration_operations SET observed_command_version=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).bind(version).execute(c).await?;Ok(())})).await?;
            if command.status().is_terminal() {
                self.wake_devices_in(tx, &[device.into()]).await?;
            }
        }
        let cursor = page.after.map(|v| v.as_str().to_owned());
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("INSERT INTO mdm_planning.configuration_recovery(tenant_id,device,authority_epoch,recovery_after) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,device) DO UPDATE SET authority_epoch=excluded.authority_epoch,recovery_after=excluded.recovery_after").bind(tenant.to_string()).bind(name).bind(epoch).bind(cursor).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
    pub async fn relay_once<T: rss_reconcile::Timer>(
        &self,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<usize, Error> {
        let claims = self
            .outbox
            .claim_partition_heads(
                std::num::NonZeroUsize::MIN,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
            )
            .await
            .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?;
        let count = claims.len();
        for claim in claims {
            let message = PgOutboxStore::<()>::message(&claim);
            let id = message
                .message_id()
                .as_str()
                .strip_prefix("dispatch.")
                .and_then(|v| Uuid::parse_str(v).ok())
                .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            let fingerprint = message.fingerprint().as_bytes().to_vec();
            let result = self
                .accept_dispatch(
                    id,
                    fingerprint,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                )
                .await;
            if matches!(
                result,
                Err(Error::Unavailable(
                    Failure::CommandInvariant | Failure::NativeInputIntegrity
                ))
            ) {
                return result.map(|_| 0);
            }
            let settlement = if result.is_ok() {
                OutboxSettlement::Published(())
            } else {
                OutboxSettlement::Retry
            };
            self.outbox
                .settle(
                    claim,
                    settlement,
                    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                        control.remaining(),
                    ),
                )
                .await
                .map_err(|_| Error::Unavailable(Failure::PolicyStorage))?;
            result?;
        }
        Ok(count)
    }
    async fn accept_dispatch(
        &self,
        id: Uuid,
        fingerprint: Vec<u8>,
        budget: rss_transactional_messaging::policy::OperationDeadline,
    ) -> std::result::Result<(), Error> {
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("configuration-dispatch");
        audit.operation(
            id,
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let result=run_budget(&self.audit_store,&self.runtime,self.tenant,&audit,budget,(self,id,fingerprint,&audit),|ctx,tx|Box::pin(async move{
            let (service,id,fingerprint,audit)=ctx;service.audit_store.prepare_in(tx,audit,&[]).await?;
            let tenant=tx.tenant_id().to_string();let operation=*id;let fingerprint=fingerprint.clone();
            let old=tx.with_connection(move|c|Box::pin(async move{
                let old=sqlx::query_scalar::<_,bool>("SELECT gateway_accepted FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_fingerprint=$3 FOR UPDATE").bind(&tenant).bind(operation).bind(fingerprint).fetch_optional(&mut *c).await?;
                if old==Some(false){sqlx::query("UPDATE mdm_planning.configuration_operations SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(operation).execute(c).await?;}
                Ok(old)
            })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
            if !old{
                let op=storage::load(tx,&service.protection,*id).await?;
                let mut dispatched = activity(&op,service.required_command(tx,&op).await?.status(),ActivityPhase::Dispatched);
                dispatched.delivery=Some(ActivityDelivery::Dispatched);
                let fact=Fact::business(audit,&format!("command:{}:dispatch",op.id),200,"success",None)?.with_activity(&dispatched)?;
                service.audit_store.append_in(tx,&fact).await?;
                // Channel consumers retain their existing durable candidate scans.
                tx.with_connection(|c|Box::pin(async move{sqlx::query("SELECT pg_notify('mdm_work_'||replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'apple'),pg_notify('mdm_work_'||replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'windows_push')").execute(c).await?;Ok(())})).await?;
            }else{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
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

pub(crate) fn activity(
    op: &super::storage::Operation,
    status: dc::Status,
    phase: rss_mdm_audit_integration::activity::ActivityPhase,
) -> rss_mdm_audit_integration::activity::Activity {
    use super::authority::Authority as A;
    use rss_mdm_audit_integration::activity::*;
    let kind = if matches!(&op.authority, A::Policy { .. }) {
        ActivityKind::Configuration
    } else {
        ActivityKind::Execution
    };
    let mut activity = Activity::new(kind, phase);
    activity.target = Some(ActivityTarget {
        device: op.device.clone(),
        registration: op.registration,
        generation: op.registration_generation,
    });
    activity.links.operation = Some(op.id);
    match &op.authority {
        A::Policy {
            policy,
            version,
            origin,
            ..
        } => {
            activity.links.policy = Some(*policy);
            activity.links.version = Some(*version);
            activity.origin = *origin;
        }
        A::Retirement {
            version,
            origin,
            retirement,
            ..
        } => {
            activity.links.version = Some(*version);
            activity.links.retirement = Some(*retirement);
            activity.origin = *origin;
        }
    }
    activity.execution = Some(match status {
        dc::Status::Queued => ActivityExecution::Queued,
        dc::Status::Published => ActivityExecution::Published,
        dc::Status::Received => ActivityExecution::Received,
        dc::Status::Applied => ActivityExecution::Applied,
        dc::Status::Rejected => ActivityExecution::Rejected,
        dc::Status::TimedOut => ActivityExecution::TimedOut,
        dc::Status::Superseded => ActivityExecution::Superseded,
        dc::Status::Cancelled => ActivityExecution::Cancelled,
    });
    activity.delivery = Some(match status {
        dc::Status::Queued => ActivityDelivery::Queued,
        dc::Status::Published => ActivityDelivery::Dispatched,
        dc::Status::Received | dc::Status::Applied | dc::Status::Rejected => {
            ActivityDelivery::Received
        }
        _ => ActivityDelivery::Unknown,
    });
    activity
}
