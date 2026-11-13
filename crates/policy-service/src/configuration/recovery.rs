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
    ) -> Result<Option<rss_mdm_agent_wire::DeviceId>> {
        let digest = entity
            .strip_prefix("configuration:")
            .ok_or(Error::Malformed)?
            .to_owned();
        let tenant = tx.tenant_id().to_string();
        Ok(tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_scalar("SELECT device FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND mdm_planning.configuration_device_key(device)=$2").bind(tenant).bind(digest).fetch_optional(c).await.and_then(|id|id.map(crate::configuration::device_id).transpose())
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
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 AND input_revision>observed_revision) OR EXISTS(SELECT 1 FROM mdm_planning.configuration_operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.device=$2 AND(c.terminal_at IS NULL OR (c.command_id IS NULL OR c.version<>o.observed_command_version OR c.outbox_domain IS DISTINCT FROM $3 OR c.device_id IS DISTINCT FROM (SELECT a.command_device FROM mdm_access.command_authorities a WHERE a.tenant_id=o.tenant_id AND a.device=o.device)))) OR EXISTS(SELECT 1 FROM mdm_planning.configuration_recovery WHERE tenant_id=$1::uuid AND device=$2 AND recovery_after IS NOT NULL) OR EXISTS(SELECT FROM rss_device_command.commands c JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(c.tenant_id,c.device_id) LEFT JOIN mdm_planning.configuration_operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,a.device) WHERE c.tenant_id=$1::uuid AND a.device=$2 AND c.outbox_domain=$3 AND o.id IS NULL)").bind(tenant).bind(device.into_uuid()).bind(messaging_domain().as_str().to_owned()).fetch_one(c).await
        })).await?)
    }
    pub(crate) async fn prepare_work_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
        audit: &RequestAudit,
    ) -> Result<rss_reconcile::ReconcileStep<Option<rss_mdm_agent_wire::DeviceId>>> {
        let device = if entity.starts_with("configuration:") {
            let device = self.device_in(tx, entity).await?;
            if let Some(device) = &device {
                let tenant = tx.tenant_id().to_string();
                let selected = *device;
                let locked = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(
                                rss_mdm_registration_service::lifecycle::try_lock_devices_in(
                                    rss_mdm_install_support::StorageProfile::Mdm,
                                    c,
                                    &tenant,
                                    &[selected],
                                )
                                .await,
                            )
                        })
                    })
                    .await??;
                if !locked {
                    return Ok(rss_reconcile::ReconcileStep::Deferred(
                        std::time::Duration::from_millis(50),
                    ));
                }
                storage::lock_device(tx, device).await?;
                let tenant = tx.tenant_id().to_string();
                let name = *device;
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT input_revision FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant).bind(name.into_uuid()).fetch_one(c).await?;Ok(())})).await?;
            }
            device
        } else {
            None
        };
        self.audit_store.prepare_in(tx, audit, &[]).await?;
        Ok(rss_reconcile::ReconcileStep::Ready(device))
    }
    pub(crate) async fn advance_work_in(
        &self,
        tx: &mut PgTransaction<'_>,
        entity: &str,
        device: Option<&rss_mdm_agent_wire::DeviceId>,
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
        device: &rss_mdm_agent_wire::DeviceId,
        audit: &RequestAudit,
    ) -> Result<()> {
        match storage::current_registration(
            tx,
            device,
            rss_mdm_registration_service::Purpose::Primary,
        )
        .await
        {
            Ok(_) => {
                rss_mdm_registration_service::command_authority::resolve_in(
                    &self.store,
                    tx,
                    device,
                )
                .await?;
            }
            Err(Fault::Request(Error::Conflict | Error::WindowsDeclaredEnrollmentNotReady)) => {}
            Err(e) => return Err(e),
        }
        let tenant = tx.tenant_id();
        let name = device.to_owned();
        let Some((command_device,_generation,epoch,cursor))=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_as::<_,(Uuid,i64,i64,Option<String>)>("SELECT a.command_device, a.generation, a.epoch, CASE WHEN r.authority_epoch = a.epoch THEN r.recovery_after END FROM mdm_access.command_authorities AS a LEFT JOIN mdm_planning.configuration_recovery AS r USING (tenant_id, device) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = $2 FOR UPDATE OF a").bind(tenant.to_string()).bind(name.into_uuid()).fetch_optional(c).await
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
        let candidates = command_candidates_in(tx, scope, device, after.as_ref()).await?;
        let mut commands = Vec::with_capacity(candidates.operations.len());
        for (id, _) in &candidates.operations {
            let id = stored(dc::CommandId::parse(&id.to_string()))?;
            commands.push(
                self.store
                    .recover_exact(tx, scope, &id)
                    .await?
                    .ok_or(Error::Unavailable(Failure::CommandInvariant))?,
            );
        }
        for command in &commands {
            let id = stored(Uuid::parse_str(command.spec().id().as_str()))?;
            let operation = storage::load(tx, &self.protection, id).await?;
            if !command.status().is_terminal() {
                let now = storage::now(tx).await?;
                if !storage::authority_decision(&self.source, &self.protection, tx, &operation, now)
                    .await?
                    .is_authorized()
                    && self
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
        for (id, previous_version) in candidates.operations {
            let operation = storage::load(tx, &self.protection, id).await?;
            let command = self.required_command(tx, &operation).await?;
            if command.version() == previous_version {
                continue;
            }
            let context = audit.transaction_copy();
            context.identify_service("configuration-recovery");
            context.owned_operation(
                rss_mdm_audit_integration::operation::OperationOwner::Configuration,
                id,
                "command_reconcile",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            context.target_device(device);
            context.target_device(&operation.device);
            let fact = Fact::business(
                &context,
                rss_mdm_audit_integration::operation::OperationOwner::Configuration,
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
                self.changes
                    .configuration_progressed_in(tx, &[*device])
                    .await?;
                self.wake_devices_in(tx, &[*device]).await?;
            }
        }
        let cursor = candidates.after;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move{
            sqlx::query("INSERT INTO mdm_planning.configuration_recovery(tenant_id,device,authority_epoch,recovery_after) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,device) DO UPDATE SET authority_epoch=excluded.authority_epoch,recovery_after=excluded.recovery_after").bind(tenant.to_string()).bind(name.into_uuid()).bind(epoch).bind(cursor).execute(c).await?;Ok(())
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
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.tenant.to_string(),
            "command_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("configuration-dispatch");
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Configuration,
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
                let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::Configuration,&format!("command:{}:dispatch",op.id),200,"success",None)?.with_activity(&dispatched)?;
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
    activity.target = Some(ActivityTarget { device: op.device });
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
) -> Result<CommandCandidates> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let after = after.map(|id| id.as_str().to_owned());
    let command_device = scope.device().as_uuid();
    let domain = messaging_domain().as_str().to_owned();
    let mut rows: Vec<(String, Option<Uuid>, Option<i64>)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as(r#"WITH candidates AS (
          (SELECT o.id::text AS command_id, CASE WHEN c.device_id=$4 AND c.outbox_domain=$5 THEN o.id END AS operation, o.observed_command_version AS observed
           FROM mdm_planning.configuration_operations o LEFT JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text)
           WHERE o.tenant_id=$1::uuid AND o.device=$2 AND ($3::text IS NULL OR o.id::text COLLATE "C">$3 COLLATE "C")
             AND (c.terminal_at IS NULL OR c.version<>o.observed_command_version OR c.device_id IS DISTINCT FROM $4 OR c.outbox_domain IS DISTINCT FROM $5)
           ORDER BY o.id::text COLLATE "C" LIMIT 65)
          UNION ALL
          (SELECT c.command_id,NULL::uuid,NULL::bigint FROM rss_device_command.commands c
           LEFT JOIN mdm_planning.configuration_operations o ON(o.tenant_id,o.id::text,o.device)=(c.tenant_id,c.command_id,$2)
           WHERE c.tenant_id=$1::uuid AND c.device_id=$4 AND c.outbox_domain=$5 AND o.id IS NULL
             AND ($3::text IS NULL OR c.command_id COLLATE "C">$3 COLLATE "C")
           ORDER BY c.command_id COLLATE "C" LIMIT 65)
        ) SELECT command_id,operation,observed FROM candidates ORDER BY command_id COLLATE "C" LIMIT 65"#)
        .bind(tenant).bind(device.into_uuid()).bind(after).bind(command_device).bind(domain).fetch_all(c).await
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
