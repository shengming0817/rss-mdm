//! One-shot fanout owns a single bounded cursor; protocol owners retain their state machines.
use super::*;
use crate::planning::{
    action_contract::Platform,
    policies::Frozen,
    remote_operations::{self as remote, Remote},
};
use sqlx::Row;
pub(super) fn operation_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("remote:")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub(super) async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT NOT o.staged OR EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=o.tenant_id AND r.remote_operation=o.id AND ((r.state->>'execution' IN('not_started','running') AND r.state->>'cancellation'<>'confirmed') OR (o.cancelled AND r.state->>'execution'='unknown' AND r.state->>'cancellation'='none'))) OR EXISTS(SELECT 1 FROM mdm_commands.operations n JOIN rss_device_command.commands d ON d.tenant_id=n.tenant_id AND d.command_id=n.id::text WHERE n.tenant_id=o.tenant_id AND n.remote_operation=o.id AND d.terminal_at IS NULL) FROM mdm_planning.remote_operations o WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}
impl ExecutionService {
    pub(super) async fn advance_remote_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<()> {
        storage::lock(tx, &format!("remote:{id}")).await?;
        let operation = remote::storage::read_in(tx, id).await?;
        let now = storage::now(tx).await?;
        if !operation.staged {
            if operation.cancelled || operation.deadline <= now {
                checkpoint(tx, id, None, true).await?;
            } else {
                let tenant = tx.tenant_id().to_string();
                let after=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<String>>("SELECT cursor FROM mdm_planning.remote_operations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(c).await})).await?;
                let mut devices = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query_scalar::<_, String>(
                                "SELECT device FROM mdm_planning.remote_target_page($1,$2,65)",
                            )
                            .bind(id)
                            .bind(after)
                            .fetch_all(c)
                            .await
                        })
                    })
                    .await?;
                let more = devices.len() > 64;
                devices.truncate(64);
                for device in &devices {
                    self.accept_remote_target(tx, &operation, device, now, audit)
                        .await?;
                }
                checkpoint(tx, id, devices.last().cloned(), !more).await?;
            }
        }
        let tenant = tx.tenant_id().to_string();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT t.delivery_id,t.device,o.frozen->>'kind' AS kind FROM mdm_planning.remote_operation_targets t JOIN mdm_planning.remote_operations o ON(o.tenant_id,o.id)=(t.tenant_id,t.operation) WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.delivery_id>coalesce(o.run_after,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY t.delivery_id LIMIT 128").bind(tenant).bind(id).fetch_all(c).await
        })).await?;
        let next = if rows.len() == 128 {
            rows.last()
                .map(|r| r.try_get::<Uuid, _>("delivery_id"))
                .transpose()?
        } else {
            None
        };
        for row in rows {
            let delivery: Uuid = row.try_get("delivery_id")?;
            if row.try_get::<&str, _>("kind")? == "execution" {
                actions::recovery::recover_one(self, tx, delivery).await?;
            } else if operation.cancelled || operation.deadline <= now {
                let device: String = row.try_get("device")?;
                storage::lock(tx, &device).await?;
                let op = storage::load(tx, delivery).await?;
                if !self.required_command(tx, &op).await?.status().is_terminal()
                    && self
                        .store
                        .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
                        .await?
                        .outcome
                        == dc::Outcome::OutOfOrder
                {
                    return Err(Error::Conflict.into());
                }
            }
        }
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.remote_operations SET run_after=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(next).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    async fn accept_remote_target(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        device: &str,
        now: i64,
        audit: &RequestAudit,
    ) -> Result<()> {
        storage::lock(tx, device).await?;
        let tenant = tx.tenant_id().to_string();
        let id = operation.id;
        let name = device.to_owned();
        let exists=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_planning.remote_operation_targets WHERE tenant_id=$1::uuid AND operation=$2 AND device=$3)").bind(tenant).bind(id).bind(name).fetch_one(c).await})).await?;
        if exists {
            return Ok(());
        }
        let delivery = Uuid::new_v4();
        match &operation.frozen {
            Frozen::Execution { .. } => {
                let tenant = tx.tenant_id().to_string();
                let name = device.to_owned();
                let registration=tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_as::<_,(Uuid,i64)>("SELECT r.id,r.generation FROM mdm_access.registrations r JOIN mdm_access.agent_bindings b ON(b.tenant_id,b.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active' AND b.wire_version=2 AND b.capabilities::jsonb ? 'task.execute.v2' ORDER BY r.id LIMIT 2").bind(tenant).bind(name).fetch_all(c).await
                })).await?;
                if registration.len() != 1 {
                    return record_target(tx, id, device, None, Some("agent_unavailable")).await;
                }
                let (registration, generation) = registration[0];
                let tenant = tx.tenant_id().to_string();
                let name = device.to_owned();
                let count=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$3").bind(tenant).bind(name).bind(now).fetch_one(c).await})).await?;
                if count >= 128 {
                    return record_target(tx, id, device, None, Some("capacity_exceeded")).await;
                }

                record_target(tx, id, device, Some(delivery), None).await?;
                actions::production::queue_run_in(
                    self,
                    tx,
                    actions::storage::Source::RemoteOperation { operation: id },
                    &actions::model::Target {
                        device: device.into(),
                        registration,
                        generation,
                    },
                    delivery,
                    format!("remote:{id}"),
                    now,
                    operation.deadline,
                    now,
                )
                .await?;
            }
            Frozen::Configuration {
                enabled, platform, ..
            } => {
                let (registration, generation) = match storage::current_registration(tx, device)
                    .await
                {
                    Ok(v) => v,
                    Err(Fault::Request(Error::Conflict)) => {
                        return record_target(tx, id, device, None, Some("mdm_unavailable")).await;
                    }
                    Err(e) => return Err(e),
                };
                let source = match platform {
                    Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
                    Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
                };
                match storage::require_source(tx, registration, source).await {
                    Ok(()) => (),
                    Err(Fault::Request(Error::Conflict | Error::Unsupported)) => {
                        return record_target(tx, id, device, None, Some("channel_unsupported"))
                            .await;
                    }
                    Err(e) => return Err(e),
                };
                let task = match platform {
                    Platform::Windows => {
                        let tenant = tx.tenant_id().to_string();
                        let cap=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(String,i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3").bind(tenant).bind(registration).bind(generation).fetch_optional(c).await})).await?;
                        let Some((os_version, edition)) = cap else {
                            return record_target(tx, id, device, None, Some("capability_unknown"))
                                .await;
                        };
                        if rss_mdm_windows_mdm::configuration::Platform::new(
                            &os_version,
                            edition as u32,
                        )
                        .and_then(|p| {
                            rss_mdm_windows_mdm::configuration::Firewall::compile(*enabled, &p)
                        })
                        .is_err()
                        {
                            return record_target(
                                tx,
                                id,
                                device,
                                None,
                                Some("platform_unsupported"),
                            )
                            .await;
                        }
                        Task::Firewall {
                            enabled: *enabled,
                            os_version,
                            edition: edition as u32,
                        }
                    }
                    Platform::Macos => {
                        let tenant = tx.tenant_id().to_string();
                        let name = device.to_owned();
                        let busy=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_apple.profiles p JOIN rss_device_command.commands d ON d.tenant_id=p.tenant_id AND d.command_id=p.operation::text WHERE p.tenant_id=$1::uuid AND p.device=$2 AND d.terminal_at IS NULL)").bind(tenant).bind(name).fetch_one(c).await})).await?;
                        if busy {
                            return record_target(tx, id, device, None, Some("configuration_busy"))
                                .await;
                        }
                        Task::ProfileInstall { enabled: *enabled }
                    }
                };
                record_target(tx, id, device, Some(delivery), None).await?;
                let input = Create {
                    operation_id: delivery,
                    task,
                    deadline: operation.deadline,
                };
                let authority = crate::authorization::ExecutionAuthority::RemoteOperation {
                    tenant: tx.tenant_id().to_string(),
                    operation: id,
                    device: device.into(),
                };
                let fingerprint = crate::transaction::fingerprint(&(id, device, &input))?;
                let fact_audit = audit.transaction_copy();
                fact_audit.identify_service("remote-operation");
                fact_audit.operation(delivery, "command_accept");
                fact_audit.target(device);
                let result = self
                    .queue_authorized_in(tx, device, &input, authority, fingerprint, &fact_audit)
                    .await;
                fact_audit.finalize(
                    result
                        .as_ref()
                        .err()
                        .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
                );
                result?;
                let target = service::target(tx.tenant_id(), device);
                rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| {
                    Box::pin(async { Ok(()) })
                })
                .await?;
            }
        }
        Ok(())
    }
}
async fn record_target(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    device: &str,
    delivery: Option<Uuid>,
    diagnosis: Option<&str>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let diagnosis = diagnosis.map(str::to_owned);
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_planning.remote_operation_targets(tenant_id,operation,device,status,delivery_id,diagnosis) VALUES($1::uuid,$2,$3,$4,$5,$6)").bind(tenant).bind(id).bind(device).bind(if delivery.is_some(){"accepted"}else{"blocked"}).bind(delivery).bind(diagnosis).execute(c).await?;Ok(())})).await?;
    Ok(())
}
async fn checkpoint(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    after: Option<String>,
    staged: bool,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.remote_operations SET cursor=$3,staged=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(after).bind(staged).execute(c).await?;Ok(())})).await?;
    Ok(())
}
