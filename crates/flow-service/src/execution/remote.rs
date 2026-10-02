//! One-shot fanout owns a single bounded cursor; protocol owners retain their state machines.
use super::*;
use crate::planning::remote_operations::{self as remote, Remote};
use rss_mdm_execution_service::action_contract::Platform;
use rss_mdm_execution_service::frozen::Frozen;
use sqlx::Row;
pub fn operation_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("remote:")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT NOT o.staged OR EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=o.tenant_id AND r.remote_operation=o.id AND ((r.state->>'execution' IN('not_started','running') AND r.state->>'cancellation'<>'confirmed') OR (o.cancelled AND r.state->>'execution'='unknown' AND r.state->>'cancellation'='none'))) OR EXISTS(SELECT 1 FROM mdm_commands.operations n JOIN rss_device_command.commands d ON d.tenant_id=n.tenant_id AND d.command_id=n.id::text WHERE n.tenant_id=o.tenant_id AND n.remote_operation=o.id AND d.terminal_at IS NULL) FROM mdm_planning.remote_operations o WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemotePhase {
    Preparing,
    Dispatched,
    Cancelling,
    Expiring,
    Unknown,
    Completed,
}
fn phase(active: bool, unknown: bool, remote: &Remote, now: i64) -> RemotePhase {
    if active {
        if remote.cancelled {
            RemotePhase::Cancelling
        } else if remote.deadline <= now {
            RemotePhase::Expiring
        } else if !remote.staged {
            RemotePhase::Preparing
        } else {
            RemotePhase::Dispatched
        }
    } else if unknown {
        RemotePhase::Unknown
    } else {
        RemotePhase::Completed
    }
}
impl ExecutionService {
    pub async fn remote_phase_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        now: i64,
    ) -> Result<RemotePhase> {
        let active = active(tx, operation.id).await?;
        let tenant = tx.tenant_id().to_string();
        let id = operation.id;
        let unknown=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND remote_operation=$2 AND state->>'execution'='unknown')").bind(tenant).bind(id).fetch_one(c).await})).await?;
        Ok(phase(active, unknown, operation, now))
    }

    pub async fn advance_remote_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<()> {
        storage::lock(tx, &format!("remote:{id}")).await?;
        let operation = remote::storage::read_in(tx, id).await?;
        let now = storage::now(tx).await?;
        self.stage_remote_in(tx, &operation, now, audit).await?;
        self.recover_remote_page(tx, &operation, now).await
    }
    async fn stage_remote_in(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        now: i64,
        audit: &RequestAudit,
    ) -> Result<()> {
        let id = operation.id;
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
                    self.accept_remote_target(tx, operation, device, now, audit)
                        .await?;
                }
                checkpoint(tx, id, devices.last().cloned(), !more).await?;
            }
        }
        Ok(())
    }
    async fn recover_remote_page(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        now: i64,
    ) -> Result<()> {
        let id = operation.id;
        let tenant = tx.tenant_id().to_string();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT t.delivery_id,t.device,o.run_after AS previous,o.frozen->>'kind' AS kind FROM mdm_planning.remote_operation_targets t JOIN mdm_planning.remote_operations o ON(o.tenant_id,o.id)=(t.tenant_id,t.operation) WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.delivery_id>coalesce(o.run_after,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY t.delivery_id LIMIT 128").bind(tenant).bind(id).fetch_all(c).await
        })).await?;
        let total = rows.len();
        let previous = rows
            .first()
            .map(|r| r.try_get::<Option<Uuid>, _>("previous"))
            .transpose()?
            .flatten();
        let mut last = previous;
        let mut processed = 0;
        for row in rows {
            // Preserve time for cursor/commit and release the tenant audit lock.
            // A bounded row count alone is not a bounded transaction cost.
            if tx.deadline().timeout() < Duration::from_secs(3) {
                break;
            }
            let delivery: Uuid = row.try_get("delivery_id")?;
            if matches!(
                row.try_get::<&str, _>("kind")?,
                "execution" | "native_collection"
            ) {
                actions::recovery::recover_one(self, tx, delivery).await?;
            } else if operation.cancelled || operation.deadline <= now {
                let device: String = row.try_get("device")?;
                storage::lock(tx, &device).await?;
                let op = storage::load(tx, &self.protection, delivery).await?;
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
            last = Some(delivery);
            processed += 1;
        }
        let next = if processed < total || total == 128 {
            last
        } else {
            None
        };
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
            Frozen::Software { .. }
            | Frozen::AgentInstall { .. }
            | Frozen::MdmEnrollment { .. } => Err(Error::Unsupported.into()),
            Frozen::Execution { .. } | Frozen::NativeCollection { .. } => {
                self.accept_remote_execution(tx, operation, device, delivery, now)
                    .await
            }
            Frozen::Configuration { .. } => {
                self.accept_remote_configuration(tx, operation, device, delivery, audit)
                    .await
            }
        }
    }
    async fn accept_remote_execution(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        device: &str,
        delivery: Uuid,
        now: i64,
    ) -> Result<()> {
        let id = operation.id;

        let tenant = tx.tenant_id().to_string();
        let name = device.to_owned();
        let channel = if matches!(operation.frozen, Frozen::NativeCollection { .. }) {
            rss_mdm_inventory::Channel::Mdm
        } else {
            rss_mdm_inventory::Channel::Agent
        };
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::device::store::lock_channel(c, &tenant, &name, channel).await)
            })
        })
        .await??;
        let registration = if let Frozen::NativeCollection { action, .. } = &operation.frozen {
            let source = match action.input.platform {
                Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
                Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
            };
            match storage::current_registration(tx, device).await {
                Ok((registration, generation)) => {
                    if storage::require_source(tx, registration, source)
                        .await
                        .is_err()
                    {
                        return record_target(tx, id, device, None, Some("channel_unsupported"))
                            .await;
                    }
                    vec![(registration, generation)]
                }
                Err(Fault::Request(Error::Conflict)) => vec![],
                Err(e) => return Err(e),
            }
        } else {
            super::channels::agent_targets_in(tx, self.agent_store.clone(), vec![device.to_owned()])
                .await?
                .into_iter()
                .filter(|r| r.binding.script())
                .take(2)
                .map(|r| (r.registration, r.generation))
                .collect()
        };
        if registration.len() != 1 {
            return record_target(tx, id, device, None, Some("channel_unavailable")).await;
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
            actions::production::RunInput {
                source: actions::storage::Source::RemoteOperation { operation: id },
                target: &rss_mdm_execution_service::Target {
                    device: device.into(),
                    registration,
                    generation,
                },
                id: delivery,
                occurrence: format!("remote:{id}"),
                available: now,
                deadline: operation.deadline,
                now,
            },
        )
        .await?;
        Ok(())
    }
    async fn accept_remote_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
        operation: &Remote,
        device: &str,
        delivery: Uuid,
        audit: &RequestAudit,
    ) -> Result<()> {
        let id = operation.id;
        let Frozen::Configuration {
            native, platform, ..
        } = &operation.frozen
        else {
            return Err(Error::Malformed.into());
        };

        let (registration, _generation) = match storage::current_registration(tx, device).await {
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
                return record_target(tx, id, device, None, Some("channel_unsupported")).await;
            }
            Err(e) => return Err(e),
        };
        let native = native.open(
            &self.protection,
            self.tenant,
            rss_mdm_execution_service::configuration::Owner::Remote { operation: id },
        )?;
        let input = native.request(delivery, id.to_string(), operation.deadline, false)?;
        record_target(tx, id, device, Some(delivery), None).await?;
        let authority = crate::execution::authority::ExecutionAuthority::RemoteOperation {
            required: input.task.permissions()?,
            tenant: tx.tenant_id().to_string(),
            operation: id,
            device: device.into(),
        };
        let fingerprint = rss_mdm_execution_service::protection::fingerprint(
            &self.protection,
            self.tenant,
            device,
            "remote-command/v3",
            &(id, &input),
        )?;
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

#[cfg(test)]
#[path = "../../tests/execution/remote_phase_unit.rs"]
mod phase_tests;
