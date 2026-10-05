//! Retired Remote sources settle existing deliveries without producing new targets.
use super::*;
use crate::remote_operations::{self as remote, Remote};
use sqlx::Row;
pub fn operation_id(entity: &str) -> Option<Uuid> {
    entity
        .strip_prefix("remote:")
        .and_then(|v| Uuid::parse_str(v).ok())
}
pub async fn active(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=o.tenant_id AND r.remote_operation=o.id AND ((r.state->>'execution' IN('not_started','running') AND r.state->>'cancellation'<>'confirmed') OR (o.cancelled AND r.state->>'execution'='unknown' AND r.state->>'cancellation'='none'))) OR EXISTS(SELECT 1 FROM mdm_commands.operations n JOIN rss_device_command.commands d ON d.tenant_id=n.tenant_id AND d.command_id=n.id::text WHERE n.tenant_id=o.tenant_id AND n.remote_operation=o.id AND d.terminal_at IS NULL) FROM mdm_planning.remote_operations o WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(tenant).bind(id).fetch_one(c).await
    })).await?)
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemotePhase {
    Retired,
    Settling,
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
        } else {
            RemotePhase::Settling
        }
    } else if unknown {
        RemotePhase::Unknown
    } else if !remote.staged {
        RemotePhase::Retired
    } else {
        RemotePhase::Completed
    }
}
pub async fn remote_phase_in(
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

impl ExecutionService {
    pub async fn advance_remote_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
        storage::lock(tx, &format!("remote:{id}")).await?;
        let operation = remote::storage::read_in(tx, id).await?;
        let now = storage::now(tx).await?;
        self.recover_remote_page(tx, &operation, now).await
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
}

#[cfg(test)]
#[path = "../tests/remote_phase_unit.rs"]
mod tests;

#[cfg(feature = "integration")]
impl ExecutionService {
    /// Exercise the production retired-source recovery transaction against persisted history.
    pub async fn recover_remote_fixture(&self, id: Uuid) -> std::result::Result<(), Error> {
        let audit = RequestAudit::new(self.tenant.to_string(), "command_reconcile");
        audit.identify_service("command-recovery");
        let result = crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            &audit,
            (self, id),
            |ctx, tx| Box::pin(async move { ctx.0.advance_remote_in(tx, ctx.1).await }),
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
