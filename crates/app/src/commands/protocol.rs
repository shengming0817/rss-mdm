use super::*;
use crate::device::DevicePrincipal;
use serde_json::{Value, json};
use sqlx::Row;
impl Commands {
    pub(crate) async fn management(
        &self,
        windows: &Arc<crate::windows::Windows>,
        principal: &DevicePrincipal,
        message: &rss_mdm_windows_mdm::syncml::Message,
        bytes: &[u8],
        audit: &Audit,
    ) -> std::result::Result<Vec<u8>, Error> {
        self.transact(
            (self, windows, principal, message, bytes, audit),
            audit,
            |ctx, tx| {
                Box::pin(async move {
                    let (s, w, p, m, b, a) = *ctx;
                    let tenant = s.tenant.to_string();
                    let instance = s.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    let tenant = s.tenant.to_string();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                                .bind(tenant)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    storage::lock(tx, p.device()).await?;
                    let principal = p.clone();
                    let windows = w.clone();
                    let message = m.clone();
                    let bytes = b.to_vec();
                    let audit = a.clone();
                    let reply = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(crate::windows::management::management_on(
                                    c, &windows, &principal, &message, &bytes, &audit,
                                )
                                .await)
                            })
                        })
                        .await??;
                    settle_reports(s, tx, p, m.header.session_id).await?;
                    storage::audit(tx, a, 200).await?;
                    Ok(reply.into_bytes())
                })
            },
        )
        .await
    }
}
async fn settle_reports(
    s: &Commands,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    session: u32,
) -> Result<()> {
    let tenant = s.tenant.to_string();
    let registration = p.registration().to_string();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT DISTINCT o.id::text FROM mdm_commands.operations o JOIN mdm_commands.attempts a ON(a.tenant_id,a.operation)=(o.tenant_id,o.id) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND a.session=$4 AND a.phase=$5 AND a.receipt_accepted AND d.terminal_at IS NULL ORDER BY o.id::text LIMIT 64").bind(tenant).bind(registration).bind(generation).bind(i64::from(session)).bind(AttemptPhase::Execute.as_str()).fetch_all(c).await})).await?;
    for id in ids {
        settle_one(s, tx, &id).await?;
    }
    Ok(())
}
async fn settle_one(s: &Commands, tx: &mut PgTransaction<'_>, id: &str) -> Result<()> {
    let id = id.to_owned();
    let op = storage::load(tx, corrupt(Uuid::parse_str(&id))?).await?;
    let command = s.required_command(tx, &op).await?;
    if command.status().is_terminal() {
        return Ok(());
    }
    let now = storage::now(tx).await?;
    if now >= op.request.deadline || !storage::approval_valid(tx, &op, now).await? {
        return Ok(());
    }
    let tenant = s.tenant.to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT status,value,receipt_accepted FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid AND phase=$3 ORDER BY ordinal DESC LIMIT 1").bind(tenant).bind(id).bind(AttemptPhase::Execute.as_str()).fetch_optional(c).await})).await?;
    let Some(row) = row else { return Ok(()) };
    if row.try_get::<Option<bool>, _>("receipt_accepted")? != Some(true) {
        return Ok(());
    }
    let status: Option<i32> = row.try_get("status")?;
    let value: Option<String> = row.try_get("value")?;
    let event = match status {
        Some(200) => dc::DeviceEvent::Received,
        Some(n) if n >= 400 => dc::DeviceEvent::Rejected,
        _ => return Ok(()),
    };
    let mut report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    let result = s.store.report(tx, &report).await?;
    if result.outcome == dc::Outcome::OutOfOrder {
        return Ok(());
    }
    if let Task::StateVerify {
        field,
        expected_value,
    } = &op.request.task
        && status == Some(200)
        && value.as_deref() == Some(expected_value)
        && !result.command.status().is_terminal()
    {
        report.event = dc::DeviceEvent::Reported(field.digest(expected_value)?);
        if s.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        };
    }
    Ok(())
}
pub(super) async fn observation(
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
    command_status: dc::Status,
) -> Result<Value> {
    if op.request.profile_target().is_some() {
        return apple::observation(tx, op, command_status).await;
    }
    let tenant = tx.tenant_id().to_string();
    let id = op.id.to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT DISTINCT ON(phase) id::text,ordinal,phase,status,value,received_at,receipt_accepted FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY phase,ordinal DESC").bind(tenant).bind(id).fetch_all(c).await})).await?;
    let phases = rows
        .iter()
        .map(|r| Ok((AttemptPhase::parse(&r.try_get::<String, _>("phase")?)?, r)))
        .collect::<Result<Vec<_>>>()?;
    let execute = phases
        .iter()
        .find(|(p, _)| *p == AttemptPhase::Execute)
        .map(|(_, r)| *r);
    let read = match op.request.task {
        Task::ProfileInstall { .. } | Task::ProfileRemove { .. } => {
            return Err(Error::Unsupported.into());
        }
        Task::StateVerify { .. } => execute,
        Task::Firewall { .. } => phases
            .iter()
            .find(|(p, _)| *p == AttemptPhase::Observe)
            .map(|(_, r)| *r),
    };
    let expired = storage::now(tx).await? >= op.request.deadline;
    let write_status = execute
        .map(|r| r.try_get::<Option<i32>, _>("status"))
        .transpose()?
        .flatten();
    let accepted = execute
        .map(|r| r.try_get::<Option<bool>, _>("receipt_accepted"))
        .transpose()?
        .flatten()
        == Some(true);
    let progress = match write_status.filter(|_| accepted) {
        Some(200) => "succeeded",
        Some(n) if n >= 400 => "failed",
        _ => "unknown",
    };
    let mut result = json!({"result":"unknown","effect":"unknown","progress":progress,"writeStatus":write_status});
    if let Some(r) = read {
        let status: Option<i32> = r.try_get("status")?;
        let value: Option<String> = r.try_get("value")?;
        let quality = match (status, &value) {
            (Some(200), Some(_)) => "success",
            (Some(404 | 405 | 501), _) => "unsupported",
            (Some(n), _) if n >= 400 => "failed",
            _ if expired => "missing",
            _ => "pending",
        };
        let verdict = observation_verdict(
            &op.request.task,
            quality,
            value.as_deref(),
            accepted,
            command_status,
        );
        result = json!({"attemptId":r.try_get::<String,_>("id")?,"attempt":r.try_get::<i64,_>("ordinal")?,"result":verdict,"effect":if verdict=="matched"{"verified_present"}else{"unknown"},"progress":progress,"writeStatus":write_status,"nativeStatus":status,"value":value,"quality":quality,"receivedAt":r.try_get::<Option<i64>,_>("received_at")?});
    }
    if matches!(op.request.task, Task::Firewall { .. }) {
        result["cleanup"] = json!("unsupported");
        result["observationScope"] = json!("device_firewall");
    }
    result["protocol"] = json!("mdm.windows");
    result["receiptAccepted"] = json!(accepted);
    Ok(result)
}

fn observation_verdict(
    task: &Task,
    quality: &str,
    value: Option<&str>,
    accepted: bool,
    status: dc::Status,
) -> &'static str {
    match task {
        Task::StateVerify { expected_value, .. } if quality == "success" && accepted => {
            if value != Some(expected_value) {
                "mismatched"
            } else if status == dc::Status::Applied {
                "matched"
            } else {
                "unknown"
            }
        }
        _ => "unknown",
    }
}
