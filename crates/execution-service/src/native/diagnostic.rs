//! Diagnostic native steps use the existing operation, attempts and receipt transaction.
use super::*;
use rss_mdm_windows_mdm::native::diagnostic::{Input, Progress, Step};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Transfer {
    Pending,
    Ready,
    Abandoned,
    Blocked,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct State {
    pub native: Progress,
    pub max_bytes: u64,
    pub retention_seconds: u64,
    pub accepted_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub transfer: Transfer,
    pub reason: Option<String>,
}
impl State {
    pub fn new(input: &Input, config: &rss_mdm_content_service::Config) -> Self {
        Self {
            native: Progress::new(input),
            max_bytes: input.max_bytes.min(config.max_artifact_bytes),
            retention_seconds: config.retention_seconds,
            accepted_at: None,
            expires_at: None,
            transfer: Transfer::Pending,
            reason: None,
        }
    }
    pub fn pending(&self) -> bool {
        matches!(self.transfer, Transfer::Pending)
    }
}
pub(crate) fn input(task: &Task) -> Option<&Input> {
    match task {
        Task::Windows {
            request: W::DiagnosticLog { request },
        } => Some(request),
        _ => None,
    }
}
pub(crate) async fn load(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
) -> std::result::Result<State, Error> {
    let state: Option<serde_json::Value> = sqlx::query_scalar("SELECT diagnostic_progress FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant.to_string()).bind(operation).fetch_one(c).await.map_err(db)?;
    serde_json::from_value(state.ok_or_else(protocol)?).map_err(|_| protocol())
}
pub(crate) async fn save(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    state: &State,
) -> std::result::Result<(), Error> {
    sqlx::query("UPDATE mdm_commands.operations SET diagnostic_progress=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant.to_string()).bind(operation).bind(serde_json::to_value(state).map_err(|_| protocol())?).execute(c).await.map_err(db)?;
    Ok(())
}
/// Called after admitted receipts are persisted and before the same transaction sends another step.
pub(super) async fn accept(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    op: &Create,
    attempt: Uuid,
) -> std::result::Result<(), Error> {
    let Some(input) = input(&op.task) else {
        return Ok(());
    };
    let mut state = load(c, p.tenant(), op.operation_id).await?;
    if !state.pending() || state.native.step == Step::Complete {
        return Ok(());
    }
    let step: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT diagnostic_step FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(p.tenant().to_string())
    .bind(attempt)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let Some(step) = step else {
        return Err(protocol());
    };
    let step: Step = serde_json::from_value(step).map_err(|_| protocol())?;
    if step != state.native.step {
        return Ok(());
    }
    let rows = sqlx::query("SELECT command,item_ordinal,kind,uri,status,receipt_accepted,value,value IS NOT NULL AS has_value,result_accepted FROM mdm_commands.attempt_items WHERE tenant_id=$1::uuid AND attempt=$2 ORDER BY command,item_ordinal")
        .bind(p.tenant().to_string()).bind(attempt).fetch_all(&mut *c).await.map_err(db)?;
    let evidence = rows
        .iter()
        .map(|r| item_evidence(r, ReceiptRole::Execute))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if evidence
        .iter()
        .any(|e| e.receipt_accepted && e.status.is_some_and(s::rejected_status))
    {
        state.transfer = Transfer::Blocked;
        state.reason = Some("native_rejected".into());
        return save(c, p.tenant(), op.operation_id, &state).await;
    }
    if evidence.is_empty() || !evidence.iter().all(ItemEvidence::successful) {
        return Ok(());
    }
    if rows.iter().any(|r| {
        r.try_get::<String, _>("kind").ok().as_deref() == Some("get")
            && r.try_get::<Option<Vec<u8>>, _>("value")
                .ok()
                .flatten()
                .is_none()
    }) {
        state.transfer = Transfer::Blocked;
        state.reason = Some("diagnostic_missing_value".into());
        return save(c, p.tenant(), op.operation_id, &state).await;
    }
    let mut count = None;
    let mut index = None;
    let mut bytes = None;
    for row in &rows {
        if row.try_get::<String, _>("kind").map_err(db)? != "get" {
            continue;
        }
        let plain = protection
            .open_bytes(
                &row.try_get::<Vec<u8>, _>("value").map_err(db)?,
                &result_aad(
                    p.tenant(),
                    p.registration(),
                    p.generation(),
                    attempt,
                    row.try_get("command").map_err(db)?,
                    row.try_get("item_ordinal").map_err(db)?,
                )?,
            )
            .map_err(|_| protocol())?;
        let value = std::str::from_utf8(plain.expose()).map_err(|_| protocol())?;
        let uri: String = row.try_get("uri").map_err(db)?;
        if uri.ends_with("/BlockCount") {
            count = value.parse::<i64>().ok();
        } else if uri.ends_with("/BlockIndexToRead") {
            index = value.parse::<u32>().ok();
        } else if uri.ends_with("/BlockData") {
            use base64::Engine;
            let max_encoded = (usize::from(input.block_size_kb) * 1024).div_ceil(3) * 4;
            if value.len() <= max_encoded {
                bytes = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .ok()
                    .map(zeroize::Zeroizing::new);
            }
        }
    }
    let mut bounded = input.clone();
    bounded.max_bytes = state.max_bytes;
    if state
        .native
        .accept(
            &bounded,
            count,
            index,
            bytes.as_deref().map(|v| v.as_slice()),
        )
        .is_err()
    {
        state.transfer = Transfer::Blocked;
        state.reason = Some("diagnostic_integrity_or_limit".into());
    }
    if state.native.step == Step::Complete {
        let at = now(c).await?;
        state.accepted_at = Some(at);
        state.expires_at = Some(
            at.checked_add(i64::try_from(state.retention_seconds).map_err(|_| protocol())?)
                .ok_or_else(protocol)?,
        );
    }
    save(c, p.tenant(), op.operation_id, &state).await
}
/// Emit one bounded step through the same command allocator, encrypted attempt and transcript.
pub(super) async fn send(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    op: &Create,
    platform: Option<Context>,
    response: &mut Message,
    limits: &CodecLimits,
) -> std::result::Result<bool, Error> {
    let log = input(&op.task).ok_or_else(protocol)?;
    let state = load(c, p.tenant(), op.operation_id).await?;
    if !state.pending() || state.native.step == Step::Complete {
        return Ok(false);
    }
    let Some(platform) = platform else {
        return Ok(true);
    };
    let tenant = p.tenant().to_string();
    // Exclude other operations targeting the same native file cursor, including raw SyncML reads.
    let others=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.id<>$4 AND d.terminal_at IS NULL AND EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id)")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(op.operation_id).fetch_all(&mut *c).await.map_err(db)?;
    for row in others {
        let other = crate::input_storage::open_row(
            protection,
            p.tenant(),
            row.try_get("id").map_err(db)?,
            &row,
            "request",
        )?;
        if input(&other.task).is_some_and(|v| v.file_context == log.file_context) {
            return Ok(true);
        }
        if let Task::Windows {
            request: W::SyncMl { request },
        } = &other.task
            && conflicts(request, log)?
        {
            return Ok(true);
        }
    }
    let old=sqlx::query("SELECT id,ordinal,session,diagnostic_step FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY ordinal DESC LIMIT 1")
        .bind(&tenant).bind(op.operation_id).fetch_optional(&mut *c).await.map_err(db)?;
    let mut ordinal = 1;
    if let Some(old) = &old {
        ordinal = old
            .try_get::<i64, _>("ordinal")
            .map_err(db)?
            .checked_add(1)
            .ok_or_else(protocol)?;
        let step: Step = serde_json::from_value(old.try_get("diagnostic_step").map_err(db)?)
            .map_err(|_| protocol())?;
        if step == state.native.step {
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempt_items WHERE tenant_id=$1::uuid AND attempt=$2 AND (NOT coalesce(receipt_accepted,false) OR status IS NULL OR (kind='get' AND NOT coalesce(result_accepted,false))))")
                .bind(&tenant).bind(old.try_get::<Uuid,_>("id").map_err(db)?).fetch_one(&mut *c).await.map_err(db)?;
            if old.try_get::<i64, _>("session").map_err(db)?
                == i64::from(response.header.session_id)
                || (pending && matches!(step, Step::Trigger | Step::Size))
            {
                return Ok(true);
            }
        }
    }
    // Count waits may recur, but are bounded by the immutable operation deadline.
    let request = log
        .request(state.native.step)
        .map_err(|_| Error::Malformed)?;
    let count = request.command_count().map_err(|_| protocol())?;
    let id = crate::device::store::allocate_commands_in(c, p, i64::from(count)).await?;
    let command = match request.compile(platform, id) {
        Ok(v) => v.command,
        Err(_) => {
            let mut state = state;
            state.transfer = Transfer::Blocked;
            state.reason = Some("diagnostic_native_unsupported".into());
            save(c, p.tenant(), op.operation_id, &state).await?;
            return Ok(false);
        }
    };
    let frame = match s::fragment(response, &command, 0, limits.syncml_bytes, limits) {
        Ok(v) => v,
        Err(rss_mdm_windows_mdm::CodecError::LimitExceeded) => return Ok(true),
        Err(_) => return Err(protocol()),
    };
    let mut wire = frame.message.clone();
    wire.commands = vec![command.clone()];
    let (wire, _) = s::encode_request(&wire, &CodecLimits::default()).map_err(|_| protocol())?;
    let attempt = Uuid::new_v4();
    let sealed = protection
        .seal_bytes(
            &wire,
            &crate::protection::aad(
                p.tenant(),
                "windows.attempt.request",
                &(p.registration(), p.generation(), attempt),
            )?,
        )
        .map_err(|_| protocol())?;
    sqlx::query("INSERT INTO mdm_commands.attempts(tenant_id,id,operation,ordinal,credential,session,message,phase,request,platform,diagnostic_step) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'execute',$8,$9,$10)")
        .bind(&tenant).bind(attempt).bind(op.operation_id).bind(ordinal).bind(p.credential()).bind(i64::from(response.header.session_id)).bind(i64::from(response.header.message_id)).bind(sealed).bind(serde_json::to_value(platform).map_err(|_|protocol())?).bind(serde_json::to_value(state.native.step).map_err(|_|protocol())?).execute(&mut *c).await.map_err(db)?;
    for item in expected_items(&command)? {
        sqlx::query("INSERT INTO mdm_commands.attempt_items(tenant_id,attempt,command,item_ordinal,kind,uri,parent_command) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(&tenant).bind(attempt).bind(i64::from(item.command)).bind(item.ordinal).bind(item.kind).bind(item.uri).bind(item.parent.map(i64::from)).execute(&mut *c).await.map_err(db)?;
    }
    *response = frame.message;
    Ok(true)
}

/// Isolate a live file transfer from raw cursor writes and log regeneration commands.
pub(super) async fn cursor_busy(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    op: &Create,
) -> std::result::Result<bool, Error> {
    let Task::Windows {
        request: W::SyncMl { request },
    } = &op.task
    else {
        return Ok(false);
    };
    let objects = request.objects().map_err(|_| protocol())?;
    if !objects.iter().any(|o| o.key().contains("/DiagnosticLog/")) {
        return Ok(false);
    }
    let rows=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request FROM mdm_commands.operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.id<>$4 AND d.terminal_at IS NULL AND o.diagnostic_progress->>'transfer'='pending' AND EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id)")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(op.operation_id).fetch_all(c).await.map_err(db)?;
    for row in rows {
        let other = crate::input_storage::open_row(
            protection,
            p.tenant(),
            row.try_get("id").map_err(db)?,
            &row,
            "request",
        )?;
        let Some(log) = input(&other.task) else {
            return Err(protocol());
        };
        if conflicts(request, log)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn conflicts(
    request: &rss_mdm_windows_mdm::native::Request,
    log: &Input,
) -> std::result::Result<bool, Error> {
    let prefix = log
        .request(Step::Count)
        .map_err(|_| protocol())?
        .objects()
        .map_err(|_| protocol())?[0]
        .key()
        .trim_end_matches("BlockCount")
        .to_owned();
    let context = format!("/{}/", log.file_context);
    Ok(request.objects().map_err(|_| protocol())?.iter().any(|v| {
        v.key().starts_with(&prefix)
            || (v.key().contains("/DiagnosticLog/EtwLog/") && v.key().contains(&context))
            || v.key()
                .ends_with("/DiagnosticLog/DeviceStateData/MdmConfiguration")
    }))
}
