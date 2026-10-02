//! Ranges are delivery facts of the existing attempt, never another execution queue.
use super::*;
use std::result::Result;

pub async fn outgoing_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    session: u32,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempt_frames f JOIN mdm_commands.attempts a ON(a.tenant_id,a.id)=(f.tenant_id,f.attempt) JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt,i.command)=(f.tenant_id,f.attempt,f.command) WHERE a.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.credential=$4 AND a.session=$5 AND NOT coalesce(i.receipt_accepted,false))")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(session)).fetch_one(c).await.map_err(db)
}

pub enum Continuation {
    None,
    Waiting,
    Sent,
    Abort,
}

pub(super) async fn record(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    attempt: Uuid,
    message: u32,
    command: u32,
    range: std::ops::Range<usize>,
    total: usize,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_commands.attempt_frames(tenant_id,attempt,message,command,start_byte,end_byte,total_bytes) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
        .bind(p.tenant().to_string()).bind(attempt).bind(i64::from(message)).bind(i64::from(command)).bind(range.start as i32).bind(range.end as i32).bind(total as i32).execute(c).await.map_err(db)?;
    Ok(())
}

pub(super) async fn receive(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut PgConnection,
    key: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    row: &sqlx::postgres::PgRow,
    raw: &Message,
    history: &s::Expected,
) -> Result<Option<Vec<(u32, u32)>>, Error> {
    let attempt: Uuid = row.try_get("id").map_err(db)?;
    let frames=sqlx::query("SELECT message,command,start_byte,end_byte,total_bytes,status,accepted FROM mdm_commands.attempt_frames WHERE tenant_id=$1::uuid AND attempt=$2 ORDER BY message,command FOR UPDATE")
        .bind(p.tenant().to_string()).bind(attempt).fetch_all(&mut *c).await.map_err(db)?;
    if frames.is_empty() {
        return Ok(None);
    }
    let input = super::super::input_storage::open_row(
        key,
        p.tenant(),
        row.try_get("operation").map_err(db)?,
        row,
        "task_request",
    )?;
    let mut cursor = 0;
    let total: i32 = frames[0].try_get("total_bytes").map_err(db)?;
    let command: i64 = frames[0].try_get("command").map_err(db)?;
    for frame in &frames {
        if frame.try_get::<i32, _>("start_byte").map_err(db)? != cursor
            || frame.try_get::<i32, _>("total_bytes").map_err(db)? != total
            || frame.try_get::<i64, _>("command").map_err(db)? != command
        {
            return Err(protocol());
        }
        cursor = frame.try_get("end_byte").map_err(db)?;
    }
    let report = correlate(history, raw, &[command as u32])?;
    let mut consumed = Vec::new();
    for frame in frames {
        let msg = frame.try_get::<i64, _>("message").map_err(db)?;
        consumed.push((msg as u32, command as u32));
        let Some(status) = report
            .statuses
            .iter()
            .find(|s| i64::from(s.message_id) == msg && i64::from(s.command_id) == command)
        else {
            continue;
        };
        let code = i32::from(status.code);
        let old: Option<i32> = frame.try_get("status").map_err(db)?;
        if old.is_some_and(|old| terminal_status(old) && old != code) {
            return Err(Error::Conflict);
        }
        let old_accept = if old == Some(code) {
            frame.try_get("accepted").map_err(db)?
        } else {
            None
        };
        let accepted = receipt_acceptance(source, c, key, &input, row, true, old_accept).await?;
        sqlx::query("UPDATE mdm_commands.attempt_frames SET status=$5,accepted=$6,received_at=coalesce(received_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND attempt=$2 AND message=$3 AND command=$4")
            .bind(p.tenant().to_string()).bind(attempt).bind(msg).bind(command).bind(code).bind(accepted).execute(&mut *c).await.map_err(db)?;
        if terminal_status(code) {
            // A native error is evidence even before the object closes. Success is not.
            let logical_accept = native_rules::accepts_frame(
                code,
                accepted == Some(true),
                frame.try_get("end_byte").map_err(db)?,
                total,
            );
            sqlx::query("UPDATE mdm_commands.attempt_items SET status=$4,receipt_accepted=$5,received_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND attempt=$2 AND command=$3")
                .bind(p.tenant().to_string()).bind(attempt).bind(command).bind(code).bind(logical_accept).execute(&mut *c).await.map_err(db)?;
        }
    }
    Ok(Some(consumed))
}

pub async fn continue_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut PgConnection,
    key: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: &mut Message,
    peer_limits: &CodecLimits,
) -> Result<Continuation, Error> {
    let row=sqlx::query("SELECT a.id,a.operation,a.platform,o.device,o.registration,o.registration_generation,o.input_context,o.request,o.approval::text,d.status AS command_status,(o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AS within_deadline,a.ordinal=(SELECT max(b.ordinal) FROM mdm_commands.attempts b WHERE b.tenant_id=a.tenant_id AND b.operation=a.operation AND b.phase=a.phase) AS latest,f.command,f.end_byte,f.total_bytes,f.status,f.accepted FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text JOIN LATERAL (SELECT * FROM mdm_commands.attempt_frames WHERE tenant_id=a.tenant_id AND attempt=a.id ORDER BY message DESC LIMIT 1) f ON true JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt,i.command)=(a.tenant_id,a.id,f.command) WHERE a.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.credential=$4 AND a.session=$5 AND NOT coalesce(i.receipt_accepted,false) ORDER BY a.ordinal LIMIT 1")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(response.header.session_id)).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(Continuation::None);
    };
    if response.header.message_id as usize >= CodecLimits::default().session_messages {
        return Ok(Continuation::Abort);
    }
    let input = super::super::input_storage::open_row(
        key,
        p.tenant(),
        row.try_get("operation").map_err(db)?,
        &row,
        "request",
    )?;
    if receipt_acceptance(source, c, key, &input, &row, true, None).await? != Some(true) {
        return Ok(Continuation::Abort);
    };
    let status: Option<i32> = row.try_get("status").map_err(db)?;
    let end = row.try_get::<i32, _>("end_byte").map_err(db)? as usize;
    let total = row.try_get::<i32, _>("total_bytes").map_err(db)? as usize;
    if status.is_some_and(terminal_status) && end < total {
        return Ok(Continuation::Abort);
    };
    if total > peer_limits.object_bytes {
        return Ok(Continuation::Abort);
    }
    if end == total || status != Some(213) {
        return Ok(Continuation::Waiting);
    };
    if row.try_get::<Option<bool>, _>("accepted").map_err(db)? != Some(true) {
        return Ok(Continuation::Abort);
    };
    let Task::Windows {
        request: W::SyncMl { request },
    } = &input.task
    else {
        return Err(protocol());
    };
    let context =
        serde_json::from_value(row.try_get("platform").map_err(db)?).map_err(|_| protocol())?;
    let id = row.try_get::<i64, _>("command").map_err(db)? as u32;
    let command = request
        .compile(context, id)
        .map_err(|_| protocol())?
        .command;
    let frame = match s::fragment(
        response,
        &command,
        end,
        peer_limits.syncml_bytes,
        peer_limits,
    ) {
        Ok(frame) => frame,
        Err(_) => return Ok(Continuation::Abort),
    };
    let attempt: Uuid = row.try_get("id").map_err(db)?;
    record(
        c,
        p,
        attempt,
        response.header.message_id,
        id,
        end..frame.end,
        total,
    )
    .await?;
    *response = frame.message;
    Ok(Continuation::Sent)
}
