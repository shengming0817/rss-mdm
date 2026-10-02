//! Durable Windows exchanges retain group and item correlation without brand-specific tasks.
use super::*;
use crate::{database::db, device::DevicePrincipal, execution::authority::ExecutionAuthority};
use rss_mdm_windows_mdm::{
    CodecLimits,
    native::{Context, Execution as W, Scope},
    syncml::{self as s, Command, Item, Message},
};
use sqlx::{PgConnection, Row};
const VERSION: &str = "./DevDetail/SwV";
const EDITION: &str = "./Vendor/MSFT/DeviceStatus/OS/Edition";
fn protocol() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn get(id: u32, uri: &str) -> Command {
    Command::Get {
        id,
        meta: None,
        items: vec![Item {
            target: Some(uri.into()),
            source: None,
            meta: None,
            data: None,
        }],
    }
}
fn refs(c: &Command) -> Option<(u32, u32)> {
    match c {
        Command::Status(s) if s.command_ref != 0 => Some((s.message_ref, s.command_ref)),
        Command::Results(r) => Some((r.message_ref.unwrap_or(1), r.command_ref.unwrap_or(1))),
        _ => None,
    }
}
fn correlate(
    request: &[u8],
    message: &Message,
    ids: &[u32],
    previous: &[u8],
) -> std::result::Result<s::Correlated, Error> {
    let limits = CodecLimits::default();
    let sent = s::decode(request, &limits).map_err(|_| protocol())?;
    let (_, sent) = s::encode_request(&sent, &limits).map_err(|_| protocol())?;
    let mut expected =
        s::Expected::new(sent, message.header.message_id, &limits).map_err(|_| protocol())?;
    if !previous.is_empty() {
        let last = s::decode(previous, &limits).map_err(|_| protocol())?;
        let original = s::decode(request, &limits).map_err(|_| protocol())?;
        if last.header.message_id != original.header.message_id {
            let (_, last) = s::encode_request(&last, &limits).map_err(|_| protocol())?;
            expected
                .record_sent(last, &limits)
                .map_err(|_| protocol())?;
        }
    }
    let response = Message {
        header: message.header.clone(),
        commands: message
            .commands
            .iter()
            .filter(|c| {
                matches!(c,Command::Status(status) if status.command_ref==0)
                    || refs(c).is_some_and(|(_, id)| ids.contains(&id))
            })
            .cloned()
            .collect(),
        final_message: true,
    };
    s::correlate(&expected, &response, &limits).map_err(|_| Error::Conflict)
}
/// Consume exact native references under the authenticated registration generation.
pub async fn receive_on(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    message: &Message,
    authenticated: bool,
    previous: &str,
) -> std::result::Result<Message, Error> {
    if !authenticated {
        return Ok(message.clone());
    }
    let tenant = p.tenant().to_string();
    let session = i64::from(message.header.session_id);
    let rows=sqlx::query("SELECT a.id,a.operation,a.message,a.request,o.device,o.registration,o.registration_generation,o.input_context,o.request AS task_request,o.approval::text,d.status AS command_status,(o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AS within_deadline,a.ordinal=(SELECT max(latest.ordinal) FROM mdm_commands.attempts latest WHERE latest.tenant_id=a.tenant_id AND latest.operation=a.operation AND latest.phase=a.phase) AS latest FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.credential=$4 AND a.session=$5 ORDER BY a.ordinal")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(session).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let attempt: Uuid = row.try_get("id").map_err(db)?;
        let msg = row.try_get::<i64, _>("message").map_err(db)? as u32;
        let items=sqlx::query("SELECT command,parent_command,item_ordinal,uri,kind,status,value,receipt_accepted,result_accepted FROM mdm_commands.attempt_items WHERE tenant_id=$1::uuid AND attempt=$2 ORDER BY command,item_ordinal FOR UPDATE").bind(&tenant).bind(attempt).fetch_all(&mut *c).await.map_err(db)?;
        let ids = items
            .iter()
            .map(|r| r.try_get::<i64, _>("command").map(|v| v as u32))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        if !message
            .commands
            .iter()
            .any(|command| refs(command).is_some_and(|(m, id)| m == msg && ids.contains(&id)))
        {
            continue;
        }
        let stored_request = protection
            .open_bytes(
                &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
                &crate::protection::aad(
                    p.tenant(),
                    "windows.attempt.request",
                    &(p.registration(), p.generation(), attempt),
                )?,
            )
            .map_err(|_| protocol())?;
        let report = correlate(stored_request.expose(), message, &ids, previous.as_bytes())?;
        let task_request = super::input_storage::open_row(
            protection,
            p.tenant(),
            row.try_get("operation").map_err(db)?,
            &row,
            "task_request",
        )?;
        let parents = items
            .iter()
            .map(|item| {
                Ok((
                    item.try_get::<i64, _>("command").map_err(db)?,
                    (
                        item.try_get::<Option<i64>, _>("parent_command")
                            .map_err(db)?,
                        item.try_get::<String, _>("kind").map_err(db)?,
                    ),
                ))
            })
            .collect::<std::result::Result<std::collections::BTreeMap<_, _>, Error>>()?;
        for item in items {
            let id = item.try_get::<i64, _>("command").map_err(db)? as u32;
            let uri: Option<String> = item.try_get("uri").map_err(db)?;
            let status = report
                .statuses
                .iter()
                .find(|s| {
                    s.message_id == msg
                        && s.command_id == id
                        && (s.targets.is_empty()
                            || uri.as_ref().is_some_and(|u| s.targets.contains(u)))
                })
                .map(|s| i32::from(s.code));
            let value = report
                .results
                .iter()
                .find(|r| {
                    r.reference.message_id == msg
                        && r.reference.command_id == id
                        && Some(&r.reference.uri) == uri.as_ref()
                })
                .map(|r| r.value.0.clone());
            if status.is_none() && value.is_none() {
                continue;
            }
            let old_status: Option<i32> = item.try_get("status").map_err(db)?;
            let item_ordinal: i32 = item.try_get("item_ordinal").map_err(db)?;
            let value_aad = result_aad(
                p.tenant(),
                p.registration(),
                p.generation(),
                attempt,
                i64::from(id),
                item_ordinal,
            )?;
            let old_sealed: Option<Vec<u8>> = item.try_get("value").map_err(db)?;
            let old_value = old_sealed
                .as_ref()
                .map(|sealed| {
                    let plain = protection
                        .open_bytes(sealed, &value_aad)
                        .map_err(|_| protocol())?;
                    String::from_utf8(plain.expose().to_vec()).map_err(|_| protocol())
                })
                .transpose()?;
            let atomic = atomic_ancestor(i64::from(id), &parents);
            let kind: String = item.try_get("kind").map_err(db)?;
            if old_status.is_some_and(|old| {
                terminal_status(old)
                    && status.is_some_and(|new| {
                        old != new
                            && !(atomic
                                && matches!(new, 216 | 516)
                                && successful_status(&kind, old))
                    })
            }) || old_value
                .as_ref()
                .is_some_and(|old| value.as_ref().is_some_and(|new| old != new))
            {
                return Err(Error::Conflict);
            }
            let new_status = status.is_some_and(terminal_status);
            let new_result = value.is_some();
            let status = status.or(old_status);
            let value = value.or(old_value);
            let old: Option<bool> = item.try_get("receipt_accepted").map_err(db)?;
            // Atomic rollback is a new receipt, not a replay of a child's earlier success.
            // Recheck current permission/deadline/generation instead of inheriting its acceptance.
            let old = if status == old_status { old } else { None };
            let accepted =
                receipt_acceptance(c, protection, &task_request, &row, new_status, old).await?;
            let old_result: Option<bool> = item.try_get("result_accepted").map_err(db)?;
            let result_accepted =
                receipt_acceptance(c, protection, &task_request, &row, new_result, old_result)
                    .await?;
            let value = if old_sealed.is_some() {
                old_sealed
            } else {
                value
                    .as_ref()
                    .map(|v| {
                        protection
                            .seal_bytes(v.as_bytes(), &value_aad)
                            .map_err(|_| protocol())
                    })
                    .transpose()?
            };
            sqlx::query("UPDATE mdm_commands.attempt_items SET status=$5,value=$6,receipt_accepted=$7,result_accepted=$8,received_at=CASE WHEN $9 AND (received_at IS NULL OR status IS DISTINCT FROM $5) THEN floor(extract(epoch FROM clock_timestamp()))::bigint ELSE received_at END,result_received_at=CASE WHEN $10 AND result_received_at IS NULL THEN floor(extract(epoch FROM clock_timestamp()))::bigint ELSE result_received_at END WHERE tenant_id=$1::uuid AND attempt=$2 AND command=$3 AND item_ordinal=$4")
                .bind(&tenant).bind(attempt).bind(i64::from(id)).bind(item.try_get::<i32,_>("item_ordinal").map_err(db)?).bind(status).bind(value).bind(accepted).bind(result_accepted).bind(new_status).bind(new_result).execute(&mut *c).await.map_err(db)?;
        }
        consumed.extend(ids.into_iter().map(|id| (msg, id)));
    }
    receive_capabilities(
        c,
        protection,
        p,
        message,
        &mut consumed,
        previous.as_bytes(),
    )
    .await?;
    Ok(Message {
        header: message.header.clone(),
        commands: message
            .commands
            .iter()
            .filter(|c| !refs(c).is_some_and(|r| consumed.contains(&r)))
            .cloned()
            .collect(),
        final_message: message.final_message,
    })
}
async fn receive_capabilities(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    message: &Message,
    consumed: &mut std::collections::BTreeSet<(u32, u32)>,
    previous: &[u8],
) -> std::result::Result<(), Error> {
    let tenant = p.tenant().to_string();
    let reg = p.registration().to_string();
    let session = i64::from(message.header.session_id);
    let query=sqlx::query("SELECT request,version_command,edition_command,os_version,edition,version_status,edition_status FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3 AND session=$4")
 .bind(&tenant).bind(&reg).bind(p.generation()).bind(session).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(row) = query {
        let ids = [
            row.try_get::<i64, _>("version_command").map_err(db)? as u32,
            row.try_get::<i64, _>("edition_command").map_err(db)? as u32,
        ];
        if message
            .commands
            .iter()
            .any(|c| refs(c).is_some_and(|(_, id)| ids.contains(&id)))
        {
            let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
            let plain = protection
                .open_bytes(
                    &sealed,
                    &crate::protection::aad(
                        p.tenant(),
                        "windows.capability.request",
                        &(p.registration(), p.generation(), session),
                    )?,
                )
                .map_err(|_| protocol())?;
            let request = plain.expose();
            let sent = s::decode(request, &CodecLimits::default()).map_err(|_| protocol())?;
            let report = correlate(request, message, &ids, previous)?;
            let mut values = [
                row.try_get::<Option<String>, _>("os_version").map_err(db)?,
                row.try_get::<Option<String>, _>("edition").map_err(db)?,
            ];
            let mut statuses = [
                row.try_get::<Option<i32>, _>("version_status")
                    .map_err(db)?,
                row.try_get::<Option<i32>, _>("edition_status")
                    .map_err(db)?,
            ];
            for (i, id) in ids.iter().enumerate() {
                for v in report
                    .results
                    .iter()
                    .filter(|v| v.reference.command_id == *id)
                {
                    if values[i].as_ref().is_some_and(|old| old != &v.value.0) {
                        return Err(Error::Conflict);
                    }
                    values[i] = Some(v.value.0.clone());
                }
                for v in report.statuses.iter().filter(|v| v.command_id == *id) {
                    if statuses[i].is_some_and(|old| old != i32::from(v.code)) {
                        return Err(Error::Conflict);
                    }
                    statuses[i] = Some(i32::from(v.code));
                }
                consumed.insert((sent.header.message_id, *id));
            }
            sqlx::query("UPDATE mdm_commands.capability_queries SET os_version=$4,edition=$5,version_status=$6,edition_status=$7 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session=$3")
   .bind(&tenant).bind(&reg).bind(session).bind(&values[0]).bind(&values[1]).bind(statuses[0]).bind(statuses[1]).execute(&mut *c).await.map_err(db)?;
            if statuses == [Some(200), Some(200)]
                && let [Some(version), Some(edition)] = &values
                && let Some(edition) = edition_id(edition)
                && context(version, edition, Scope::Device).is_ok()
            {
                let changed=sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3 AND os_version=$4 AND edition=$5)").bind(&tenant).bind(&reg).bind(p.generation()).bind(version).bind(edition as i32).fetch_one(&mut *c).await.map_err(db)?;
                sqlx::query("INSERT INTO mdm_commands.capabilities VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,registration) DO UPDATE SET generation=excluded.generation,os_version=excluded.os_version,edition=excluded.edition,session=excluded.session,observed_at=excluded.observed_at")
    .bind(&tenant).bind(&reg).bind(p.generation()).bind(version).bind(edition as i32).bind(session).execute(&mut *c).await.map_err(db)?;
                if changed {
                    sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1").bind(&tenant).bind(p.device()).execute(&mut *c).await.map_err(db)?;
                    sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3)")
                        .bind(&tenant)
                        .bind(super::DOMAIN)
                        .bind(format!("configuration:{}", p.device()))
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    crate::worker_wake::notify(c, crate::worker_wake::Work::CommandRecovery)
                        .await
                        .map_err(db)?;
                }
            }
        }
    }
    Ok(())
}
fn edition_id(value: &str) -> Option<u32> {
    match value {
        "Professional" | "Pro" => Some(48),
        "Enterprise" => Some(4),
        "Education" => Some(121),
        "IoTEnterprise" => Some(188),
        "IoTEnterpriseS" => Some(191),
        _ => value.parse::<u32>().ok(),
    }
}

fn context(version: &str, edition: u32, scope: Scope) -> std::result::Result<Context, Error> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(protocol());
    }
    let mut build = [0; 4];
    for (i, part) in parts.iter().enumerate() {
        build[i] = part.parse().map_err(|_| protocol())?;
    }
    Ok(Context {
        build: Some(build),
        edition: Some(edition),
        scope,
    })
}
/// Persist the exact native request and expected item set before exposing outbound bytes.
/// Admission uses the complete response; a valid tree must not poison every check-in.
fn admit_response(
    response: &Message,
    commands: &[Command],
) -> Result<Option<Vec<u8>>, &'static str> {
    let mut candidate = response.clone();
    candidate.commands.extend_from_slice(commands);
    candidate.final_message = true;
    if let Ok(bytes) = s::encode(&candidate, &CodecLimits::default()) {
        return Ok(Some(bytes));
    }
    let mut minimum = response.clone();
    minimum
        .commands
        .retain(|c| matches!(c, Command::Status(status) if status.command_ref == 0));
    minimum.commands.extend_from_slice(commands);
    minimum.final_message = true;
    if s::encode(&minimum, &CodecLimits::default()).is_ok() {
        Ok(None)
    } else {
        Err("native_response_budget_exceeded")
    }
}
pub async fn send_on(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: &mut Message,
    authenticated: bool,
) -> std::result::Result<bool, Error> {
    if !authenticated {
        return Ok(false);
    }
    let tenant = p.tenant().to_string();
    let session = i64::from(response.header.session_id);
    let stopped: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) WHERE a.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.session=$4 AND i.status=214)")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(session)
        .fetch_one(&mut *c).await.map_err(db)?;
    if stopped {
        return Ok(false);
    }
    let msg = i64::from(response.header.message_id);
    if msg >= 8 {
        return Ok(false);
    }
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid AND registration=$2 AND session=$3)").bind(&tenant).bind(p.registration()).bind(session).fetch_one(&mut *c).await.map_err(db)?;
    let mut pending = false;
    if !exists {
        let id = crate::collection::store::allocate_commands_in(c, p, 2).await?;
        let mut request = response.clone();
        request.commands = vec![get(id, VERSION), get(id + 1, EDITION)];
        let Some(_) = admit_response(response, &request.commands).map_err(|_| protocol())? else {
            return Ok(true);
        };
        let wire = s::encode(&request, &CodecLimits::default()).map_err(|_| protocol())?;
        let wire = protection
            .seal_bytes(
                &wire,
                &crate::protection::aad(
                    p.tenant(),
                    "windows.capability.request",
                    &(p.registration(), p.generation(), session),
                )?,
            )
            .map_err(|_| protocol())?;
        sqlx::query("INSERT INTO mdm_commands.capability_queries(tenant_id,registration,generation,session,request,version_command,edition_command) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)").bind(&tenant).bind(p.registration()).bind(p.generation()).bind(session).bind(wire).bind(i64::from(id)).bind(i64::from(id+1)).execute(&mut *c).await.map_err(db)?;
        response.commands.extend(request.commands);
        pending = true;
    }
    let cap=sqlx::query_as::<_,(String,i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3").bind(&tenant).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
    let rows=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request,o.approval FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.input_context->>'platform'='windows' AND o.gateway_accepted AND o.dispatch_failure IS NULL AND d.status IN('published','received') AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY o.id LIMIT 64").bind(&tenant).bind(p.registration()).bind(p.generation()).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let op = super::input_storage::open_row(
            protection,
            p.tenant(),
            row.try_get("id").map_err(db)?,
            &row,
            "request",
        )?;
        let approval: ExecutionAuthority =
            serde_json::from_value(row.try_get("approval").map_err(db)?).map_err(|_| protocol())?;
        let at = now(c).await?;
        if !approval
            .valid(c, protection, &op.task.permissions()?, at)
            .await?
            || !approval.dispatch_ready(c).await?
        {
            continue;
        }
        // A user request must be served by its independently authenticated user context.
        if !matches!(op.target, NativeTarget::Device) {
            continue;
        }
        let Task::Windows { request } = &op.task else {
            return Err(protocol());
        };
        let old=sqlx::query("SELECT a.id,a.ordinal,a.phase,a.session,a.platform FROM mdm_commands.attempts a WHERE a.tenant_id=$1::uuid AND a.operation=$2 ORDER BY a.ordinal DESC LIMIT 1").bind(&tenant).bind(op.operation_id).fetch_optional(&mut *c).await.map_err(db)?;
        let accepted = if let Some(old) = &old {
            let items = sqlx::query("SELECT kind,status,receipt_accepted,value,result_accepted FROM mdm_commands.attempt_items WHERE tenant_id=$1::uuid AND attempt=$2")
                .bind(&tenant).bind(old.try_get::<Uuid, _>("id").map_err(db)?)
                .fetch_all(&mut *c).await.map_err(db)?;
            let mut accepted = !items.is_empty();
            for item in items {
                let kind: String = item.try_get("kind").map_err(db)?;
                let status: Option<i32> = item.try_get("status").map_err(db)?;
                accepted &= item
                    .try_get::<Option<bool>, _>("receipt_accepted")
                    .map_err(db)?
                    == Some(true)
                    && status.is_some_and(|code| successful_status(&kind, code))
                    && (kind != "get"
                        || status == Some(204)
                        || (item
                            .try_get::<Option<Vec<u8>>, _>("value")
                            .map_err(db)?
                            .is_some()
                            && item
                                .try_get::<Option<bool>, _>("result_accepted")
                                .map_err(db)?
                                == Some(true)));
            }
            accepted
        } else {
            false
        };
        let fresh = cap
            .as_ref()
            .map(|(v, e)| context(v, *e as u32, Scope::Device))
            .transpose()?;
        let frozen = old
            .as_ref()
            .map(|r| r.try_get::<Option<serde_json::Value>, _>("platform"))
            .transpose()
            .map_err(db)?
            .flatten()
            .map(|v| serde_json::from_value::<Context>(v).map_err(|_| protocol()))
            .transpose()?;
        let platform = frozen.or(fresh);
        let (ordinal, phase) = match (&old, request) {
            (None, W::Msi { .. }) => (1, AttemptPhase::Prepare),
            (None, _) => (1, AttemptPhase::Execute),
            (Some(old), W::Msi { .. })
                if old.try_get::<String, _>("phase").map_err(db)? == "prepare" && accepted =>
            {
                (
                    old.try_get::<i64, _>("ordinal")
                        .map_err(db)?
                        .checked_add(1)
                        .ok_or_else(protocol)?,
                    AttemptPhase::Execute,
                )
            }
            (Some(old), W::SyncMl { request })
                if old.try_get::<String, _>("phase").map_err(db)? == "execute"
                    && old.try_get::<i64, _>("session").map_err(db)? != session
                    && request.read_only().map_err(|_| protocol())? =>
            {
                (
                    old.try_get::<i64, _>("ordinal")
                        .map_err(db)?
                        .checked_add(1)
                        .ok_or_else(protocol)?,
                    AttemptPhase::Execute,
                )
            }
            (Some(old), W::SyncMl { request })
                if (old.try_get::<String, _>("phase").map_err(db)? == "execute" && accepted)
                    || (old.try_get::<String, _>("phase").map_err(db)? == "observe"
                        && old.try_get::<i64, _>("session").map_err(db)? != session) =>
            {
                let Some(platform) = platform else {
                    continue;
                };
                if request
                    .effect_plan(platform)
                    .map_err(|_| Error::Unsupported)?
                    .readback()
                    .is_none()
                {
                    continue;
                }
                (
                    old.try_get::<i64, _>("ordinal")
                        .map_err(db)?
                        .checked_add(1)
                        .ok_or_else(protocol)?,
                    AttemptPhase::Observe,
                )
            }
            _ => continue,
        };
        if ordinal > 32 {
            continue;
        }
        let readback = if phase == AttemptPhase::Observe {
            let W::SyncMl { request } = request else {
                return Err(protocol());
            };
            Some(
                request
                    .effect_plan(platform.ok_or_else(protocol)?)
                    .map_err(|_| Error::Unsupported)?
                    .into_readback()
                    .ok_or_else(protocol)?,
            )
        } else {
            None
        };
        let count = match (request, &readback) {
            (_, Some(v)) => v.request.command_count().map_err(|_| protocol())?,
            (W::SyncMl { request }, _) => request.command_count().map_err(|_| protocol())?,
            (W::Msi { .. }, _) => 1,
        };
        let id = crate::collection::store::allocate_commands_in(c, p, i64::from(count)).await?;
        let command = match request {
            W::SyncMl { request } => {
                let Some(platform) = platform else {
                    continue;
                };
                match readback
                    .as_ref()
                    .map(|v| &v.request)
                    .unwrap_or(request)
                    .compile(platform, id)
                {
                    Ok(compiled) => compiled.command,
                    Err(error) => {
                        let failure = serde_json::json!({"platform":"windows","phase":phase.as_str(),"reason":error.to_string(),"context":platform});
                        sqlx::query("UPDATE mdm_commands.operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_failure IS NULL")
                            .bind(&tenant).bind(op.operation_id).bind(failure).execute(&mut *c).await.map_err(db)?;
                        continue;
                    }
                }
            }
            W::Msi { job } => {
                let installer = rss_mdm_windows_mdm::software::Installer::new(job.clone())
                    .map_err(|_| protocol())?;
                if phase == AttemptPhase::Prepare {
                    installer.prepare(id)
                } else {
                    installer.install(id).map_err(|_| protocol())?
                }
            }
        };
        match admit_response(response, std::slice::from_ref(&command)) {
            Ok(Some(_)) => (),
            Ok(None) => {
                pending = true;
                continue;
            }
            Err(reason) => {
                let failure = serde_json::json!({"platform":"windows","phase":phase.as_str(),"reason":reason});
                sqlx::query("UPDATE mdm_commands.operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_failure IS NULL")
                    .bind(&tenant).bind(op.operation_id).bind(failure).execute(&mut *c).await.map_err(db)?;
                continue;
            }
        };
        let mut request = response.clone();
        request.commands = vec![command.clone()];
        let (wire, _) =
            s::encode_request(&request, &CodecLimits::default()).map_err(|_| protocol())?;
        let attempt = Uuid::new_v4();
        let wire = protection
            .seal_bytes(
                &wire,
                &crate::protection::aad(
                    p.tenant(),
                    "windows.attempt.request",
                    &(p.registration(), p.generation(), attempt),
                )?,
            )
            .map_err(|_| protocol())?;
        sqlx::query("INSERT INTO mdm_commands.attempts(tenant_id,id,operation,ordinal,credential,session,message,phase,request,platform) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(&tenant).bind(attempt).bind(op.operation_id).bind(ordinal).bind(p.credential()).bind(session).bind(msg).bind(phase.as_str()).bind(wire).bind(platform.map(serde_json::to_value).transpose().map_err(|_|protocol())?).execute(&mut *c).await.map_err(db)?;
        for item in expected_items(&command)? {
            sqlx::query("INSERT INTO mdm_commands.attempt_items(tenant_id,attempt,command,item_ordinal,kind,uri,parent_command) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)").bind(&tenant).bind(attempt).bind(i64::from(item.command)).bind(item.ordinal).bind(item.kind).bind(item.uri).bind(item.parent.map(i64::from)).execute(&mut *c).await.map_err(db)?;
        }
        response.commands.push(command);
        pending = true;
        break;
    }
    let outstanding:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) WHERE a.tenant_id=$1::uuid AND o.registration=$2 AND a.session=$3 AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AND (i.status IS NULL OR i.status IN (101,202,206,213) OR (i.kind='get' AND i.status IN (200,214) AND i.value IS NULL)))").bind(&tenant).bind(p.registration()).bind(session).fetch_one(c).await.map_err(db)?;
    Ok(pending || outstanding)
}
struct ExpectedItem {
    command: u32,
    ordinal: i32,
    kind: &'static str,
    uri: Option<String>,
    parent: Option<u32>,
}
fn expected_items(command: &Command) -> std::result::Result<Vec<ExpectedItem>, Error> {
    let mut pending = vec![(command, None)];
    let mut out = Vec::new();
    while let Some((command, parent)) = pending.pop() {
        let (kind, items) = match command {
            Command::Get { items, .. } => ("get", items.as_slice()),
            Command::Add { items, .. } => ("add", items.as_slice()),
            Command::Replace { items, .. } => ("replace", items.as_slice()),
            Command::Delete { items, .. } => ("delete", items.as_slice()),
            Command::Exec { items, .. } => ("exec", items.as_slice()),
            Command::Atomic { id, commands } | Command::Sequence { id, commands } => {
                pending.extend(commands.iter().rev().map(|c| (c, Some(*id))));
                out.push(ExpectedItem {
                    command: *id,
                    ordinal: 0,
                    kind: if matches!(command, Command::Atomic { .. }) {
                        "atomic"
                    } else {
                        "sequence"
                    },
                    uri: None,
                    parent,
                });
                continue;
            }
            _ => return Err(protocol()),
        };
        for (ordinal, item) in items.iter().enumerate() {
            out.push(ExpectedItem {
                command: command.id(),
                ordinal: ordinal as i32,
                kind,
                uri: Some(item.target.clone().ok_or_else(protocol)?),
                parent,
            });
        }
    }
    Ok(out)
}
async fn now(c: &mut PgConnection) -> std::result::Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await
        .map_err(db)
}
/// Cached command bytes still require a live task approval and deadline.
pub async fn replay_on(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    m: &Message,
) -> std::result::Result<(), Error> {
    let rows=sqlx::query("SELECT o.id,o.device,o.registration,o.registration_generation,o.input_context,o.request,o.approval::text,d.status FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE a.tenant_id=$1::uuid AND o.registration=$2::uuid AND a.session=$3 AND a.message=$4")
 .bind(p.tenant().to_string()).bind(p.registration().to_string()).bind(i64::from(m.header.session_id)).bind(i64::from(m.header.message_id)).fetch_all(&mut *c).await.map_err(db)?;
    let now = now(c).await?;
    for row in rows {
        let request = super::input_storage::open_row(
            protection,
            p.tenant(),
            row.try_get("id").map_err(db)?,
            &row,
            "request",
        )?;
        let approval: ExecutionAuthority =
            serde_json::from_str(&row.try_get::<String, _>("approval").map_err(db)?)
                .map_err(|_| protocol())?;
        if request.deadline <= now
            || !matches!(
                row.try_get::<String, _>("status").map_err(db)?.as_str(),
                "published" | "received"
            )
            || !approval
                .valid(c, protection, &request.task.permissions()?, now)
                .await?
        {
            return Err(Error::Forbidden);
        }
    }
    Ok(())
}

async fn receipt_acceptance(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    request: &Create,
    row: &sqlx::postgres::PgRow,
    received: bool,
    old: Option<bool>,
) -> std::result::Result<Option<bool>, Error> {
    if old.is_some() || !received {
        return Ok(old);
    }
    if !row.try_get::<bool, _>("within_deadline").map_err(db)?
        || !row.try_get::<bool, _>("latest").map_err(db)?
        || !matches!(
            row.try_get::<String, _>("command_status")
                .map_err(db)?
                .as_str(),
            "published" | "received"
        )
    {
        return Ok(Some(false));
    }
    let approval: ExecutionAuthority =
        serde_json::from_str(&row.try_get::<String, _>("approval").map_err(db)?)
            .map_err(|_| protocol())?;
    let at = now(c).await?;
    Ok(Some(
        at < request.deadline
            && approval
                .valid(c, protection, &request.task.permissions()?, at)
                .await?,
    ))
}

/// OMA SyncML Representation 1.2.2 §10: provisional receipts allow later completion.
/// Unknown codes remain evidence, without inventing a successful business outcome.
pub(super) fn terminal_status(status: i32) -> bool {
    status >= 200 && !matches!(status, 202 | 206 | 213)
}
pub(super) fn successful_status(kind: &str, status: i32) -> bool {
    match status {
        200 | 214 => matches!(
            kind,
            "add" | "replace" | "delete" | "get" | "exec" | "atomic" | "sequence"
        ),
        201 => kind == "add",
        204 => kind == "get",
        210 | 211 => kind == "delete",
        _ => false,
    }
}
pub(super) fn rejected_status(status: i32) -> bool {
    matches!(status, 215 | 216) || ((400..600).contains(&status) && status != 516)
}
fn atomic_ancestor(
    command: i64,
    parents: &std::collections::BTreeMap<i64, (Option<i64>, String)>,
) -> bool {
    let mut next = parents.get(&command).and_then(|(parent, _)| *parent);
    for _ in 0..parents.len() {
        let Some((parent, kind)) = next.and_then(|id| parents.get(&id)) else {
            return false;
        };
        if kind == "atomic" {
            return true;
        }
        next = *parent;
    }
    false
}

pub(super) fn result_aad(
    tenant: TenantId,
    registration: Uuid,
    generation: i64,
    attempt: Uuid,
    command: i64,
    ordinal: i32,
) -> std::result::Result<rss_mdm_native_protection::DerivedAad, Error> {
    crate::protection::aad(
        tenant,
        "windows.attempt.result",
        &(registration, generation, attempt, command, ordinal),
    )
}

#[cfg(test)]
mod status_tests {
    #[test]
    fn only_explicit_command_outcomes_are_successful() {
        for kind in [
            "add", "replace", "delete", "get", "exec", "atomic", "sequence",
        ] {
            assert!(super::successful_status(kind, 200));
            for code in [
                101, 202, 203, 205, 206, 207, 208, 209, 212, 213, 215, 216, 217, 218, 507, 516,
            ] {
                assert!(!super::successful_status(kind, code), "{kind} {code}");
            }
        }
        assert!(super::successful_status("get", 204));
        assert!(!super::successful_status("exec", 204));
        assert!(super::successful_status("add", 201));
        assert!(!super::successful_status("get", 201));
        assert!(super::successful_status("delete", 211));
        assert!(super::rejected_status(215));
        assert!(super::rejected_status(216));
        assert!(!super::rejected_status(516));
    }
    #[test]
    fn partial_completion_can_receive_a_later_terminal_receipt() {
        for code in [101, 202, 206, 213] {
            assert!(!super::terminal_status(code), "provisional status {code}");
        }
        assert!(super::terminal_status(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response() -> Message {
        Message {
            header: s::Header {
                session_id: 1,
                message_id: 2,
                target: "device".into(),
                source: "https://mdm.example.test".into(),
                credential: None,
                meta: None,
            },
            commands: vec![Command::Status(s::Status {
                id: 1,
                message_ref: 1,
                command_ref: 0,
                command: s::CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 212,
                items: vec![],
                challenge: None,
                credential: None,
            })],
            final_message: true,
        }
    }
    fn tree(children: u32) -> Command {
        Command::Sequence {
            id: 10,
            commands: (0..children)
                .map(|n| get(11 + n, "./DevInfo/Mod"))
                .collect(),
        }
    }
    #[test]
    fn response_admission_accounts_for_header_and_collection_without_splitting_groups() {
        let response = response();
        assert!(admit_response(&response, &[tree(254)]).unwrap().is_some());
        assert_eq!(
            admit_response(&response, &[tree(255)]).unwrap_err(),
            "native_response_budget_exceeded"
        );
        let mut with_collection = response.clone();
        with_collection.commands.push(get(2, "./DevInfo/Man"));
        assert!(
            admit_response(&with_collection, &[tree(254)])
                .unwrap()
                .is_none()
        );
        assert!(admit_response(&response, &[tree(254)]).unwrap().is_some());
    }
}
