//! One durable native exchange for tasks and capability evidence. No transaction commits.
use super::*;
use crate::{access_store::db, authorization::Approval, device::DevicePrincipal};
use rss_mdm_windows_mdm::{
    CodecLimits,
    configuration::{Firewall, Platform},
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
async fn allocate(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    count: i64,
) -> std::result::Result<u32, Error> {
    let n:i64=sqlx::query_scalar("UPDATE mdm_access.report_sources SET next_command=next_command+$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='mdm.windows' AND enabled AND next_command<=$4 RETURNING next_command-$3")
 .bind(p.tenant().to_string()).bind(p.registration().to_string()).bind(count).bind(i64::from(u32::MAX)-count).fetch_one(c).await.map_err(db)?;
    n.try_into().map_err(|_| protocol())
}
fn refs(c: &Command) -> Option<(u32, u32)> {
    match c {
        Command::Status(x) if x.command_ref != 0 => Some((x.message_ref, x.command_ref)),
        Command::Results(x) => Some((x.message_ref.unwrap_or(1), x.command_ref.unwrap_or(1))),
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
/// Consume only exact server-authored references; leave Inventory to its owner.
pub(crate) async fn receive_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    message: &Message,
    authenticated: bool,
) -> std::result::Result<Message, Error> {
    if !authenticated {
        return Ok(message.clone());
    }
    let tenant = p.tenant().to_string();
    let reg = p.registration().to_string();
    let session = i64::from(message.header.session_id);
    let previous=sqlx::query_scalar::<_,String>("SELECT correlation FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3").bind(&tenant).bind(&reg).bind(session.to_string()).fetch_optional(&mut *c).await.map_err(db)?.unwrap_or_default();
    let rows=sqlx::query("SELECT a.id::text,a.command,a.message,a.status,a.value,a.request,a.uri,a.receipt_accepted,o.request::text AS task_request,o.approval::text,d.status AS command_status,(o.request->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AS within_deadline,a.ordinal=(SELECT max(latest.ordinal) FROM mdm_commands.attempts latest WHERE latest.tenant_id=a.tenant_id AND latest.operation=a.operation AND latest.phase=a.phase) AS latest FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND a.credential=$4::uuid AND a.session=$5 ORDER BY a.ordinal")
 .bind(&tenant).bind(&reg).bind(p.generation()).bind(p.credential().to_string()).bind(session).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let id = row.try_get::<i64, _>("command").map_err(db)? as u32;
        let msg = row.try_get::<i64, _>("message").map_err(db)? as u32;
        if !message.commands.iter().any(|c| refs(c) == Some((msg, id))) {
            continue;
        }
        let report = correlate(
            &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
            message,
            &[id],
            previous.as_bytes(),
        )?;
        let status = report
            .statuses
            .iter()
            .find(|s| s.command_id == id)
            .map(|s| i32::from(s.code));
        let value = report.results.first().map(|r| r.value.0.clone());
        let old_status = row.try_get::<Option<i32>, _>("status").map_err(db)?;
        let old_value = row.try_get::<Option<String>, _>("value").map_err(db)?;
        if old_status.is_some_and(|s| s >= 200 && s != 202 && status.is_some_and(|n| s != n))
            || old_value
                .as_ref()
                .is_some_and(|v| value.as_ref().is_some_and(|n| n != v))
        {
            return Err(Error::Conflict);
        }
        let status = status.or(old_status);
        let value = value.or(old_value);
        let uri: String = row.try_get("uri").map_err(db)?;
        if let Some(value) = &value {
            let valid = match uri.as_str() {
                rss_mdm_windows_mdm::configuration::STATUS_URI => {
                    matches!(value.as_str(), "0" | "1" | "2" | "3" | "4")
                }
                "./DevInfo/Mod" => Field::Model.digest(value).is_ok(),
                VERSION => Field::OsVersion.digest(value).is_ok(),
                _ => false,
            };
            if !valid {
                return Err(Error::Malformed);
            }
        }
        if status.is_some_and(|s| s >= 400) && value.is_some() {
            return Err(Error::Conflict);
        }
        let accepted = receipt_acceptance(c, p, &row, status).await?;
        sqlx::query("UPDATE mdm_commands.attempts SET status=$3,value=$4,received_at=floor(extract(epoch FROM clock_timestamp()))::bigint,receipt_accepted=$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
  .bind(&tenant).bind(row.try_get::<String,_>("id").map_err(db)?).bind(status).bind(value).bind(accepted).execute(&mut *c).await.map_err(db)?;
        consumed.insert((msg, id));
    }
    receive_capabilities(c, p, message, &mut consumed, previous.as_bytes()).await?;
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
            let request: Vec<u8> = row.try_get("request").map_err(db)?;
            let sent = s::decode(&request, &CodecLimits::default()).map_err(|_| protocol())?;
            let report = correlate(&request, message, &ids, previous)?;
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
                && Platform::new(version, edition).is_ok()
            {
                sqlx::query("INSERT INTO mdm_commands.capabilities VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(tenant_id,registration) DO UPDATE SET generation=excluded.generation,os_version=excluded.os_version,edition=excluded.edition,session=excluded.session,observed_at=excluded.observed_at")
    .bind(&tenant).bind(&reg).bind(p.generation()).bind(version).bind(edition as i32).bind(session).execute(&mut *c).await.map_err(db)?;
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
/// Add bounded native work before the response owner encodes/caches its final bytes.
pub(crate) async fn send_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    response: &mut Message,
    authenticated: bool,
) -> std::result::Result<bool, Error> {
    if !authenticated {
        return Ok(false);
    }
    let tenant = p.tenant().to_string();
    let reg = p.registration().to_string();
    let session = i64::from(response.header.session_id);
    let msg = i64::from(response.header.message_id);
    if msg >= 8 {
        return Ok(false);
    }
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.capability_queries WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session=$3)").bind(&tenant).bind(&reg).bind(session).fetch_one(&mut *c).await.map_err(db)?;
    let mut pending = false;
    if !exists {
        let id = allocate(c, p, 2).await?;
        let mut request = response.clone();
        request.commands = vec![get(id, VERSION), get(id + 1, EDITION)];
        let wire = s::encode(&request, &CodecLimits::default()).map_err(|_| protocol())?;
        sqlx::query("INSERT INTO mdm_commands.capability_queries(tenant_id,registration,generation,session,request,version_command,edition_command) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7)")
  .bind(&tenant).bind(&reg).bind(p.generation()).bind(session).bind(wire).bind(i64::from(id)).bind(i64::from(id+1)).execute(&mut *c).await.map_err(db)?;
        response.commands.extend(request.commands);
        pending = true;
    }
    let rows=sqlx::query("SELECT o.id::text,o.request::text,o.approval::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND d.status IN('published','received') AND (o.request->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.session=$4 AND o.request->'task'->>'kind'='state_verify') ORDER BY o.id LIMIT 64")
 .bind(&tenant).bind(&reg).bind(p.generation()).bind(session).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let op: Create = serde_json::from_str(&row.try_get::<String, _>("request").map_err(db)?)
            .map_err(|_| protocol())?;
        let approval: Approval =
            serde_json::from_str(&row.try_get::<String, _>("approval").map_err(db)?)
                .map_err(|_| protocol())?;
        let at = now(c).await?;
        if !approval.valid(c, op.task.permission(), at).await? {
            continue;
        }
        let id: String = row.try_get("id").map_err(db)?;
        let old=sqlx::query("SELECT ordinal,phase,status,value,session,receipt_accepted FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY ordinal DESC LIMIT 1").bind(&tenant).bind(&id).fetch_optional(&mut *c).await.map_err(db)?;
        let (next, waiting) = next_phase(old.as_ref(), &op.task, session)?;
        pending |= waiting;
        let Some((ordinal, phase)) = next else {
            continue;
        };
        let native = allocate(c, p, 1).await?;
        let Some(command) = command_for(c, p, &op.task, native, phase, session).await? else {
            continue;
        };
        let uri = match &command {
            Command::Get { items, .. } => items[0].target.clone().ok_or_else(protocol)?,
            Command::Replace { .. } => rss_mdm_windows_mdm::configuration::FIREWALL_URI.into(),
            _ => return Err(protocol()),
        };
        let mut request = response.clone();
        request.commands = vec![command.clone()];
        let wire = s::encode(&request, &CodecLimits::default()).map_err(|_| protocol())?;
        sqlx::query("INSERT INTO mdm_commands.attempts(tenant_id,id,operation,ordinal,credential,session,message,command,phase,uri,request) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,$8,$9,$10,$11)")
  .bind(&tenant).bind(Uuid::new_v4().to_string()).bind(id).bind(ordinal).bind(p.credential().to_string()).bind(session).bind(msg).bind(i64::from(native)).bind(phase.as_str()).bind(uri).bind(wire).execute(&mut *c).await.map_err(db)?;
        response.commands.push(command);
        pending = true;
        break;
    }
    let outstanding:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) WHERE a.tenant_id=$1::uuid AND o.registration=$2::uuid AND a.session=$3 AND (o.request->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) AND (a.status IS NULL OR (a.status=200 AND a.value IS NULL AND (a.phase=$4 OR o.request->'task'->>'kind'='state_verify'))))")
    .bind(&tenant).bind(&reg).bind(session).bind(AttemptPhase::Observe.as_str()).fetch_one(c).await.map_err(db)?;
    Ok(pending || outstanding)
}
type NextPhase = (Option<(i64, AttemptPhase)>, bool);
fn next_phase(
    old: Option<&sqlx::postgres::PgRow>,
    task: &Task,
    session: i64,
) -> std::result::Result<NextPhase, Error> {
    let Some(old) = old else {
        return Ok((Some((1, AttemptPhase::Execute)), false));
    };
    let ordinal = old
        .try_get::<i64, _>("ordinal")
        .map_err(db)?
        .checked_add(1)
        .ok_or_else(protocol)?;
    let phase = AttemptPhase::parse(&old.try_get::<String, _>("phase").map_err(db)?)?;
    let status: Option<i32> = old.try_get("status").map_err(db)?;
    let same = old.try_get::<i64, _>("session").map_err(db)? == session;
    match task {
        Task::Firewall { .. }
            if phase == AttemptPhase::Execute
                && status == Some(200)
                && old
                    .try_get::<Option<bool>, _>("receipt_accepted")
                    .map_err(db)?
                    == Some(true) =>
        {
            Ok((Some((ordinal, AttemptPhase::Observe)), false))
        }
        Task::StateVerify { .. } if !same => Ok((Some((ordinal, AttemptPhase::Execute)), false)),
        _ => Ok((
            None,
            same && (status.is_none()
                || (status == Some(200)
                    && old
                        .try_get::<Option<String>, _>("value")
                        .map_err(db)?
                        .is_none())),
        )),
    }
}
async fn command_for(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    task: &Task,
    native: u32,
    phase: AttemptPhase,
    session: i64,
) -> std::result::Result<Option<Command>, Error> {
    let tenant = p.tenant().to_string();
    let reg = p.registration().to_string();
    let command = match task {
        Task::StateVerify { field, .. } => get(
            native,
            match field {
                Field::Model => "./DevInfo/Mod",
                Field::OsVersion => VERSION,
            },
        ),
        Task::Firewall {
            enabled,
            os_version,
            edition,
            plan,
            ..
        } => {
            let eligible:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.capabilities c JOIN mdm_commands.plan_executions e ON e.tenant_id=c.tenant_id AND e.plan=$6::uuid JOIN mdm_policy.aggregates a ON a.tenant_id=e.tenant_id AND a.id=e.policy AND a.revision=e.policy_revision WHERE c.tenant_id=$1::uuid AND c.registration=$2::uuid AND c.generation=$3 AND c.os_version=$4 AND c.edition=$5 AND c.session=$7)")
    .bind(&tenant).bind(&reg).bind(p.generation()).bind(os_version).bind(*edition as i32).bind(plan.to_string()).bind(session).fetch_one(&mut *c).await.map_err(db)?;
            if !eligible || !current_plan_on(c, &tenant, *plan).await? {
                return Ok(None);
            }
            let firewall = Firewall::compile(
                *enabled,
                &Platform::new(os_version, *edition).map_err(|_| protocol())?,
            )
            .map_err(|_| protocol())?;
            if phase == AttemptPhase::Observe {
                firewall.observe(native)
            } else {
                firewall.replace(native)
            }
        }
    };
    Ok(Some(command))
}
async fn now(c: &mut PgConnection) -> std::result::Result<i64, Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(c)
        .await
        .map_err(db)
}
/// Cached command bytes still require a live task approval and deadline.
pub(crate) async fn replay_on(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    m: &Message,
) -> std::result::Result<(), Error> {
    let rows=sqlx::query("SELECT o.request::text,o.approval::text,d.status FROM mdm_commands.attempts a JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(a.tenant_id,a.operation) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE a.tenant_id=$1::uuid AND o.registration=$2::uuid AND a.session=$3 AND a.message=$4")
 .bind(p.tenant().to_string()).bind(p.registration().to_string()).bind(i64::from(m.header.session_id)).bind(i64::from(m.header.message_id)).fetch_all(&mut *c).await.map_err(db)?;
    let now = now(c).await?;
    for row in rows {
        let request: Create =
            serde_json::from_str(&row.try_get::<String, _>("request").map_err(db)?)
                .map_err(|_| protocol())?;
        let approval: Approval =
            serde_json::from_str(&row.try_get::<String, _>("approval").map_err(db)?)
                .map_err(|_| protocol())?;
        if let Task::Firewall { plan, .. } = request.task
            && !current_plan_on(c, &p.tenant().to_string(), plan).await?
        {
            return Err(Error::Forbidden);
        }
        if request.deadline <= now
            || !matches!(
                row.try_get::<String, _>("status").map_err(db)?.as_str(),
                "published" | "received"
            )
            || !approval.valid(c, request.task.permission(), now).await?
        {
            return Err(Error::Forbidden);
        }
    }
    Ok(())
}

pub(super) async fn current_plan_on(
    c: &mut PgConnection,
    tenant: &str,
    plan: Uuid,
) -> std::result::Result<bool, Error> {
    sqlx::query_scalar(include_str!("current-plan.sql"))
        .bind(tenant)
        .bind(plan.to_string())
        .fetch_one(c)
        .await
        .map_err(db)
}

async fn receipt_acceptance(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    row: &sqlx::postgres::PgRow,
    status: Option<i32>,
) -> std::result::Result<Option<bool>, Error> {
    let old: Option<bool> = row.try_get("receipt_accepted").map_err(db)?;
    if old.is_some() || !status.is_some_and(|s| s >= 200 && s != 202) {
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
    let request: Create =
        serde_json::from_str(&row.try_get::<String, _>("task_request").map_err(db)?)
            .map_err(|_| protocol())?;
    let approval: Approval =
        serde_json::from_str(&row.try_get::<String, _>("approval").map_err(db)?)
            .map_err(|_| protocol())?;
    let at = now(c).await?;
    let mut valid = approval.valid(c, request.task.permission(), at).await?;
    if let Task::Firewall { plan, .. } = request.task {
        valid &= current_plan_on(c, &p.tenant().to_string(), plan).await?;
    }
    Ok(Some(valid))
}
