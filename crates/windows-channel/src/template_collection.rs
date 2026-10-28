//! One plan executor for scalar and dynamic native collection reads.
use crate::{Error, Failure, database::db, device::DevicePrincipal};
use rss_mdm_inventory::{FieldKey, NativeValue};
use rss_mdm_inventory_service::collection::{native, store};
use rss_mdm_native_protection::Protector;
use rss_mdm_windows_mdm::{
    CodecLimits,
    native::collection::{Outcome, State},
    syncml::{self as s, Command},
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
fn corrupt() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn refs(command: &Command) -> Option<(u32, u32)> {
    match command {
        Command::Status(v) if v.command_ref != 0 => Some((v.message_ref, v.command_ref)),
        Command::Results(v) => Some((v.message_ref?, v.command_ref?)),
        _ => None,
    }
}
fn open(
    protection: &Protector,
    run: &store::Run,
    id: Uuid,
    session: u32,
    bytes: &[u8],
) -> Result<State, Error> {
    rss_mdm_execution_service::native::open_collection_state(
        protection, &run.scope, id, session, bytes,
    )
    .map_err(|_| corrupt())
}
fn seal(
    protection: &Protector,
    run: &store::Run,
    id: Uuid,
    session: u32,
    state: &State,
) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(state).map_err(|_| corrupt())?;
    if bytes.len() > CodecLimits::default().object_bytes {
        return Err(corrupt());
    }
    protection
        .seal_bytes(
            &bytes,
            &crate::protection::collection_aad(&run.scope, id, session)?,
        )
        .map_err(|_| corrupt())
}
#[allow(
    clippy::too_many_arguments,
    reason = "native dispatch carries the current authority, transaction, protection and negotiated protocol context explicitly"
)]
pub async fn send(
    source: &dyn rss_mdm_execution_service::source_authority::SourceAuthority,
    c: &mut PgConnection,
    protection: &Protector,
    p: &DevicePrincipal,
    response: &mut s::Message,
    limits: &CodecLimits,
    provider: &str,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<bool, Error> {
    if response.header.message_id as usize >= limits.session_messages {
        return Ok(false);
    }
    let capabilities = sqlx::query_as::<_,(String,i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND session=$4")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(i64::from(response.header.session_id)).fetch_optional(&mut *c).await.map_err(db)?;
    let Some((version, edition)) = capabilities else {
        return Ok(false);
    };
    let build = version
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| corrupt())?
        .try_into()
        .map_err(|_| corrupt())?;
    let context = rss_mdm_windows_mdm::native::Context {
        enrollment: rss_mdm_windows_mdm::native::Enrollment::Primary,
        build: Some(build),
        edition: Some(edition.try_into().map_err(|_| corrupt())?),
        scope: rss_mdm_windows_mdm::native::Scope::Device,
    };
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT r.id FROM mdm_access.collection_runs r LEFT JOIN LATERAL (SELECT * FROM mdm_windows.collections w0 WHERE w0.tenant_id=r.tenant_id AND w0.id=r.id ORDER BY (w0.session_id=$3) DESC, w0.first_command DESC LIMIT 1) w ON true WHERE r.tenant_id=$1::uuid AND r.registration=$2 AND r.source='mdm.windows' AND r.sealed_at IS NULL AND r.evidence ? 'nativeTemplate' AND r.deadline>clock_timestamp() AND (w.id IS NULL OR w.session_id=$3 OR EXISTS(SELECT 1 FROM mdm_access.management_sessions s WHERE s.tenant_id=w.tenant_id AND s.registration=w.registration AND s.session_id=w.session_id AND s.state='complete')) ORDER BY r.sequence LIMIT 1 FOR UPDATE OF r")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(response.header.session_id.to_string()).fetch_all(&mut *c).await.map_err(db)?;
    for id in ids {
        if !rss_mdm_execution_service::actions::native_collection::delivery_eligible_on(
            source, c, p, id,
        )
        .await?
        {
            continue;
        }
        let plan = rss_mdm_execution_service::actions::native_collection::plan_on(
            c,
            &p.tenant().to_string(),
            id,
        )
        .await?;
        let mut run = store::load_on(c, &p.tenant().to_string(), id).await?;
        if plan.applicable(context).is_err() {
            facts.extend(store::seal(c, &mut run, "native_not_applicable").await?);
            continue;
        }
        let bytes: Option<Vec<u8>> = sqlx::query_scalar("SELECT template_state FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2 AND kind='template' AND session_id=$3")
            .bind(p.tenant().to_string()).bind(id).bind(response.header.session_id.to_string()).fetch_optional(&mut *c).await.map_err(db)?;
        let fresh = bytes.is_none();
        let mut state = match bytes {
            Some(bytes) => open(protection, &run, id, response.header.session_id, &bytes)?,
            None => {
                let previous: Option<(String, Vec<u8>)> = sqlx::query_as("SELECT session_id,template_state FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2 AND kind='template' ORDER BY first_command DESC LIMIT 1")
                    .bind(p.tenant().to_string()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
                match previous {
                    Some((sid, bytes)) => open(
                        protection,
                        &run,
                        id,
                        sid.parse().map_err(|_| corrupt())?,
                        &bytes,
                    )?
                    .resume(&plan, provider)
                    .map_err(|_| corrupt())?,
                    None => plan.start(provider).map_err(|_| corrupt())?,
                }
            }
        };
        let first = crate::device::store::allocate_commands_in(
            c,
            p,
            state.unsent().max(1).min(limits.commands) as i64,
        )
        .await?;
        let mut count = 0;
        while count < limits.commands {
            let Some((step, request)) = state.next().map_err(|_| corrupt())? else {
                break;
            };
            let command = request
                .compile(context, first + count as u32)
                .map_err(|_| corrupt())?
                .command;
            match s::admit(response, std::slice::from_ref(&command), limits)
                .map_err(|_| corrupt())?
            {
                s::Admission::Send(_) => response.commands.push(command),
                s::Admission::Defer => break,
                s::Admission::Unsupported => {
                    facts
                        .extend(store::seal(c, &mut run, "native_response_budget_exceeded").await?);
                    break;
                }
            }
            state
                .sent(step, response.header.message_id, first + count as u32)
                .map_err(|_| corrupt())?;
            count += 1;
        }
        let bytes = seal(protection, &run, id, response.header.session_id, &state)?;
        if fresh {
            sqlx::query("INSERT INTO mdm_windows.collections(tenant_id,id,registration,session_id,request_message,first_command,kind,template_state) VALUES($1::uuid,$2,$3,$4,$5,$6,'template',$7)")
                .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(i64::from(first)).bind(bytes).execute(&mut *c).await.map_err(db)?;
        } else {
            sqlx::query("UPDATE mdm_windows.collections SET template_state=$3 WHERE tenant_id=$1::uuid AND id=$2 AND kind='template' AND session_id=$4")
                .bind(p.tenant().to_string()).bind(id).bind(bytes).bind(response.header.session_id.to_string()).execute(&mut *c).await.map_err(db)?;
        }
        if count > 0 {
            rss_mdm_execution_service::actions::native_collection::sent(
                c,
                &p.tenant().to_string(),
                id,
            )
            .await?;
        }
    }
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) WHERE r.tenant_id=$1::uuid AND r.registration=$2 AND r.sealed_at IS NULL AND w.kind='template' AND w.session_id=$3)")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(response.header.session_id.to_string()).fetch_one(c).await.map_err(db)
}
pub async fn receive(
    source: &dyn rss_mdm_execution_service::source_authority::SourceAuthority,
    c: &mut PgConnection,
    protection: &Protector,
    p: &DevicePrincipal,
    message: &s::Message,
    history: &s::Expected,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<(s::Message, Vec<Uuid>), Error> {
    let tenant = p.tenant().to_string();
    let rows = sqlx::query("SELECT id,template_state FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND registration=$2 AND session_id=$3 AND kind='template' ORDER BY first_command")
        .bind(&tenant).bind(p.registration()).bind(message.header.session_id.to_string()).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    let mut runs = Vec::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let mut run = store::load_on(c, &tenant, id).await?;
        let mut state = open(
            protection,
            &run,
            id,
            message.header.session_id,
            &row.try_get::<Vec<u8>, _>("template_state").map_err(db)?,
        )?;
        let commands: Vec<_> = message
            .commands
            .iter()
            .filter(|cmd| refs(cmd).is_some_and(|(m, c)| state.owns(m, c)))
            .cloned()
            .collect();
        consumed.extend(commands.iter().filter_map(refs));
        if run.sealed_at.is_some()
            || !rss_mdm_execution_service::actions::native_collection::eligible_on(source, c, p, id)
                .await?
        {
            continue;
        }
        runs.push(id);
        let plan =
            rss_mdm_execution_service::actions::native_collection::plan_on(c, &tenant, id).await?;
        let template = native::template(c, &tenant, id)
            .await?
            .ok_or_else(corrupt)?;
        let correlated = s::correlate(
            history,
            &s::Message {
                header: message.header.clone(),
                commands: message
                    .commands
                    .iter()
                    .filter(|cmd| {
                        matches!(cmd,Command::Status(v) if v.command_ref == 0)
                            || refs(cmd).is_some_and(|(m, c)| state.owns(m, c))
                    })
                    .cloned()
                    .collect(),
                final_message: message.final_message,
            },
            &CodecLimits::default(),
        )
        .map_err(|_| Error::Conflict)?;
        for status in correlated.statuses {
            if status.command_id != 0 {
                state
                    .status(status.message_id, status.command_id, status.code)
                    .map_err(|_| Error::Conflict)?;
            }
        }
        for result in correlated.results {
            if !result.explicit_message_ref || !result.explicit_command_ref {
                return Err(Error::Conflict);
            }
            state
                .value(
                    result.reference.message_id,
                    result.reference.command_id,
                    &result.reference.uri,
                    result.value.0,
                )
                .map_err(|_| Error::Conflict)?;
        }
        state
            .advance(&plan, template.spec().output_bytes as usize)
            .map_err(|_| Error::Conflict)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        for (name, outcome) in state.outcomes(&plan).map_err(|_| corrupt())? {
            let key = FieldKey::parse(&name).map_err(|_| corrupt())?;
            match outcome {
                Outcome::Status(code) => run
                    .attempts
                    .observe_status(key, code, now)
                    .map_err(|_| Error::Conflict)?,
                Outcome::Value(raw) => {
                    let field = run
                        .attempts
                        .definition()
                        .field(key)
                        .map_err(|_| corrupt())?;
                    let value = native::value(field, &template.spec().mappings[&name], &raw);
                    match value {
                        NativeValue::Value(value)
                            if run.attempts.value_bytes().map_err(|_| corrupt())?
                                + value.encode(field).map_err(|_| corrupt())?.len()
                                <= template.spec().output_bytes as usize =>
                        {
                            run.attempts
                                .observe_status(key, 200, now)
                                .map_err(|_| Error::Conflict)?;
                            run.attempts
                                .observe_value(key, value, now)
                                .map_err(|_| Error::Conflict)?;
                        }
                        NativeValue::InvalidItems { items, values }
                            if run.attempts.value_bytes().map_err(|_| corrupt())?
                                + rss_mdm_inventory::CollectedValue::Value(
                                    rss_mdm_inventory::Scalar::Array(values.clone()),
                                )
                                .encode(field)
                                .map_err(|_| corrupt())?
                                .len()
                                <= template.spec().output_bytes as usize =>
                        {
                            run.attempts
                                .observe_invalid_items(key, items, values, now)
                                .map_err(|_| Error::Conflict)?
                        }
                        _ => run
                            .attempts
                            .observe_invalid(key, now)
                            .map_err(|_| Error::Conflict)?,
                    }
                }
            }
        }
        let bytes = seal(protection, &run, id, message.header.session_id, &state)?;
        sqlx::query("UPDATE mdm_windows.collections SET template_state=$3 WHERE tenant_id=$1::uuid AND id=$2 AND kind='template' AND session_id=$4").bind(&tenant).bind(id).bind(bytes).bind(message.header.session_id.to_string()).execute(&mut *c).await.map_err(db)?;
        match settlement(
            !state.pending() && run.attempts.complete(),
            message.final_message,
            message.header.message_id as usize,
        ) {
            Settlement::Seal(reason) => facts.extend(store::seal(c, &mut run, reason).await?),
            Settlement::Abandon => facts.extend(
                rss_mdm_inventory_service::collection::channel::abandon_in(
                    c,
                    &tenant,
                    id,
                    "message_budget",
                )
                .await?,
            ),
            Settlement::Pending => store::save_attempts_in(c, &run).await?,
        }
    }
    Ok((
        s::Message {
            header: message.header.clone(),
            commands: message
                .commands
                .iter()
                .filter(|cmd| !refs(cmd).is_some_and(|r| consumed.contains(&r)))
                .cloned()
                .collect(),
            final_message: message.final_message,
        },
        runs,
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Settlement {
    Seal(&'static str),
    Abandon,
    Pending,
}
pub(super) fn settlement(complete: bool, final_message: bool, message_id: usize) -> Settlement {
    if complete && final_message {
        Settlement::Seal("complete")
    } else if message_id >= CodecLimits::default().session_messages {
        if final_message {
            Settlement::Seal("message_budget")
        } else {
            Settlement::Abandon
        }
    } else {
        Settlement::Pending
    }
}
