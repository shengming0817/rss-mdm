//! Frozen CSP reads on the existing authenticated SyncML exchange and collection store.
use crate::{Error, Failure, database::db, device::DevicePrincipal};
use rss_mdm_inventory::{FieldKey, NativeValue};
use rss_mdm_inventory_service::collection::{native, store};
use rss_mdm_windows_mdm::{
    CodecLimits,
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
pub async fn send(
    source: &dyn rss_mdm_execution_service::source_authority::SourceAuthority,
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: &mut s::Message,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<bool, Error> {
    if response.header.message_id as usize >= CodecLimits::default().session_messages {
        return Ok(false);
    }
    let row=sqlx::query("SELECT r.id FROM mdm_access.collection_runs r WHERE r.tenant_id=$1::uuid AND r.registration=$2 AND r.source='mdm.windows' AND r.sealed_at IS NULL AND r.evidence ? 'nativeTemplate' AND r.deadline>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM mdm_windows.collections w WHERE (w.tenant_id,w.id)=(r.tenant_id,r.id)) ORDER BY r.sequence LIMIT 1 FOR UPDATE")
        .bind(p.tenant().to_string()).bind(p.registration()).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(row) = row {
        let id: Uuid = row.try_get("id").map_err(db)?;
        if !rss_mdm_execution_service::actions::native_collection::eligible_on(source, c, p, id)
            .await?
        {
            return Ok(false);
        }
        let template = native::template(c, &p.tenant().to_string(), id)
            .await?
            .ok_or_else(corrupt)?;
        let first =
            crate::device::store::allocate_commands_in(c, p, template.spec().mappings.len() as i64).await?;
        let capabilities=sqlx::query_as::<_,(String,i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND session=$4").bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(i64::from(response.header.session_id)).fetch_optional(&mut *c).await.map_err(db)?;
        let Some((version, edition)) = capabilities else {
            return Ok(false);
        };
        let build = version
            .split('.')
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| corrupt())?
            .try_into()
            .map_err(|_| corrupt())?;
        let context = rss_mdm_windows_mdm::native::Context {
            enrollment: rss_mdm_windows_mdm::native::Enrollment::Primary,
            build: Some(build),
            edition: Some(edition.try_into().map_err(|_| corrupt())?),
            scope: rss_mdm_windows_mdm::native::Scope::Device,
        };
        let queries = rss_mdm_execution_service::actions::native_collection::queries_on(
            c,
            &p.tenant().to_string(),
            id,
        )
        .await?;
        if queries.len() != template.spec().mappings.len() {
            return Err(corrupt());
        }
        let commands = queries
            .iter()
            .enumerate()
            .map(|(i, q)| {
                q.compile(context, first + i as u32)
                    .map(|v| v.command)
                    .map_err(|_| Error::Unsupported)
            })
            .collect::<Result<Vec<_>, _>>();
        let commands = match commands {
            Ok(commands) => commands,
            Err(Error::Unsupported) => {
                let mut run = store::load_on(c, &p.tenant().to_string(), id).await?;
                facts.extend(store::seal(c, &mut run, "native_not_applicable").await?);
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let request = s::Message {
            header: response.header.clone(),
            commands: commands.clone(),
            final_message: true,
        };
        let bytes = s::encode(&request, &CodecLimits::default()).map_err(|_| corrupt())?;
        let run = store::load_on(c, &p.tenant().to_string(), id).await?;
        let bytes = protection
            .seal_bytes(&bytes, &crate::protection::collection_aad(&run.scope, id)?)
            .map_err(|_| corrupt())?;
        sqlx::query("INSERT INTO mdm_windows.collections(tenant_id,id,registration,session_id,request_message,first_command,request) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(i64::from(first)).bind(bytes).execute(&mut *c).await.map_err(db)?;
        rss_mdm_execution_service::actions::native_collection::sent(c, &p.tenant().to_string(), id)
            .await?;
        response.commands.extend(commands);
    }
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs r JOIN mdm_windows.collections w USING(tenant_id,id) WHERE r.tenant_id=$1::uuid AND r.registration=$2 AND r.sealed_at IS NULL AND r.evidence ? 'nativeTemplate' AND w.session_id=$3)")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(response.header.session_id.to_string()).fetch_one(c).await.map_err(db)
}
pub async fn receive(
    source: &dyn rss_mdm_execution_service::source_authority::SourceAuthority,
    c: &mut PgConnection,
    _protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    message: &s::Message,
    history: &s::Expected,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<s::Message, Error> {
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT w.id,w.request,w.request_message,w.first_command FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND r.evidence ? 'nativeTemplate' ORDER BY w.first_command")
        .bind(&tenant).bind(p.registration()).bind(message.header.session_id.to_string()).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let template = native::template(c, &tenant, id)
            .await?
            .ok_or_else(corrupt)?;
        let fields: Vec<_> = template.spec().mappings.iter().collect();
        let queries =
            rss_mdm_execution_service::actions::native_collection::queries_on(c, &tenant, id)
                .await?;
        if queries.len() != fields.len() {
            return Err(corrupt());
        }
        let first = row.try_get::<i64, _>("first_command").map_err(db)? as u32;
        let msg = row.try_get::<i64, _>("request_message").map_err(db)? as u32;
        let commands: Vec<_> = message
            .commands
            .iter()
            .filter(|command| {
                refs(command).is_some_and(|(m, i)| {
                    m == msg && (first..first + fields.len() as u32).contains(&i)
                })
            })
            .cloned()
            .collect();
        consumed.extend(commands.iter().filter_map(refs));
        let mut run = store::load_on(c, &tenant, id).await?;
        if run.sealed_at.is_some()
            || !rss_mdm_execution_service::actions::native_collection::eligible_on(source, c, p, id)
                .await?
        {
            continue;
        }
        let limits = CodecLimits::default();
        let correlated = s::correlate(
            history,
            &s::Message {
                header: message.header.clone(),
                commands: message
                    .commands
                    .iter()
                    .filter(|command| {
                        matches!(command, Command::Status(status) if status.command_ref == 0)
                            || refs(command)
                                .is_some_and(|r| commands.iter().any(|c| refs(c) == Some(r)))
                    })
                    .cloned()
                    .collect(),
                final_message: true,
            },
            &limits,
        )
        .map_err(|_| Error::Conflict)?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        for status in correlated.statuses {
            if status.message_id != msg
                || !(first..first + fields.len() as u32).contains(&status.command_id)
            {
                continue;
            }
            let key = FieldKey::parse(fields[(status.command_id - first) as usize].0)
                .map_err(|_| corrupt())?;
            run.attempts
                .observe_status(key, status.code, now)
                .map_err(|_| Error::Conflict)?;
        }
        for result in correlated.results {
            if !result.explicit_message_ref
                || !result.explicit_command_ref
                || result.reference.message_id != msg
                || !(first..first + fields.len() as u32).contains(&result.reference.command_id)
            {
                return Err(Error::Conflict);
            }
            let (key, mapping) = fields[(result.reference.command_id - first) as usize];
            let expected_uri = queries[(result.reference.command_id - first) as usize]
                .objects()
                .map_err(|_| corrupt())?
                .into_iter()
                .next()
                .ok_or_else(corrupt)?
                .key().to_owned();
            if result.reference.uri != expected_uri {
                return Err(Error::Conflict);
            }
            let key = FieldKey::parse(key).map_err(|_| corrupt())?;
            let field = run
                .attempts
                .definition()
                .field(key)
                .map_err(|_| corrupt())?;
            let value = native::value(field, mapping, &serde_json::Value::String(result.value.0));
            match value {
                NativeValue::Value(value)
                    if run.attempts.value_bytes().map_err(|_| corrupt())?
                        + value.encode(field).map_err(|_| corrupt())?.len()
                        <= template.spec().output_bytes as usize =>
                {
                    run.attempts
                        .observe_value(key, value, now)
                        .map_err(|_| Error::Conflict)?
                }
                NativeValue::InvalidItems(items) => run
                    .attempts
                    .observe_invalid_items(key, items, now)
                    .map_err(|_| Error::Conflict)?,
                _ => run
                    .attempts
                    .observe_invalid(key, now)
                    .map_err(|_| Error::Conflict)?,
            }
        }
        if run.attempts.complete() && message.final_message {
            facts.extend(store::seal(c, &mut run, "complete").await?);
        } else if message.header.message_id as usize >= CodecLimits::default().session_messages {
            facts.extend(
                rss_mdm_inventory_service::collection::channel::abandon_in(
                    c,
                    &p.tenant().to_string(),
                    id,
                    "message_budget",
                )
                .await?,
            );
        } else {
            store::save_attempts_in(c, &run).await?;
        }
    }
    Ok(s::Message {
        header: message.header.clone(),
        commands: message
            .commands
            .iter()
            .filter(|v| !refs(v).is_some_and(|r| consumed.contains(&r)))
            .cloned()
            .collect(),
        final_message: message.final_message,
    })
}
