//! Native PFN/ChannelURI observations feed the Windows push route, never operation completion.
use crate::{Error, Failure, Windows, database::db, device::DevicePrincipal};
use rss_mdm_native_protection::Protector;
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use sqlx::Row;
use std::collections::BTreeMap;
fn corrupt() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn targets(w: &Windows) -> [String; 2] {
    [
        format!(
            "./Device/Vendor/MSFT/DMClient/Provider/{}/Push/PFN",
            w.provider_id
        ),
        format!(
            "./Device/Vendor/MSFT/DMClient/Provider/{}/Push/ChannelURI",
            w.provider_id
        ),
    ]
}
fn aad(
    p: &DevicePrincipal,
    session: u32,
    kind: &str,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    crate::protection::native_aad(
        p.tenant(),
        kind,
        &(p.registration(), p.generation(), p.credential(), session),
    )
}
pub(crate) async fn send(
    c: &mut sqlx::PgConnection,
    key: &Protector,
    w: &Windows,
    p: &DevicePrincipal,
    response: &mut s::Message,
    limits: &CodecLimits,
) -> Result<bool, Error> {
    let Some(push) = &w.push else {
        return Ok(false);
    };
    let tenant = p.tenant().to_string();
    let session = response.header.session_id;
    let existing = sqlx::query("SELECT results FROM mdm_windows.push_queries WHERE tenant_id=$1::uuid AND registration=$2 AND session=$3")
        .bind(&tenant).bind(p.registration()).bind(i64::from(session)).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(row) = existing {
        let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("results").map_err(db)? else {
            return Ok(true);
        };
        let plain = key
            .open_bytes(&sealed, &aad(p, session, "windows.push.results")?)
            .map_err(|_| corrupt())?;
        let state: BTreeMap<String, Value> =
            serde_json::from_slice(plain.expose()).map_err(|_| corrupt())?;
        return Ok(state.values().any(|v| {
            v.status
                .is_none_or(|s| s < 200 || matches!(s, 202 | 206 | 213))
                || (v.status == Some(200) && v.value.is_none())
        }));
    }
    let id = rss_mdm_inventory_service::collection::store::allocate_commands_in(c, p, 1).await?;
    let command = s::Command::Get {
        id,
        meta: None,
        items: targets(w)
            .into_iter()
            .map(|uri| s::Item {
                target: Some(uri),
                source: None,
                meta: None,
                data: None,
                more_data: false,
            })
            .collect(),
    };
    let mut complete = response.clone();
    complete.commands.push(command.clone());
    if s::encode(&complete, limits).is_err() {
        return Ok(true);
    }
    let mut request = response.clone();
    request.commands = vec![command.clone()];
    let bytes = s::encode(&request, &CodecLimits::default()).map_err(|_| corrupt())?;
    let sealed = key
        .seal_bytes(&bytes, &aad(p, session, "windows.push.query")?)
        .map_err(|_| corrupt())?;
    sqlx::query("INSERT INTO mdm_windows.push_queries(tenant_id,registration,generation,credential,session,message,command,configuration,request) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(session)).bind(i64::from(response.header.message_id)).bind(i64::from(id)).bind(push.configuration.as_slice()).bind(sealed).execute(c).await.map_err(db)?;
    response.commands.push(command);
    Ok(true)
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Value {
    status: Option<u16>,
    value: Option<String>,
}
fn reference(command: &s::Command) -> Option<(u32, u32)> {
    match command {
        s::Command::Status(v) if v.command_ref != 0 => Some((v.message_ref, v.command_ref)),
        s::Command::Results(v) => Some((v.message_ref.unwrap_or(1), v.command_ref.unwrap_or(1))),
        _ => None,
    }
}
pub(crate) async fn receive(
    c: &mut sqlx::PgConnection,
    key: &Protector,
    w: &Windows,
    p: &DevicePrincipal,
    raw: &s::Message,
    expected: &s::Expected,
    audit: &crate::RequestAudit,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<s::Message, Error> {
    let tenant = p.tenant().to_string();
    let session = raw.header.session_id;
    let row=sqlx::query("SELECT message,command,configuration,request,results FROM mdm_windows.push_queries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND credential=$4 AND session=$5 FOR UPDATE")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(session)).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(raw.clone());
    };
    let msg = row.try_get::<i64, _>("message").map_err(db)? as u32;
    let command = row.try_get::<i64, _>("command").map_err(db)? as u32;
    let input = key
        .open_bytes(
            &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
            &aad(p, session, "windows.push.query")?,
        )
        .map_err(|_| corrupt())?;
    let request = s::decode(input.expose(), &CodecLimits::default()).map_err(|_| corrupt())?;
    let [s::Command::Get { id, items, .. }] = request.commands.as_slice() else {
        return Err(corrupt());
    };
    if *id != command || request.header.message_id != msg {
        return Err(corrupt());
    }
    let mut state: BTreeMap<String, Value> =
        match row.try_get::<Option<Vec<u8>>, _>("results").map_err(db)? {
            Some(value) => serde_json::from_slice(
                key.open_bytes(&value, &aad(p, session, "windows.push.results")?)
                    .map_err(|_| corrupt())?
                    .expose(),
            )
            .map_err(|_| corrupt())?,
            None => items
                .iter()
                .map(|i| Ok((i.target.clone().ok_or_else(corrupt)?, Value::default())))
                .collect::<Result<_, Error>>()?,
        };
    let report = s::Message {
        header: raw.header.clone(),
        commands: raw
            .commands
            .iter()
            .filter(|v| {
                matches!(v,s::Command::Status(s) if s.command_ref==0)
                    || reference(v) == Some((msg, command))
            })
            .cloned()
            .collect(),
        final_message: raw.final_message,
    };
    let report =
        s::correlate(expected, &report, &CodecLimits::default()).map_err(|_| Error::Conflict)?;
    for status in report
        .statuses
        .iter()
        .filter(|s| s.message_id == msg && s.command_id == command)
    {
        for (uri, value) in &mut state {
            if status.targets.is_empty() || status.targets.contains(uri) {
                if value.status.is_some_and(|old| {
                    old >= 200 && !matches!(old, 202 | 206 | 213) && old != status.code
                }) {
                    return Err(Error::Conflict);
                }
                value.status = Some(status.code);
            }
        }
    }
    for result in report
        .results
        .iter()
        .filter(|r| r.reference.message_id == msg && r.reference.command_id == command)
    {
        if result.value.0.len() > 4096
            || (result.reference.uri.ends_with("/PFN") && result.value.0.len() > 256)
        {
            return Err(Error::Malformed);
        }
        let value = state
            .get_mut(&result.reference.uri)
            .ok_or(Error::Conflict)?;
        if value
            .value
            .as_ref()
            .is_some_and(|old| old != &result.value.0)
        {
            return Err(Error::Conflict);
        }
        value.value = Some(result.value.0.clone());
    }
    let sealed = key
        .seal_bytes(
            &serde_json::to_vec(&state).map_err(|_| corrupt())?,
            &aad(p, session, "windows.push.results")?,
        )
        .map_err(|_| corrupt())?;
    sqlx::query("UPDATE mdm_windows.push_queries SET results=$4 WHERE tenant_id=$1::uuid AND registration=$2 AND session=$3").bind(&tenant).bind(p.registration()).bind(i64::from(session)).bind(sealed).execute(&mut *c).await.map_err(db)?;
    if let Some(push) = &w.push {
        let uri = targets(w);
        if raw
            .commands
            .iter()
            .any(|c| reference(c) == Some((msg, command)))
            && row.try_get::<Vec<u8>, _>("configuration").map_err(db)? == push.configuration
            && state
                .values()
                .all(|v| v.status == Some(200) && v.value.is_some())
            && state.get(&uri[0]).and_then(|v| v.value.as_deref()) == Some(push.pfn.as_str())
        {
            if let Some(value) = state
                .get(&uri[1])
                .and_then(|v| v.value.as_deref())
                .filter(|v| super::push::channel_uri(v).is_ok())
            {
                let aad = crate::protection::native_aad(
                    p.tenant(),
                    "windows.push.channel",
                    &(p.registration(), p.generation(), push.configuration),
                )?;
                let digest = key.mac(value.as_bytes(), &aad).map_err(|_| corrupt())?;
                let sealed = key
                    .seal_bytes(value.as_bytes(), &aad)
                    .map_err(|_| corrupt())?;
                let revision:Option<i64>=sqlx::query_scalar("INSERT INTO mdm_windows.push_channels(tenant_id,registration,generation,revision,configuration,uri,digest,expires_at) VALUES($1::uuid,$2,$3,1,$4,$5,$6,clock_timestamp()+interval '30 days') ON CONFLICT(tenant_id,registration) DO UPDATE SET generation=excluded.generation,revision=push_channels.revision+1,configuration=excluded.configuration,uri=excluded.uri,digest=excluded.digest,expires_at=excluded.expires_at,next_push=clock_timestamp(),lease_id=NULL,lease_until=NULL,settled_id=NULL,failures=0,status=NULL,outcome=NULL WHERE (push_channels.generation,push_channels.configuration,push_channels.digest) IS DISTINCT FROM (excluded.generation,excluded.configuration,excluded.digest) RETURNING revision")
                    .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(push.configuration.as_slice()).bind(sealed).bind(digest.as_slice()).fetch_optional(&mut *c).await.map_err(db)?;
                if let Some(revision) = revision {
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("windows-push:{}:{revision}:route", p.registration()),
                        &digest,
                        200,
                        "success",
                        None,
                    )
                    .and_then(|f| f.with_details(serde_json::json!({"revision":revision})))
                    .map_err(Error::from)?;
                    facts.push(fact);
                    crate::management::notify(c).await.map_err(db)?;
                } else {
                    // A newly correlated observation renews freshness without changing route identity,
                    // reviving rejected routes, or disturbing an in-flight lease.
                    sqlx::query("UPDATE mdm_windows.push_channels SET expires_at=clock_timestamp()+interval '30 days' WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND configuration=$4 AND digest=$5")
                        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(push.configuration.as_slice()).bind(digest.as_slice()).execute(&mut *c).await.map_err(db)?;
                }
            }
        }
    }
    let mut output = raw.clone();
    output
        .commands
        .retain(|c| reference(c) != Some((msg, command)));
    Ok(output)
}

pub(crate) async fn result_eligible(
    c: &mut sqlx::PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    session: u32,
    reference: &s::Reference,
) -> Result<Option<bool>, Error> {
    let row=sqlx::query("SELECT request FROM mdm_windows.push_queries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND credential=$4 AND session=$5 AND message=$6 AND command=$7")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(session)).bind(i64::from(reference.message_id)).bind(i64::from(reference.command_id)).fetch_optional(c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let plain = key
        .open_bytes(
            &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
            &aad(p, session, "windows.push.query")?,
        )
        .map_err(|_| corrupt())?;
    let request = s::decode(plain.expose(), &CodecLimits::default()).map_err(|_| corrupt())?;
    let [s::Command::Get { items, .. }] = request.commands.as_slice() else {
        return Err(corrupt());
    };
    Ok(Some(items.iter().any(|i| {
        i.target.as_deref() == Some(reference.uri.as_str())
    })))
}
