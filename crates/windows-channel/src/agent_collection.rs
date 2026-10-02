//! Fixed product inventory uses ordinary collection runs and SyncML correlation.
use crate::{Error, Failure, database::db, device::DevicePrincipal};
use rss_mdm_execution_service::agent_install::Identity;
use rss_mdm_inventory::{AgentInstallation, ReportSource};
use rss_mdm_inventory_service::collection::channel::{self, AgentEvidence};
use rss_mdm_windows_mdm::{
    CodecLimits,
    syncml::{self as s, Command, Item},
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
const ARCH: &str = "./DevDetail/Ext/Microsoft/ProcessorArchitecture";
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    product: Uuid,
    publisher: String,
    statuses: [Option<u16>; 4],
    values: [Option<String>; 4],
}
fn protocol() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn refs(c: &Command) -> Option<(u32, u32)> {
    match c {
        Command::Status(v) if v.command_ref != 0 => Some((v.message_ref, v.command_ref)),
        Command::Results(v) => Some((v.message_ref.unwrap_or(1), v.command_ref.unwrap_or(1))),
        _ => None,
    }
}
pub async fn receive(
    c: &mut PgConnection,
    _protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    message: &s::Message,
    history: &s::Expected,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<s::Message, Error> {
    let limits = CodecLimits::default();
    let rows=sqlx::query("SELECT w.id,w.request,w.request_message,w.first_command,w.channel_state,r.sealed_at FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.channel_state IS NOT NULL ORDER BY w.first_command")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(message.header.session_id.to_string()).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let first = row.try_get::<i64, _>("first_command").map_err(db)? as u32;
        let msg = row.try_get::<i64, _>("request_message").map_err(db)? as u32;
        let commands: Vec<_> = message
            .commands
            .iter()
            .filter(|v| refs(v).is_some_and(|(m, i)| m == msg && (first..first + 4).contains(&i)))
            .cloned()
            .collect();
        if commands.is_empty() {
            continue;
        }
        if row
            .try_get::<Option<i64>, _>("sealed_at")
            .map_err(db)?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let report = s::correlate(
            history,
            &s::Message {
                header: message.header.clone(),
                commands: message
                    .commands
                    .iter()
                    .filter(|v| {
                        matches!(v,Command::Status(s) if s.command_ref==0)
                            || refs(v).is_some_and(|r| commands.iter().any(|c| refs(c) == Some(r)))
                    })
                    .cloned()
                    .collect(),
                final_message: true,
            },
            &limits,
        )
        .map_err(|_| Error::Conflict)?;
        let mut query: Query = serde_json::from_value(row.try_get("channel_state").map_err(db)?)
            .map_err(|_| protocol())?;
        for status in report.statuses.into_iter().filter(|s| s.command_id != 0) {
            let i = status
                .command_id
                .checked_sub(first)
                .filter(|i| *i < 4)
                .ok_or(Error::Conflict)? as usize;
            if query.statuses[i].is_some_and(|v| v != status.code) {
                return Err(Error::Conflict);
            }
            query.statuses[i] = Some(status.code);
        }
        for value in report.results {
            let i = value
                .reference
                .command_id
                .checked_sub(first)
                .filter(|i| *i < 4)
                .ok_or(Error::Conflict)? as usize;
            if query.values[i]
                .as_ref()
                .is_some_and(|v| v != &value.value.0)
            {
                return Err(Error::Conflict);
            }
            query.values[i] = Some(value.value.0);
        }
        let complete = (0..4).all(|i| {
            query.statuses[i].is_some_and(|v| v >= 400 || v == 200 && query.values[i].is_some())
        });
        if (complete && message.final_message)
            || message.header.message_id as usize >= CodecLimits::default().session_messages
        {
            let absent = query.statuses[..3] == [Some(404); 3];
            let installed = query.statuses[..3] == [Some(200); 3]
                && query.values[0].as_deref() == Some("70")
                && query.values[1].as_deref() == Some(&query.publisher)
                && query.values[2]
                    .as_ref()
                    .is_some_and(|v| !v.is_empty() && v.len() <= 64);
            let state = if absent {
                AgentInstallation::Absent
            } else if installed {
                AgentInstallation::Installed
            } else {
                AgentInstallation::Unknown
            };
            // Microsoft documents ambiguous arm/x86 values; only explicit 64-bit evidence is usable.
            let architecture = if query.statuses[3] == Some(200) {
                match query.values[3].as_deref() {
                    Some("AMD64" | "amd64" | "x64" | "x86_64") => Some("x86_64".into()),
                    Some("ARM64" | "arm64" | "aarch64") => Some("aarch64".into()),
                    _ => None,
                }
            } else {
                None
            };
            facts.extend(
                channel::finish_in(
                    c,
                    p,
                    id,
                    ReportSource::MdmWindows,
                    state,
                    Some(AgentEvidence {
                        identity: query.product.to_string(),
                        publisher: query.values[1].clone(),
                        version: query.values[2].clone(),
                        architecture,
                    }),
                )
                .await?,
            );
        }
        sqlx::query("UPDATE mdm_windows.collections SET channel_state=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id).bind(serde_json::to_value(query).map_err(|_|protocol())?).execute(&mut *c).await.map_err(db)?;
        consumed.extend(commands.iter().filter_map(refs));
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
pub async fn send(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: &mut s::Message,
    identity: Option<&Identity>,
) -> Result<bool, Error> {
    let Some(Identity::Windows { product, publisher }) = identity else {
        return Ok(false);
    };
    if response.header.message_id as usize >= CodecLimits::default().session_messages {
        return Ok(false);
    }
    let old:Option<Option<i64>>=sqlx::query_scalar("SELECT r.sealed_at FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.channel_state IS NOT NULL")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(response.header.session_id.to_string()).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(sealed) = old {
        return Ok(sealed.is_none());
    }
    let (id, scope, _) = channel::start_in(c, p, ReportSource::MdmWindows).await?;
    let first = rss_mdm_inventory_service::collection::store::allocate_commands_in(c, p, 4).await?;
    let mut request = response.clone();
    request.commands.clear();
    let mut uris = vec![];
    for name in ["Status", "Publisher", "Version"] {
        uris.push(
            rss_mdm_windows_mdm::software::property(
                rss_mdm_windows_mdm::native::Scope::Device,
                &product.to_string(),
                name,
            )
            .map_err(|_| protocol())?,
        );
    }
    uris.push(ARCH.into());
    for (i, uri) in uris.into_iter().enumerate() {
        request.commands.push(Command::Get {
            id: first + i as u32,
            meta: None,
            items: vec![Item {
                more_data: false,
                target: Some(uri),
                source: None,
                meta: None,
                data: None,
            }],
        });
    }
    let wire = s::encode(&request, &CodecLimits::default()).map_err(|_| protocol())?;
    let query = Query {
        product: *product,
        publisher: publisher.clone(),
        statuses: [None; 4],
        values: std::array::from_fn(|_| None),
    };
    let wire = protection
        .seal_bytes(&wire, &crate::protection::collection_aad(&scope, id)?)
        .map_err(|_| protocol())?;
    sqlx::query("INSERT INTO mdm_windows.collections(tenant_id,id,registration,session_id,request_message,first_command,request,channel_state) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(i64::from(first)).bind(wire).bind(serde_json::to_value(query).map_err(|_|protocol())?).execute(&mut *c).await.map_err(db)?;
    response.commands.extend(request.commands);
    Ok(true)
}
