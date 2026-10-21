//! Agent presence reuses the bounded native read-plan executor, including Win32 inventory.
use crate::{Error, Failure, database::db, device::DevicePrincipal};
use rss_mdm_execution_service::agent_install::{DetectionCatalog, Identity};
use rss_mdm_inventory::{AgentInstallation, ReportSource};
use rss_mdm_inventory_service::collection::{
    channel::{self, AgentEvidence},
    store,
};
use rss_mdm_windows_mdm::{
    CodecLimits,
    native::collection::{Inventory, Outcome, Plan, Read, State},
    syncml::{self as s, Command, Item},
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
const ARCH: &str = "./DevDetail/Ext/Microsoft/ProcessorArchitecture";
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    catalog: DetectionCatalog,
    plans: Vec<Plan>,
    batch: usize,
    present_win32: Vec<String>,
    probes: Vec<Probe>,
    statuses: Vec<Option<u16>>,
    values: Vec<Option<String>>,
    exe_done: bool,
    exe_absent: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Probe {
    identity: Identity,
    offset: usize,
    width: usize,
}
fn protocol() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn refs(command: &Command) -> Option<(u32, u32)> {
    match command {
        Command::Status(v) if v.command_ref != 0 => Some((v.message_ref, v.command_ref)),
        Command::Results(v) => Some((v.message_ref?, v.command_ref?)),
        _ => None,
    }
}
async fn read_state(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    id: Uuid,
    bytes: &[u8],
) -> Result<State, Error> {
    let run = store::load_on(c, &p.tenant().to_string(), id).await?;
    rss_mdm_execution_service::native::open_collection_state(protection, &run.scope, id, bytes)
        .map_err(|_| protocol())
}
async fn save(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    id: Uuid,
    query: &Query,
    state: &State,
) -> Result<(), Error> {
    let run = store::load_on(c, &p.tenant().to_string(), id).await?;
    let bytes = serde_json::to_vec(state).map_err(|_| protocol())?;
    if bytes.len() > CodecLimits::default().object_bytes {
        return Err(protocol());
    }
    let sealed = protection
        .seal_bytes(&bytes, &crate::protection::collection_aad(&run.scope, id)?)
        .map_err(|_| protocol())?;
    sqlx::query("UPDATE mdm_windows.collections SET channel_state=$3,template_state=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id).bind(serde_json::to_value(query).map_err(|_|protocol())?).bind(sealed).execute(c).await.map_err(db)?;
    Ok(())
}
pub async fn receive(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    message: &s::Message,
    history: &s::Expected,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<s::Message, Error> {
    let rows=sqlx::query("SELECT w.id,w.channel_state,w.template_state,r.sealed_at FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.kind='agent' ORDER BY w.first_command")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(message.header.session_id.to_string()).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let mut query: Query = serde_json::from_value(row.try_get("channel_state").map_err(db)?)
            .map_err(|_| protocol())?;
        let mut state = read_state(
            c,
            protection,
            p,
            id,
            &row.try_get::<Vec<u8>, _>("template_state").map_err(db)?,
        )
        .await?;
        let commands: Vec<_> = message
            .commands
            .iter()
            .filter(|cmd| refs(cmd).is_some_and(|(m, c)| state.owns(m, c)))
            .cloned()
            .collect();
        if row
            .try_get::<Option<i64>, _>("sealed_at")
            .map_err(db)?
            .is_some()
        {
            if commands.is_empty() {
                continue;
            }
            return Err(Error::Conflict);
        }
        let report = s::correlate(
            history,
            &s::Message {
                header: message.header.clone(),
                commands: message
                    .commands
                    .iter()
                    .filter(|cmd| {
                        matches!(cmd,Command::Status(v) if v.command_ref==0)
                            || refs(cmd).is_some_and(|(m, c)| state.owns(m, c))
                    })
                    .cloned()
                    .collect(),
                final_message: message.final_message,
            },
            &CodecLimits::default(),
        )
        .map_err(|_| Error::Conflict)?;
        for status in report.statuses {
            if status.command_id != 0 {
                state
                    .status(status.message_id, status.command_id, status.code)
                    .map_err(|_| Error::Conflict)?;
            }
        }
        for result in report.results {
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
            .advance(
                &query.plans[query.batch],
                CodecLimits::default().object_bytes,
            )
            .map_err(|_| Error::Conflict)?;
        for (field, outcome) in state
            .outcomes(&query.plans[query.batch])
            .map_err(|_| protocol())?
        {
            if field == "win32" {
                query.exe_done = true;
                query.exe_absent = match outcome {
                    Outcome::Value(serde_json::Value::Array(rows)) => {
                        query.present_win32 = query
                            .catalog
                            .win32
                            .iter()
                            .filter(|identity| {
                                rows.iter().any(|row| {
                                    row["RegKey"]
                                        .as_str()
                                        .is_some_and(|key| key.eq_ignore_ascii_case(&identity.key))
                                })
                            })
                            .map(|identity| format!("win32:{}", identity.key))
                            .collect();
                        query.present_win32.is_empty()
                    }
                    _ => false,
                };
            } else {
                let index = field
                    .strip_prefix('v')
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|i| *i < query.statuses.len())
                    .ok_or_else(protocol)?;
                match outcome {
                    Outcome::Value(value) => {
                        query.statuses[index] = Some(200);
                        query.values[index] = Some(value.as_str().ok_or_else(protocol)?.to_owned());
                    }
                    Outcome::Status(code) => query.statuses[index] = Some(code),
                }
            }
        }
        if !state.pending() && query.batch + 1 < query.plans.len() {
            query.batch += 1;
            state = query.plans[query.batch]
                .start("agent-observation")
                .map_err(|_| protocol())?;
        }
        let complete = query.exe_done && query.statuses.iter().all(Option::is_some);
        if message.header.message_id as usize >= CodecLimits::default().session_messages
            && !(complete && message.final_message)
        {
            facts.extend(
                channel::abandon_in(c, &p.tenant().to_string(), id, "message_budget").await?,
            );
        } else if complete && message.final_message {
            let mut absent = query.catalog.complete
                && query.exe_absent
                && (!query.catalog.identities.is_empty() || !query.catalog.win32.is_empty());
            let mut installed = false;
            let mut provisioned = false;
            let mut identity = query.present_win32.first().cloned().unwrap_or_default();
            let mut publisher = None;
            let mut version = None;
            let mut checked_identities: Vec<String> = query
                .catalog
                .win32
                .iter()
                .map(|v| format!("win32:{}", v.key))
                .collect();
            for probe in &query.probes {
                let i = probe.offset;
                let (key, present, missing, pkg) = match &probe.identity {
                    Identity::WindowsMsi { product, publisher } => (
                        product.to_string(),
                        query.statuses[i..i + 3] == [Some(200); 3]
                            && query.values[i].as_deref() == Some("70")
                            && publisher.as_ref().is_none_or(|p| query.values[i + 1].as_ref() == Some(p))
                            && query.values[i + 2].as_ref().is_some_and(|v| !v.is_empty()),
                        query.statuses[i..i + 3] == [Some(404); 3],
                        false,
                    ),
                    Identity::WindowsMsix {
                        family, identity, ..
                    } => (
                        family.clone(),
                        query.statuses[i + 2..i + 6] == [Some(200); 4]
                            && query.values[i + 2].as_deref() == Some("0")
                            && query.values[i + 3].as_ref() == Some(&identity.publisher)
                            && query.values[i + 4].as_deref()
                                == Some(version_string(identity).as_str())
                            && matches!(
                                query.values[i + 5].as_deref(),
                                Some("1" | "True" | "true")
                            ),
                        query.statuses[i..i + 6] == [Some(404); 6],
                        true,
                    ),
                    _ => return Err(protocol()),
                };
                checked_identities.push(key.clone());
                absent &= missing;
                if present {
                    identity = key;
                    publisher = query.values[i + if pkg { 3 } else { 1 }].clone();
                    version = query.values[i + if pkg { 4 } else { 2 }].clone();
                    installed |= !pkg;
                    provisioned |= pkg;
                }
            }
            let state = if installed {
                AgentInstallation::Installed
            } else if absent {
                AgentInstallation::Absent
            } else {
                AgentInstallation::Unknown
            };
            let last = query.statuses.len() - 1;
            let architecture = if query.statuses[last] == Some(200) {
                match query.values[last].as_deref() {
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
                        catalog_digest: query.catalog.digest()?,
                        checked_identities,
                        provisioned,
                        identity,
                        publisher,
                        version,
                        architecture,
                    }),
                )
                .await?,
            );
        }
        save(c, protection, p, id, &query, &state).await?;
        consumed.extend(commands.iter().filter_map(refs));
    }
    Ok(s::Message {
        header: message.header.clone(),
        commands: message
            .commands
            .iter()
            .filter(|cmd| !refs(cmd).is_some_and(|r| consumed.contains(&r)))
            .cloned()
            .collect(),
        final_message: message.final_message,
    })
}
pub async fn send(
    mdm_software_enabled: bool,
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: &mut s::Message,
) -> Result<bool, Error> {
    if response.header.message_id as usize >= CodecLimits::default().session_messages {
        return Ok(false);
    }
    let old=sqlx::query("SELECT w.id,w.channel_state,w.template_state,r.sealed_at FROM mdm_windows.collections w JOIN mdm_access.collection_runs r USING(tenant_id,id) WHERE w.tenant_id=$1::uuid AND w.registration=$2 AND w.session_id=$3 AND w.kind='agent'").bind(p.tenant().to_string()).bind(p.registration()).bind(response.header.session_id.to_string()).fetch_optional(&mut *c).await.map_err(db)?;
    let (id, query, mut state) = if let Some(row) = old {
        if row
            .try_get::<Option<i64>, _>("sealed_at")
            .map_err(db)?
            .is_some()
        {
            return Ok(false);
        }
        let id = row.try_get("id").map_err(db)?;
        let query: Query = serde_json::from_value(row.try_get("channel_state").map_err(db)?)
            .map_err(|_| protocol())?;
        let state = read_state(
            c,
            protection,
            p,
            id,
            &row.try_get::<Vec<u8>, _>("template_state").map_err(db)?,
        )
        .await?;
        (id, query, state)
    } else {
        let catalog = rss_mdm_execution_service::agent_install::detection_on(
            c,
            p.tenant(),
            ReportSource::MdmWindows,
        )
        .await?;
        if catalog.identities.is_empty() && catalog.win32.is_empty() && !mdm_software_enabled {
            return Ok(false);
        }
        let query = query(catalog)?;
        let state = query.plans[query.batch]
            .start("agent-observation")
            .map_err(|_| protocol())?;
        let (id, scope, _) =
            channel::start_in(c, p, ReportSource::MdmWindows, query.catalog.digest()?).await?;
        let first = crate::device::store::allocate_commands_in(c, p, 1).await?;
        let bytes = protection
            .seal_bytes(
                &serde_json::to_vec(&state).map_err(|_| protocol())?,
                &crate::protection::collection_aad(&scope, id)?,
            )
            .map_err(|_| protocol())?;
        sqlx::query("INSERT INTO mdm_windows.collections(tenant_id,id,registration,session_id,request_message,first_command,channel_state,template_state,kind) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,'agent')").bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(i64::from(first)).bind(serde_json::to_value(&query).map_err(|_|protocol())?).bind(bytes).execute(&mut *c).await.map_err(db)?;
        (id, query, state)
    };
    let count = state.unsent().min(
        CodecLimits::default()
            .commands
            .saturating_sub(response.commands.len()),
    );
    if count > 0 {
        let first = crate::device::store::allocate_commands_in(c, p, count as i64).await?;
        for index in 0..count {
            let Some((step, request)) = state.next().map_err(|_| protocol())? else {
                break;
            };
            let objects = request.objects().map_err(|_| protocol())?;
            if objects.len() != 1 || !request.read_only().map_err(|_| protocol())? {
                return Err(protocol());
            }
            let uri = objects[0].key().to_owned();
            let command = first + index as u32;
            response.commands.push(Command::Get {
                id: command,
                meta: None,
                items: vec![Item {
                    more_data: false,
                    target: Some(uri),
                    source: None,
                    meta: None,
                    data: None,
                }],
            });
            if s::encode(response, &CodecLimits::default()).is_err() {
                response.commands.pop();
                break;
            }
            state
                .sent(step, response.header.message_id, command)
                .map_err(|_| protocol())?;
        }
    }
    save(c, protection, p, id, &query, &state).await?;
    Ok(state.pending())
}
fn query(catalog: DetectionCatalog) -> Result<Query, Error> {
    let mut uris = vec![];
    let mut probes = vec![];
    for identity in catalog.identities.iter().cloned() {
        let offset = uris.len();
        match &identity {
            Identity::WindowsMsi { product, .. } => {
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
            }
            Identity::WindowsMsix {
                family, identity, ..
            } => {
                let root = "./Device/Vendor/MSFT/EnterpriseModernAppManagement";
                for name in ["Status", "LastError"] {
                    uris.push(format!("{root}/AppInstallation/{family}/{name}"));
                }
                let arch = match identity.architecture {
                    rss_mdm_resource::MsixArchitecture::X86_64 => "x64",
                    rss_mdm_resource::MsixArchitecture::Aarch64 => "arm64",
                    rss_mdm_resource::MsixArchitecture::Neutral => "neutral",
                };
                let publisher_id = family.rsplit_once('_').ok_or_else(protocol)?.1;
                let full = format!(
                    "{}_{}_{}_{}_{}",
                    identity.name,
                    version_string(identity),
                    arch,
                    identity.resource_id,
                    publisher_id
                );
                for name in ["PackageStatus", "Publisher", "Version", "IsProvisioned"] {
                    uris.push(format!(
                        "{root}/AppManagement/nonStore/{family}/{full}/{name}"
                    ));
                }
            }
            _ => return Err(protocol()),
        }
        probes.push(Probe {
            identity,
            offset,
            width: uris.len() - offset,
        });
    }
    uris.push(ARCH.into());
    let count = uris.len();
    let mut reads = std::collections::BTreeMap::new();
    for (i, uri) in uris.into_iter().enumerate() {
        reads.insert(format!("v{i:04}"), Read::Scalar { uri });
    }
    let exe_done = catalog.win32.is_empty();
    if !exe_done {
        reads.insert(
            "win32".into(),
            Read::Inventory {
                inventory: Inventory::Win32,
            },
        );
    }
    let entries: Vec<_> = reads.into_iter().collect();
    let plans = entries
        .chunks(64)
        .map(|batch| {
            Plan::try_from(
                batch
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
            .map_err(|_| protocol())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Query {
        catalog,
        plans,
        batch: 0,
        present_win32: Vec::new(),
        probes,
        statuses: vec![None; count],
        values: vec![None; count],
        exe_done,
        exe_absent: exe_done,
    })
}
fn version_string(identity: &rss_mdm_resource::MsixIdentity) -> String {
    identity
        .version
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
