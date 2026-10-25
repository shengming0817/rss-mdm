//! Native CA installation uses the authenticated SyncML transcript and exact CSP readback.
//! ref: Microsoft RootCATrustedCertificates CSP, Device/Root and Device/CA/EncodedCertificate.
use crate::{Error, Failure, Windows, database::db, device::DevicePrincipal};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::pki::Acknowledgement;
use rss_mdm_native_protection::Protector;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    statuses: Vec<Option<u16>>,
    values: Vec<Option<String>>,
}
fn unavailable() -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn aad(
    p: &DevicePrincipal,
    id: Uuid,
    kind: &str,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    crate::protection::native_aad(
        p.tenant(),
        kind,
        &(p.registration(), p.generation(), p.credential(), id),
    )
}
fn reference(command: &s::Command) -> Option<(u32, u32)> {
    match command {
        s::Command::Status(v) if v.command_ref != 0 => Some((v.message_ref, v.command_ref)),
        s::Command::Results(v) => Some((v.message_ref.unwrap_or(1), v.command_ref.unwrap_or(1))),
        _ => None,
    }
}
async fn targets(
    c: &mut PgConnection,
    w: &Windows,
    p: &DevicePrincipal,
) -> Result<
    Vec<(
        rss_mdm_windows_mdm::provisioning::AuthorityCertificate,
        bool,
    )>,
    Error,
> {
    let mut result = w
        .trust_certificates()?
        .into_iter()
        .map(|c| (c, false))
        .collect::<Vec<_>>();
    let previous:Option<Vec<u8>>=sqlx::query_scalar("SELECT body FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND purpose='windows' AND registration=$2")
        .bind(p.tenant().to_string()).bind(p.registration()).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(bytes) = previous {
        let public: rss_mdm_agent_wire::pki::Trust =
            serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        let prior = rss_mdm_device_trust::DeviceTrust::restore(
            public,
            rss_mdm_agent_wire::pki::Purpose::Windows,
            now,
        )
        .map_err(|_| unavailable())?;
        let old = prior.public().map_err(|_| unavailable())?;
        let current = w.ca.trust.public().map_err(|_| unavailable())?;
        if old.tenant != current.tenant || old.origin != current.origin {
            return Err(Error::Conflict);
        }
        for (root, certificate) in prior.certificates().map_err(|_| unavailable())? {
            if result.iter().any(|(c, _)| c.certificate == certificate) {
                continue;
            }
            let thumbprint =
                ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &certificate)
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
            use rss_mdm_windows_mdm::provisioning::{AuthorityCertificate, AuthorityStore};
            result.push((
                AuthorityCertificate {
                    store: if root {
                        AuthorityStore::Root
                    } else {
                        AuthorityStore::Intermediate
                    },
                    certificate,
                    thumbprint,
                },
                true,
            ));
        }
    }
    Ok(result)
}
pub(crate) async fn send(
    c: &mut PgConnection,
    key: &Protector,
    w: &Windows,
    p: &DevicePrincipal,
    response: &mut s::Message,
    limits: &CodecLimits,
    effects: (
        &mut Vec<rss_mdm_audit_integration::Fact>,
        &crate::RequestAudit,
    ),
) -> Result<bool, Error> {
    let (facts, audit) = effects;
    let trust = w.ca.trust.public().map_err(|_| Error::Conflict)?;
    let digest = trust.installation_digest();
    let tenant = p.tenant().to_string();
    let session = i64::from(response.header.session_id);
    let done:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND registration=$2 AND purpose='windows' AND revision=$3 AND digest=$4)")
        .bind(&tenant).bind(p.registration()).bind(trust.revision as i64).bind(&digest).fetch_one(&mut *c).await.map_err(db)?;
    if done {
        return Ok(false);
    }
    let authorities = targets(c, w, p).await?;
    if authorities.is_empty() || authorities.len() > 64 {
        return Err(Error::Conflict);
    }
    let confirmed:Vec<String>=sqlx::query_scalar("SELECT DISTINCT authority FROM mdm_windows.trust_deliveries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 AND digest=$5 AND confirmed")
        .bind(&tenant).bind(p.registration()).bind(p.generation()).bind(trust.revision as i64).bind(&digest).fetch_all(&mut *c).await.map_err(db)?;
    let Some(authority) = authorities
        .into_iter()
        .find(|(a, _)| !confirmed.contains(&rss_mdm_device_trust::digest(&a.certificate)))
    else {
        return Ok(false);
    };
    let authority_digest = rss_mdm_device_trust::digest(&authority.0.certificate);
    if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_windows.trust_deliveries WHERE tenant_id=$1::uuid AND registration=$2 AND session=$3 AND revision=$4 AND authority=$5)")
        .bind(&tenant).bind(p.registration()).bind(session).bind(trust.revision as i64).bind(&authority_digest).fetch_one(&mut *c).await.map_err(db)? {return Ok(true);}
    // One authority per message fits negotiated device budgets; progress survives message/session changes.
    let authorities = [authority];
    let count = 1;
    let first = crate::device::store::allocate_commands_in(c, p, (count * 2) as i64).await?;
    let mut commands = Vec::new();
    for (i, (cert, remove)) in authorities.iter().enumerate() {
        use rss_mdm_windows_mdm::provisioning::AuthorityStore;
        let uri = format!(
            "./Device/Vendor/MSFT/RootCATrustedCertificates/{}/{}/EncodedCertificate",
            if matches!(cert.store, AuthorityStore::Root) {
                "Root"
            } else {
                "CA"
            },
            cert.thumbprint
        );
        if *remove {
            commands.push(s::Command::Delete {
                id: first + i as u32,
                meta: None,
                items: vec![s::Item {
                    target: Some(uri.trim_end_matches("/EncodedCertificate").to_owned()),
                    source: None,
                    meta: None,
                    data: None,
                    more_data: false,
                }],
            });
        } else {
            commands.push(s::Command::Add {
                id: first + i as u32,
                meta: Some(s::Meta {
                    format: Some("b64".into()),
                    ..Default::default()
                }),
                items: vec![s::Item {
                    target: Some(uri.clone()),
                    source: None,
                    meta: None,
                    data: Some(Secret(STANDARD.encode(&cert.certificate))),
                    more_data: false,
                }],
            });
        }
    }
    for i in 0..count {
        let items = match &commands[i] {
            s::Command::Add { items, .. } | s::Command::Delete { items, .. } => items,
            _ => return Err(unavailable()),
        };
        commands.push(s::Command::Get {
            id: first + (count + i) as u32,
            meta: None,
            items: vec![s::Item {
                target: items[0].target.as_ref().map(|uri| {
                    if matches!(commands[i], s::Command::Delete { .. }) {
                        format!("{uri}/EncodedCertificate")
                    } else {
                        uri.clone()
                    }
                }),
                source: None,
                meta: None,
                data: None,
                more_data: false,
            }],
        });
    }
    let mut complete = response.clone();
    complete.commands.extend(commands.clone());
    if s::encode_outbound(&complete, limits).is_err() {
        return Ok(true);
    }
    let mut request = response.clone();
    request.commands = commands.clone();
    let bytes = s::encode(&request, &CodecLimits::default()).map_err(|_| unavailable())?;
    let id = Uuid::new_v4();
    let sealed = key
        .seal_bytes(&bytes, &aad(p, id, "windows.pki.request")?)
        .map_err(|_| unavailable())?;
    let results = key
        .seal_bytes(
            &serde_json::to_vec(&Progress {
                statuses: vec![None; count * 2],
                values: vec![None; count],
            })
            .map_err(|_| unavailable())?,
            &aad(p, id, "windows.pki.results")?,
        )
        .map_err(|_| unavailable())?;
    sqlx::query("INSERT INTO mdm_windows.trust_deliveries(tenant_id,id,registration,generation,credential,revision,digest,session,message,first_command,request,results,authority) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(trust.revision as i64).bind(&digest).bind(session)
        .bind(i64::from(response.header.message_id)).bind(i64::from(first)).bind(sealed).bind(results).bind(&authority_digest).execute(&mut *c).await.map_err(db)?;
    let a = audit.fact_copy("windows_pki_install");
    a.identify_device(p.registration());
    a.registration(p.registration());
    a.target(p.device());
    facts.push(rss_mdm_audit_integration::Fact::business(
        &a,
        &format!("windows-pki:{id}:dispatch"),
        200,
        "success",
        Some(id),
    )?);
    response.commands.extend(commands);
    Ok(true)
}
pub(crate) async fn receive(
    c: &mut PgConnection,
    key: &Protector,
    w: &Windows,
    p: &DevicePrincipal,
    message: (&s::Message, &s::Expected),
    a: &crate::RequestAudit,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<s::Message, Error> {
    let (raw, expected) = message;
    let rows=sqlx::query("SELECT * FROM mdm_windows.trust_deliveries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND credential=$4 AND session=$5 ORDER BY first_command FOR UPDATE")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(p.credential()).bind(i64::from(raw.header.session_id)).fetch_all(&mut *c).await.map_err(db)?;
    let mut consumed = std::collections::BTreeSet::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let message = row.try_get::<i64, _>("message").map_err(db)? as u32;
        let first = row.try_get::<i64, _>("first_command").map_err(db)? as u32;
        let request = key
            .open_bytes(
                &row.try_get::<Vec<u8>, _>("request").map_err(db)?,
                &aad(p, id, "windows.pki.request")?,
            )
            .map_err(|_| unavailable())?;
        let request =
            s::decode(request.expose(), &CodecLimits::default()).map_err(|_| unavailable())?;
        let count = request.commands.len() / 2;
        let results = key
            .open_bytes(
                &row.try_get::<Vec<u8>, _>("results").map_err(db)?,
                &aad(p, id, "windows.pki.results")?,
            )
            .map_err(|_| unavailable())?;
        let mut progress: Progress =
            serde_json::from_slice(results.expose()).map_err(|_| unavailable())?;
        if count == 0
            || count > 32
            || request.commands.len() != count * 2
            || progress.statuses.len() != count * 2
            || progress.values.len() != count
            || request.header.message_id != message
        {
            return Err(unavailable());
        }
        let matches = |command: &s::Command| {
            reference(command).is_some_and(|(m, c)| {
                m == message && (first..first + count as u32 * 2).contains(&c)
            })
        };
        if !raw.commands.iter().any(matches) {
            continue;
        }
        let report = s::correlate(
            expected,
            &s::Message {
                header: raw.header.clone(),
                commands: raw
                    .commands
                    .iter()
                    .filter(|v| matches(v) || matches!(v,s::Command::Status(s) if s.command_ref==0))
                    .cloned()
                    .collect(),
                final_message: raw.final_message,
            },
            &CodecLimits::default(),
        )
        .map_err(|_| Error::Conflict)?;
        for status in report.statuses.into_iter().filter(|s| s.command_id != 0) {
            let i = status
                .command_id
                .checked_sub(first)
                .filter(|i| *i < count as u32 * 2)
                .ok_or(Error::Conflict)? as usize;
            if progress.statuses[i].is_some_and(|old| {
                old >= 200 && !matches!(old, 202 | 206 | 213) && old != status.code
            }) {
                return Err(Error::Conflict);
            }
            progress.statuses[i] = Some(status.code);
        }
        for result in report.results {
            let i = result
                .reference
                .command_id
                .checked_sub(first + count as u32)
                .filter(|i| *i < count as u32)
                .ok_or(Error::Conflict)? as usize;
            if result.value.0.len() > 65536
                || progress.values[i]
                    .as_ref()
                    .is_some_and(|old| *old != result.value.0)
            {
                return Err(Error::Conflict);
            }
            progress.values[i] = Some(result.value.0);
        }
        let confirmed = (0..count).all(|i| {
            let (items, remove) = match &request.commands[i] {
                s::Command::Add { items, .. } => (items, false),
                s::Command::Delete { items, .. } => (items, true),
                _ => return false,
            };
            let s::Command::Get { items: query, .. } = &request.commands[count + i] else {
                return false;
            };
            if !items[0]
                .target
                .as_ref()
                .zip(query[0].target.as_ref())
                .is_some_and(|(target, query)| {
                    if remove {
                        query == &format!("{target}/EncodedCertificate")
                    } else {
                        target == query
                    }
                })
            {
                return false;
            }
            if remove {
                return progress.statuses[count + i] == Some(404) && progress.values[i].is_none();
            }
            progress.statuses[count + i] == Some(200)
                && progress.values[i]
                    .as_ref()
                    .zip(items[0].data.as_ref())
                    .is_some_and(|(actual, original)| {
                        STANDARD
                            .decode(actual)
                            .ok()
                            .zip(STANDARD.decode(&original.0).ok())
                            .is_some_and(|(a, b)| a == b)
                    })
        });
        let sealed = key
            .seal_bytes(
                &serde_json::to_vec(&progress).map_err(|_| unavailable())?,
                &aad(p, id, "windows.pki.results")?,
            )
            .map_err(|_| unavailable())?;
        sqlx::query("UPDATE mdm_windows.trust_deliveries SET results=$3,confirmed=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id).bind(sealed).bind(confirmed).execute(&mut *c).await.map_err(db)?;
        let trust = w.ca.trust.public().map_err(|_| Error::Conflict)?;
        if confirmed
            && !row.try_get::<bool, _>("confirmed").map_err(db)?
            && row.try_get::<String, _>("digest").map_err(db)? == trust.installation_digest()
        {
            let installed:Vec<String>=sqlx::query_scalar("SELECT DISTINCT authority FROM mdm_windows.trust_deliveries WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 AND digest=$5 AND confirmed")
                .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(trust.revision as i64).bind(trust.installation_digest()).fetch_all(&mut *c).await.map_err(db)?;
            let complete = targets(c, w, p).await?.iter().all(|(cert, _)| {
                installed.contains(&rss_mdm_device_trust::digest(&cert.certificate))
            });
            if complete {
                rss_mdm_pki_service::registry::Registry::acknowledge_in(
                    c,
                    &p.tenant().to_string(),
                    p.registration(),
                    &trust,
                    &Acknowledgement {
                        operation: id,
                        version: 1,
                        revision: trust.revision,
                        digest: trust.installation_digest(),
                    },
                )
                .await
                .map_err(|_| Error::Conflict)?;
                facts.push(rss_mdm_audit_integration::Fact::business(
                    a,
                    &format!("windows-pki:{id}:confirmed"),
                    200,
                    "success",
                    Some(id),
                )?);
            }
        }
        consumed.extend(
            raw.commands
                .iter()
                .filter(|v| matches(v))
                .filter_map(reference),
        );
    }
    let mut output = raw.clone();
    output
        .commands
        .retain(|v| reference(v).is_none_or(|r| !consumed.contains(&r)));
    Ok(output)
}
