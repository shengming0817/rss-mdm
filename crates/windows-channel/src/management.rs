//! Fixed APPSRV BASIC / CLIENT DIGEST initialization and durable exact-response replay.
use super::*;

use crate::{database::db, device::DevicePrincipal};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{
    self, Challenge, Command, CommandName, Credential, Meta, Status,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use zeroize::Zeroizing;
pub async fn manage(
    State(app): State<Arc<HttpState>>,
    Extension(peer): Extension<rss_mdm_certificate::HandshakePeer>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, Error> {
    if headers.keys().any(|k| {
        k.as_str() == "forwarded"
            || k.as_str().starts_with("x-forwarded-")
            || k.as_str().starts_with("x-ssl-")
            || matches!(k.as_str(), "x-client-cert" | "x-device-id" | "x-tenant-id")
    }) {
        return Err(Error::Unauthorized);
    }
    if headers.get_all("content-type").iter().count() != 1
        || !headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| {
                s.split(';').next().is_some_and(|s| {
                    s.trim()
                        .eq_ignore_ascii_case("application/vnd.syncml.dm+xml")
                })
            })
    {
        return Err(Error::Malformed);
    }
    let checked = app.windows()?.ca.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let credential = app.mount.credential(checked.fingerprint());
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    let message = syncml::decode(&bytes, &CodecLimits::default()).map_err(|_| Error::Malformed)?;
    if message.header.source != principal.device()
        || message.header.target != app.windows()?.management_url()
    {
        return Err(Error::Forbidden);
    }
    for command in &message.commands {
        if let Command::DevInfo { items, .. } = command {
            for item in items {
                if item.source.as_deref() == Some("./DevInfo/DevId")
                    && item.data.as_ref().map(|v| v.0.as_str()) != Some(principal.device())
                {
                    return Err(Error::Forbidden);
                }
            }
        }
    }
    let response = app
        .execution
        .management(app.windows()?.clone(), &principal, &message, &bytes, &audit)
        .await?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.syncml.dm+xml; charset=utf-8",
        )],
        response,
    )
        .into_response())
}

use rss_mdm_execution_service::channels::{PackageState, Reply};
mod session;
async fn lock_sessions(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
) -> Result<(), Error> {
    // One registration lock orders nonce changes across sessions and restarts.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2351))")
        .bind(format!("{tenant}:{registration}"))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    // Session rows precede their collection row, including supersession and retention.
    sqlx::query("SELECT session_id FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state IN ('challenge','collecting') FOR UPDATE")
            .bind(tenant).bind(registration).fetch_all(&mut *tx).await.map_err(db)?;
    Ok(())
}

async fn collect(
    tx: &mut sqlx::PgConnection,
    effects: (&mut Vec<rss_mdm_audit_integration::Fact>, &RequestAudit),
    scope: &rss_observation::Scope,
    message: &syncml::Message,
    native: (
        &rss_mdm_native_protection::Protector,
        Option<&sqlx::postgres::PgRow>,
        Option<&syncml::Expected>,
    ),
    response: &mut syncml::Message,
    authenticated_session: bool,
    dispatch: bool,
) -> Result<(Option<Uuid>, bool), Error> {
    let (facts, audit) = effects;
    let (protection, stored, history) = native;
    let tenant = scope.tenant().to_string();
    let registration = scope.registration().as_str().to_owned();
    let run_id = stored
        .map(|row| row.try_get::<Option<String>, _>("run_id").map_err(db))
        .transpose()?
        .flatten()
        .map(|id| Uuid::parse_str(&id).map_err(|_| Error::Unavailable(Failure::Database)))
        .transpose()?;
    if !authenticated_session
        && message
            .commands
            .iter()
            .any(|c| matches!(c, Command::Results(_)))
    {
        return Err(Error::Unauthorized);
    }
    if stored.is_none() {
        let sessions: Vec<String> = sqlx::query_scalar("SELECT session_id FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state IN ('challenge','collecting')")
            .bind(&tenant).bind(&registration).fetch_all(&mut *tx).await.map_err(db)?;
        for session in sessions {
            crate::collection::terminate_session(
                tx,
                facts,
                &tenant,
                &registration,
                &session,
                "superseded",
            )
            .await?;
        }
        sqlx::query("UPDATE mdm_access.management_sessions SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state IN ('challenge','collecting')")
                .bind(&tenant).bind(&registration).execute(&mut *tx).await.map_err(db)?;
    }
    let mut complete = false;
    if let Some(id) = run_id {
        if !authenticated_session {
            return Err(Error::Unauthorized);
        }
        complete = crate::collection::accept(
            tx,
            protection,
            facts,
            &tenant,
            id,
            message,
            history.ok_or(Error::Conflict)?,
        )
        .await?;
        audit.operation(id, "windows_management");
    } else if message
        .commands
        .iter()
        .any(|c| matches!(c, Command::Results(_)))
    {
        return Err(Error::Conflict);
    }
    let run_id = if dispatch && authenticated_session && run_id.is_none() {
        let id = crate::collection::create(tx, protection, scope, response).await?;
        audit.operation(id, "windows_management");
        if message.header.message_id as usize >= CodecLimits::default().session_messages {
            crate::collection::terminate_session(
                tx,
                facts,
                &tenant,
                &registration,
                &message.header.session_id.to_string(),
                "message_budget",
            )
            .await?;
            complete = true;
        }
        Some(id)
    } else {
        run_id
    };
    Ok((run_id, complete))
}

fn authenticate_client(
    registration: &str,
    secrets: &protection::Secrets,
    credential: Option<&Credential>,
    before: bool,
) -> Result<bool, Error> {
    Ok(match credential {
        Some(credential) => {
            if credential.meta.media_type.as_deref() != Some("syncml:auth-basic")
                || credential
                    .meta
                    .format
                    .as_deref()
                    .is_some_and(|v| v != "b64")
            {
                return Err(Error::Unauthorized);
            }
            let expected = Zeroizing::new(STANDARD.encode(format!(
                "{registration}:{}",
                secrets.client_password.as_str()
            )));
            if !crate::enrollment::equal(&credential.data.0, &expected) {
                return Err(Error::Unauthorized);
            }
            true
        }
        None => before,
    })
}
struct ServerAuthentication {
    nonce: Vec<u8>,
    next_nonce: Vec<u8>,
    authenticated: bool,
}
impl ServerAuthentication {
    async fn persist_nonce(
        &self,
        tx: &mut sqlx::PgConnection,
        tenant: &str,
        request: Uuid,
        message: &syncml::Message,
    ) -> Result<(), Error> {
        if let Some(nonce) = self.advertised_nonce(message) {
            crate::enrollment_store::update_nonce(&mut *tx, tenant, request.to_string(), nonce)
                .await
                .map_err(db)?;
        }
        Ok(())
    }
    fn advertised_nonce(&self, message: &syncml::Message) -> Option<&[u8]> {
        (self.authenticated && message.commands.iter().any(|c| matches!(c, Command::Status(s) if s.command == CommandName::SyncHdr && s.challenge.is_some()))).then_some(self.next_nonce.as_slice())
    }
}

fn authenticate_server(
    stored: Option<&sqlx::postgres::PgRow>,
    history: Option<&syncml::Expected>,
    message: &syncml::Message,
    mut nonce: Vec<u8>,
) -> Result<ServerAuthentication, Error> {
    let mut next_nonce = nonce.clone();
    let mut server_authenticated = false;
    if let Some(row) = stored {
        let expected = history.ok_or(Error::Conflict)?;
        let collecting = row.try_get::<String, _>("state").map_err(db)? == "collecting";
        let statuses = syncml::Message {
            header: message.header.clone(),
            commands: message
                .commands
                .iter()
                .filter(|c| matches!(c, Command::Status(s) if !collecting || s.command == CommandName::SyncHdr))
                .cloned()
                .collect(),
            final_message: true,
        };
        let _correlated = syncml::correlate(expected, &statuses, &CodecLimits::default())
            .map_err(|_| Error::Conflict)?;
        let header_status = message
            .commands
            .iter()
            .find_map(|c| match c {
                Command::Status(s) if s.command == CommandName::SyncHdr => Some(s),
                _ => None,
            })
            .ok_or(Error::Conflict)?;
        match header_status.code {
            212 => server_authenticated = true,
            200 if row.try_get::<String, _>("state").map_err(db)? == "collecting" => {
                server_authenticated = true
            }
            401 | 407 => {}
            _ => return Err(Error::Unauthorized),
        }
        if let Some(challenge) = &header_status.challenge {
            if challenge.media_type != "syncml:auth-md5" {
                return Err(Error::Unauthorized);
            }
            next_nonce = STANDARD
                .decode(&challenge.nonce.as_ref().ok_or(Error::Malformed)?.0)
                .map_err(|_| Error::Malformed)?;
            if !(16..=64).contains(&next_nonce.len()) || next_nonce == nonce {
                return Err(Error::Malformed);
            }
            // A successful Status advertises the next session nonce; a challenge retries now.
            if !server_authenticated {
                nonce = next_nonce.clone();
            }
        } else if row.try_get::<String, _>("state").map_err(db)? != "collecting" {
            return Err(Error::Unauthorized);
        }
    }
    Ok(ServerAuthentication {
        nonce,
        next_nonce,
        authenticated: server_authenticated,
    })
}
fn initialization(
    message: &syncml::Message,
    authenticated_before: bool,
) -> Result<Vec<&Command>, Error> {
    let initial: Vec<_> = message
        .commands
        .iter()
        .filter(|c| !matches!(c, Command::Status(_) | Command::Results(_)))
        .collect();
    if !authenticated_before
        && !matches!(
            initial.as_slice(),
            [Command::Alert { .. }, Command::DevInfo { .. }]
        )
        || authenticated_before
            && initial.iter().any(|c| {
                !matches!(
                    c,
                    Command::Alert {
                        alert: syncml::Alert::Generic { .. }
                            | syncml::Alert::SessionAbort
                            | syncml::Alert::MoreMessages
                            | syncml::Alert::EndOfData { .. },
                        ..
                    }
                )
            })
    {
        return Err(Error::Malformed);
    }
    Ok(initial)
}
fn management_response(
    windows: &Windows,
    principal: &DevicePrincipal,
    message: &syncml::Message,
    secrets: &protection::Secrets,
    authenticated: bool,
    nonce: &[u8],
    initial: Vec<&Command>,
) -> Result<syncml::Message, Error> {
    let mut execution = vec![Command::Status(Status {
        credential: None,
        id: 1,
        message_ref: message.header.message_id,
        command_ref: 0,
        command: CommandName::SyncHdr,
        target_refs: vec![],
        source_refs: vec![],
        code: if authenticated { 212 } else { 401 },
        items: vec![],
        challenge: (!authenticated).then(|| Challenge {
            media_type: "syncml:auth-basic".into(),
            nonce: None,
        }),
    })];
    if authenticated {
        for command in initial {
            let kind = match command {
                Command::Alert { .. } => CommandName::Alert,
                Command::DevInfo { .. } => CommandName::Replace,
                _ => return Err(Error::Malformed),
            };
            execution.push(Command::Status(Status {
                credential: None,
                id: execution.len() as u32 + 1,
                message_ref: message.header.message_id,
                command_ref: command.id(),
                command: kind,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
            }));
        }
    }
    for result in message
        .commands
        .iter()
        .filter(|c| matches!(c, Command::Results(_)))
    {
        execution.push(Command::Status(Status {
            id: execution.len() as u32 + 1,
            message_ref: message.header.message_id,
            command_ref: result.id(),
            command: CommandName::Results,
            target_refs: vec![],
            source_refs: vec![],
            code: 200,
            items: vec![],
            challenge: None,
            credential: None,
        }));
    }
    let response = syncml::Message {
        header: syncml::Header {
            session_id: message.header.session_id,
            message_id: message.header.message_id,
            target: principal.device().into(),
            source: windows.management_url(),
            credential: Some(Credential {
                meta: Meta {
                    format: Some("b64".into()),
                    media_type: Some("syncml:auth-md5".into()),
                    ..Meta::default()
                },
                data: Secret(protection::digest(
                    &windows.provider_id,
                    &secrets.server_password,
                    nonce,
                )),
            }),
            meta: None,
        },
        commands: execution,
        final_message: true,
    };
    Ok(response)
}

fn verify_session_identity(
    row: &sqlx::postgres::PgRow,
    principal: &DevicePrincipal,
) -> Result<(), Error> {
    if !row.try_get::<bool, _>("live").map_err(db)?
        || row.try_get::<i64, _>("generation").map_err(db)? != principal.generation()
        || row.try_get::<String, _>("credential").map_err(db)? != principal.credential().to_string()
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

enum SessionDecision {
    Replay(Reply, PackageState),
    Continue(Option<sqlx::postgres::PgRow>),
}
async fn session_decision(
    tx: &mut sqlx::PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    principal: &DevicePrincipal,
    message: &syncml::Message,
    digest: &str,
    audit: &RequestAudit,
) -> Result<SessionDecision, Error> {
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    let session = message.header.session_id.to_string();
    let message_id = i64::from(message.header.message_id);
    let stored=sqlx::query("SELECT generation,credential::text,run_id::text,state,last_message,client_authenticated,nonce,expires_at>clock_timestamp() AS live FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 FOR UPDATE")
        .bind(&tenant).bind(&registration).bind(&session).fetch_optional(&mut *tx).await.map_err(db)?;
    if let Some(row) = &stored {
        verify_session_identity(row, principal)?;
        if let Some(old)=sqlx::query("SELECT digest,response,package_state FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 AND message_id=$4")
            .bind(&tenant).bind(&registration).bind(&session).bind(message_id).fetch_optional(&mut *tx).await.map_err(db)? {
            if old.try_get::<String,_>("digest").map_err(db)?!=digest { return Err(Error::Conflict); }
            audit.operation(Uuid::from_bytes(Sha256::digest(format!("{registration}:{session}:{message_id}")).as_slice()[..16].try_into().expect("digest width")),"windows_management");
            audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
            let sealed: Vec<u8> = old.try_get("response").map_err(db)?;
            let aad = crate::protection::native_aad(principal.tenant(), "windows.management.response", &(principal.registration(), principal.generation(), principal.credential(), &session, message_id))?;
            let plain = protection.open_bytes(&sealed, &aad).map_err(|_| Error::Unavailable(Failure::Protocol))?;
            let package = match old.try_get::<String,_>("package_state").map_err(db)?.as_str() {
                "complete" => PackageState::Complete, "partial" => PackageState::Partial, "aborted" => PackageState::Aborted,
                _ => return Err(Error::Unavailable(Failure::Protocol)),
            };
            return Ok(SessionDecision::Replay(Reply { bytes: plain.expose().to_vec(), facts: vec![] }, package));
        }
        if !matches!(
            row.try_get::<String, _>("state").map_err(db)?.as_str(),
            "challenge" | "collecting"
        ) || row.try_get::<i64, _>("last_message").map_err(db)? + 1 != message_id
            || message_id as usize > CodecLimits::default().session_messages
        {
            return Err(Error::Conflict);
        }
    } else if message_id != 1
        || message
            .commands
            .iter()
            .any(|c| matches!(c, Command::Status(_) | Command::Results(_)))
    {
        return Err(Error::Conflict);
    }
    Ok(SessionDecision::Continue(stored))
}

async fn notify(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'windows')").execute(c).await?;
    Ok(())
}

/// The native listener supplies the TLS peer; JSON has no source identity overrides.
pub async fn register_agent(
    State(app): State<Arc<HttpState>>,
    Extension(peer): Extension<rss_mdm_certificate::HandshakePeer>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, Error> {
    if bytes.len() > 16384
        || headers.keys().any(|k| {
            k.as_str() == "forwarded"
                || k.as_str().starts_with("x-forwarded-")
                || k.as_str().starts_with("x-ssl-")
                || matches!(k.as_str(), "x-client-cert" | "x-device-id" | "x-tenant-id")
        })
    {
        return Err(Error::Malformed);
    }
    if headers.get_all("content-type").iter().count() != 1
        || headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/json")
    {
        return Err(Error::Malformed);
    }
    let checked = app.windows()?.ca.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let principal = app
        .devices
        .management_principal(&app.mount.credential(checked.fingerprint()))
        .await?;
    let input = match rss_mdm_agent_wire::ManagedRegistrationRequest::decode(&bytes) {
        Ok(input) => input,
        Err(code) => {
            let mut response = Error::Malformed.into_response();
            response
                .extensions_mut()
                .insert(rss_mdm_agent_wire::ErrorBody { code });
            return Ok(response);
        }
    };
    let (receipt, replay) = app
        .execution
        .managed_registration(
            &principal,
            rss_mdm_inventory::ReportSource::MdmWindows,
            &input,
            &audit,
        )
        .await?;
    Ok((
        if replay {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::CREATED
        },
        axum::Json(receipt),
    )
        .into_response())
}
