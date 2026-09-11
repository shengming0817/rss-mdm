//! Fixed APPSRV BASIC / CLIENT DIGEST initialization and durable exact-response replay.
use super::*;
use crate::{
    access_store::db,
    device::{DevicePrincipal, VerifiedChannelCredential},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{
    self, Challenge, Command, CommandName, Credential, Meta, Status,
};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use sqlx::Row;
use zeroize::Zeroizing;
pub(super) async fn manage(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<tls::Peer>,
    Extension(audit): Extension<Audit>,
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
    let checked = app.windows.ca.verify(peer.chain(), app.sessions.now()?)?;
    let credential = VerifiedChannelCredential::windows(
        TenantId::parse(app.policy.tenant()).map_err(|_| Error::Unauthorized)?,
        &checked,
    );
    let principal = app.devices.management_principal(&credential).await?;
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    let message = syncml::decode(&bytes, &CodecLimits::default()).map_err(|_| Error::Malformed)?;
    if message.header.source != principal.device()
        || message.header.target != app.windows.management_url()
        || !message.final_message
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
        .access
        .management(&app.windows, &principal, &message, &bytes, &audit)
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
impl crate::AccessStore {
    async fn management(
        &self,
        windows: &Windows,
        principal: &DevicePrincipal,
        message: &syncml::Message,
        bytes: &[u8],
        audit: &Audit,
    ) -> Result<Vec<u8>, Error> {
        let tenant = principal.tenant().to_string();
        let registration = principal.registration().to_string();
        let session = message.header.session_id.to_string();
        let message_id = i64::from(message.header.message_id);
        let digest = format!("{:x}", Sha256::digest(bytes));
        let mut tx = self.begin(&tenant).await?;
        // One registration lock orders nonce changes across sessions and restarts.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2351))")
            .bind(format!("{tenant}:{registration}"))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let stored = match session_decision(&mut tx, principal, message, &digest, audit).await? {
            SessionDecision::Replay(bytes) => return Ok(bytes),
            SessionDecision::Continue(stored) => stored,
        };
        let registration_data=sqlx::query("SELECT i.request_id::text,i.secrets,c.server_nonce FROM mdm_access.enrollment_intents i JOIN mdm_access.enrollment_certificates c ON (c.tenant_id,c.request_id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid AND i.registration=$2::uuid FOR UPDATE OF c")
            .bind(&tenant).bind(&registration).fetch_one(&mut *tx).await.map_err(db)?;
        let request = crate::enrollment::store::uuid(&registration_data, "request_id")?;
        let secrets = windows.protection.open(
            &tenant,
            request,
            &registration_data
                .try_get::<Vec<u8>, _>("secrets")
                .map_err(db)?,
        )?;
        let authenticated_before = stored
            .as_ref()
            .map(|r| r.try_get::<bool, _>("client_authenticated").map_err(db))
            .transpose()?
            .unwrap_or(false);
        let authenticated = authenticate_client(
            &registration,
            &secrets,
            message.header.credential.as_ref(),
            authenticated_before,
        )?;
        let nonce: Vec<u8> = stored
            .as_ref()
            .map(|r| r.try_get("nonce").map_err(db))
            .transpose()?
            .unwrap_or(registration_data.try_get("server_nonce").map_err(db)?);
        let server = authenticate_server(stored.as_ref(), message, nonce)?;
        let initial = initialization(message, authenticated_before)?;
        let complete = authenticated && server.authenticated;
        let response = management_response(
            windows,
            principal,
            message,
            &secrets,
            authenticated,
            &server.nonce,
            initial,
        )?;
        let correlation =
            std::str::from_utf8(&response).map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let state = if complete { "complete" } else { "challenge" };
        if stored.is_none() {
            // A registration has one advancing session. Keep old exact responses replayable.
            sqlx::query("UPDATE mdm_access.management_sessions SET state='superseded' WHERE tenant_id=$1::uuid AND registration=$2::uuid AND state='challenge'")
                .bind(&tenant).bind(&registration).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO mdm_access.management_sessions(tenant_id,registration,session_id,generation,credential,state,last_message,client_authenticated,correlation,nonce,expires_at) VALUES($1::uuid,$2::uuid,$3,$4,$5::uuid,$6,$7,$8,$9,$10,clock_timestamp()+interval '15 minutes')")
                .bind(&tenant).bind(&registration).bind(&session).bind(principal.generation()).bind(principal.credential().to_string()).bind(state).bind(message_id).bind(authenticated).bind(correlation).bind(&server.nonce).execute(&mut *tx).await.map_err(db)?;
        } else {
            sqlx::query("UPDATE mdm_access.management_sessions SET state=$4,last_message=$5,client_authenticated=$6,correlation=$7,nonce=$8 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3")
                .bind(&tenant).bind(&registration).bind(&session).bind(state).bind(message_id).bind(authenticated).bind(correlation).bind(&server.nonce).execute(&mut *tx).await.map_err(db)?;
        }
        if server.authenticated {
            sqlx::query("UPDATE mdm_access.enrollment_certificates SET server_nonce=$3 WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(&tenant).bind(request.to_string()).bind(&server.next_nonce).execute(&mut *tx).await.map_err(db)?;
        }
        sqlx::query("INSERT INTO mdm_access.management_messages(tenant_id,registration,session_id,message_id,digest,response) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)")
            .bind(&tenant).bind(&registration).bind(&session).bind(message_id).bind(digest).bind(&response).execute(&mut *tx).await.map_err(db)?;
        self.commit_audited(tx, audit, None).await?;
        Ok(response)
    }
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
            if !crate::sessions::equal(&credential.data.0, &expected) {
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
fn authenticate_server(
    stored: Option<&sqlx::postgres::PgRow>,
    message: &syncml::Message,
    mut nonce: Vec<u8>,
) -> Result<ServerAuthentication, Error> {
    let mut next_nonce = nonce.clone();
    let mut server_authenticated = false;
    if let Some(row) = stored {
        let previous: String = row.try_get("correlation").map_err(db)?;
        let previous = syncml::decode(previous.as_bytes(), &CodecLimits::default())
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let (_, sent) = syncml::encode_request(&previous, &CodecLimits::default())
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let expected =
            syncml::Expected::new(sent, message.header.message_id, &CodecLimits::default())
                .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let statuses = syncml::Message {
            header: message.header.clone(),
            commands: message
                .commands
                .iter()
                .filter(|c| matches!(c, Command::Status(_)))
                .cloned()
                .collect(),
            final_message: true,
        };
        let _correlated = syncml::correlate(&expected, &statuses, &CodecLimits::default())
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
        } else {
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
        .filter(|c| !matches!(c, Command::Status(_)))
        .collect();
    if !authenticated_before
        && !matches!(
            initial.as_slice(),
            [Command::Alert { .. }, Command::DevInfo { .. }]
        )
        || authenticated_before && !initial.is_empty()
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
) -> Result<Vec<u8>, Error> {
    let mut commands = vec![Command::Status(Status {
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
            commands.push(Command::Status(Status {
                credential: None,
                id: commands.len() as u32 + 1,
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
                    &windows.config.provider_id,
                    &secrets.server_password,
                    nonce,
                )),
            }),
            meta: None,
        },
        commands,
        final_message: true,
    };
    syncml::encode(&response, &CodecLimits::default())
        .map_err(|_| Error::Unavailable(Failure::Protocol))
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
    Replay(Vec<u8>),
    Continue(Option<sqlx::postgres::PgRow>),
}
async fn session_decision(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &DevicePrincipal,
    message: &syncml::Message,
    digest: &str,
    audit: &Audit,
) -> Result<SessionDecision, Error> {
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    let session = message.header.session_id.to_string();
    let message_id = i64::from(message.header.message_id);
    let stored=sqlx::query("SELECT generation,credential::text,state,last_message,client_authenticated,correlation,nonce,expires_at>clock_timestamp() AS live FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 FOR UPDATE")
        .bind(&tenant).bind(&registration).bind(&session).fetch_optional(&mut **tx).await.map_err(db)?;
    if let Some(row) = &stored {
        verify_session_identity(row, principal)?;
        if let Some(old)=sqlx::query("SELECT digest,response FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 AND message_id=$4")
            .bind(&tenant).bind(&registration).bind(&session).bind(message_id).fetch_optional(&mut **tx).await.map_err(db)? {
            if old.try_get::<String,_>("digest").map_err(db)?!=digest { return Err(Error::Conflict); }
            audit.operation(Uuid::from_bytes(Sha256::digest(format!("{registration}:{session}:{message_id}")).as_slice()[..16].try_into().expect("digest width")),"windows_management");
            return old.try_get("response").map(SessionDecision::Replay).map_err(db);
        }
        if row.try_get::<String, _>("state").map_err(db)? != "challenge"
            || row.try_get::<i64, _>("last_message").map_err(db)? + 1 != message_id
            || message_id > 8
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
