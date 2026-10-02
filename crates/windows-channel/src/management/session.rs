//! Request-local protocol participant; the execution use case owns all business ordering.
use super::*;
use rss_mdm_execution_service::channels::{PreparedWindows, WindowsReception, WindowsSession};

struct Session {
    windows: Arc<Windows>,
    scope: rss_observation::Scope,
    stored: Option<sqlx::postgres::PgRow>,
    raw: syncml::Message,
    bytes: Vec<u8>,
    digest: String,
    enrollment: Uuid,
    client_authenticated: bool,
    authenticated: bool,
    server: ServerAuthentication,
    audit: RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
    run_id: Option<Uuid>,
    collection_complete: bool,
}
impl rss_mdm_execution_service::channels::Windows for Windows {
    fn prepare<'a>(
        self: Arc<Self>,
        c: &'a mut sqlx::PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        raw: &'a syncml::Message,
        bytes: &'a [u8],
        audit: &'a RequestAudit,
    ) -> rss_mdm_execution_service::channels::Pending<'a, WindowsReception> {
        Box::pin(async move {
            prepare(self, c, key, p, raw, bytes, audit)
                .await
                .map_err(Into::into)
        })
    }
}
async fn prepare(
    windows: Arc<Windows>,
    c: &mut sqlx::PgConnection,
    key: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    raw: &syncml::Message,
    bytes: &[u8],
    audit: &RequestAudit,
) -> Result<WindowsReception, Error> {
    let tenant = p.tenant().to_string();
    let registration = p.registration().to_string();
    let binding = (
        p.registration(),
        p.generation(),
        p.credential(),
        raw.header.session_id.to_string(),
        i64::from(raw.header.message_id),
    );
    let digest = key
        .mac(
            bytes,
            &crate::protection::native_aad(p.tenant(), "windows.management.incoming", &binding)?,
        )
        .map_err(|_| Error::Unavailable(Failure::Protocol))?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let scope = crate::device::store::revalidate(c, p).await?;
    lock_sessions(c, &tenant, &registration).await?;
    let stored = match session_decision(c, key, p, raw, &digest, audit).await? {
        SessionDecision::Replay(reply, package) => {
            return Ok(WindowsReception::Replay { reply, package });
        }
        SessionDecision::Continue(stored) => stored,
    };
    let registration_data = crate::enrollment_store::registration(c, &tenant, &registration)
        .await
        .map_err(db)?;
    let enrollment = crate::enrollment::store::uuid(&registration_data, "request_id")?;
    let secrets = windows.protection.open(
        &tenant,
        enrollment,
        &registration_data
            .try_get::<Vec<u8>, _>("secrets")
            .map_err(db)?,
    )?;
    let before = stored
        .as_ref()
        .map(|r| r.try_get::<bool, _>("client_authenticated").map_err(db))
        .transpose()?
        .unwrap_or(false);
    let client_authenticated = authenticate_client(
        &registration,
        &secrets,
        raw.header.credential.as_ref(),
        before,
    )?;
    let nonce = stored
        .as_ref()
        .map(|r| r.try_get::<Vec<u8>, _>("nonce").map_err(db))
        .transpose()?
        .unwrap_or(registration_data.try_get("server_nonce").map_err(db)?);
    let mut history = crate::transcript::load(c, key, p, raw).await?;
    let server = authenticate_server(stored.as_ref(), history.expected.as_ref(), raw, nonce)?;
    let initial = initialization(raw, before)?;
    let authenticated = client_authenticated && server.authenticated;
    let response = management_response(
        &windows,
        p,
        raw,
        &secrets,
        client_authenticated,
        &server.nonce,
        initial,
    )?;
    let mut input = raw.clone();
    let mut controls = vec![];
    let mut continuing = history.assembly.pending().into_iter().collect::<Vec<_>>();
    let mut package = if raw.final_message {
        PackageState::Complete
    } else {
        PackageState::Partial
    };
    if authenticated {
        let expected = history.expected.as_ref().ok_or(Error::Conflict)?;
        for command in &raw.commands {
            if let Command::Results(result) = command {
                for item in result.items.iter().filter(|i| i.more_data) {
                    continuing.push(
                        expected
                            .get_reference(
                                result.message_ref.unwrap_or(1),
                                result.command_ref.unwrap_or(1),
                                item.source.as_deref().ok_or(Error::Malformed)?,
                            )
                            .map_err(|_| Error::Conflict)?,
                    );
                }
            }
        }
        match history
            .assembly
            .feed(raw, expected, &CodecLimits::default())
        {
            Ok(frame) => {
                input = frame.message;
                controls = frame.controls;
                if history.assembly.pending().is_some() {
                    package = PackageState::Partial;
                }
            }
            Err(crate::large_object::Fault::Invalid) => return Err(Error::Conflict),
            Err(fault) => {
                package = PackageState::Aborted;
                controls = interruption(raw, fault);
                input.commands.retain(|c| !matches!(c, Command::Results(_)));
                input.final_message = false;
            }
        }
        if raw.commands.iter().any(|c| {
            matches!(
                c,
                Command::Alert {
                    alert: syncml::Alert::SessionAbort,
                    ..
                }
            )
        }) {
            package = PackageState::Aborted;
        }
        input
            .commands
            .retain(|c| !matches!(c, Command::Alert { .. }));
        let _ = syncml::correlate(expected, &input, &CodecLimits::default())
            .map_err(|_| Error::Conflict)?;
    }
    let facts = if authenticated {
        crate::notifications::facts(key, p, raw, bytes, audit)?
    } else {
        vec![]
    };
    let prepared = PreparedWindows {
        input,
        history: history.expected,
        response,
        controls,
        continuing,
        limits: history.limits,
        package,
        session: Box::new(Session {
            windows,
            scope,
            stored,
            raw: raw.clone(),
            bytes: bytes.to_vec(),
            digest,
            enrollment,
            client_authenticated,
            authenticated,
            server,
            audit: audit.clone(),
            facts,
            run_id: None,
            collection_complete: false,
        }),
    };
    Ok(if authenticated {
        WindowsReception::Authenticated(prepared)
    } else {
        WindowsReception::Challenge(prepared)
    })
}
fn interruption(raw: &syncml::Message, fault: crate::large_object::Fault) -> Vec<Command> {
    let control = match fault {
        crate::large_object::Fault::Size(command) => Command::Status(Status {
            id: 0,
            message_ref: raw.header.message_id,
            command_ref: command,
            command: CommandName::Results,
            target_refs: vec![],
            source_refs: vec![],
            code: 424,
            items: vec![],
            challenge: None,
            credential: None,
        }),
        crate::large_object::Fault::Interrupted(reference) => Command::Alert {
            id: 0,
            alert: syncml::Alert::EndOfData {
                items: vec![syncml::Item {
                    more_data: false,
                    source: Some(reference.uri),
                    target: None,
                    meta: None,
                    data: None,
                }],
            },
        },
        crate::large_object::Fault::Invalid => return vec![],
    };
    vec![
        control,
        Command::Alert {
            id: 0,
            alert: syncml::Alert::SessionAbort,
        },
    ]
}
impl WindowsSession for Session {
    fn collect<'a>(
        &'a mut self,
        source: &'a dyn rss_mdm_execution_service::source_authority::SourceAuthority,
        c: &'a mut sqlx::PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        input: &'a syncml::Message,
        history: Option<&'a syncml::Expected>,
        response: &'a mut syncml::Message,
        dispatch: bool,
    ) -> rss_mdm_execution_service::channels::Pending<'a, bool> {
        Box::pin(async move {
            let result: Result<bool, Error> = async {
                let filtered = if self.authenticated {
                    let history = history.ok_or(Error::Conflict)?;
                    let input = crate::agent_collection::receive(
                        c,
                        key,
                        p,
                        input,
                        history,
                        &mut self.facts,
                    )
                    .await?;
                    crate::template_collection::receive(
                        source,
                        c,
                        key,
                        p,
                        &input,
                        history,
                        &mut self.facts,
                    )
                    .await?
                } else {
                    input.clone()
                };
                let (run_id, complete) = collect(
                    c,
                    (&mut self.facts, &self.audit),
                    &self.scope,
                    &filtered,
                    (key, self.stored.as_ref(), history),
                    response,
                    self.authenticated,
                    dispatch,
                )
                .await?;
                self.run_id = run_id;
                self.collection_complete = complete;
                let mut pending = false;
                if dispatch && self.authenticated {
                    pending |= crate::agent_collection::send(
                        c,
                        key,
                        p,
                        response,
                        self.windows.agent_identity.as_ref(),
                    )
                    .await?;
                    pending |= crate::template_collection::send(
                        source,
                        c,
                        key,
                        p,
                        response,
                        &mut self.facts,
                    )
                    .await?;
                }
                Ok(pending)
            }
            .await;
            result.map_err(Into::into)
        })
    }
    fn finish<'a>(
        self: Box<Self>,
        c: &'a mut sqlx::PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        response: syncml::Message,
        package: PackageState,
        pending: bool,
    ) -> rss_mdm_execution_service::channels::Pending<'a, Reply> {
        Box::pin(async move {
            save(*self, c, key, p, response, package, pending)
                .await
                .map_err(Into::into)
        })
    }
}
async fn save(
    session: Session,
    c: &mut sqlx::PgConnection,
    key: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    response: syncml::Message,
    package: PackageState,
    pending: bool,
) -> Result<Reply, Error> {
    let tenant = p.tenant().to_string();
    let registration = p.registration().to_string();
    let sid = session.raw.header.session_id.to_string();
    let mid = i64::from(session.raw.header.message_id);
    let binding = (p.registration(), p.generation(), p.credential(), &sid, mid);
    let bytes = syncml::encode(&response, &CodecLimits::default())
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    let seal = |bytes: &[u8], part: &str| -> Result<Vec<u8>, Error> {
        key.seal_bytes(
            bytes,
            &crate::protection::native_aad(p.tenant(), part, &binding)?,
        )
        .map_err(|_| Error::Unavailable(Failure::Protocol))
    };
    let reply = seal(&bytes, "windows.management.response")?;
    let incoming = seal(&session.bytes, "windows.management.incoming")?;
    let state = if package == PackageState::Aborted {
        "complete"
    } else if session.authenticated {
        if session.collection_complete && !pending && package == PackageState::Complete {
            "complete"
        } else {
            "collecting"
        }
    } else {
        "challenge"
    };
    if session.stored.is_none() {
        sqlx::query("INSERT INTO mdm_access.management_sessions(tenant_id,registration,session_id,generation,credential,state,last_message,client_authenticated,nonce,expires_at,run_id) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '15 minutes',$10)")
            .bind(&tenant).bind(&registration).bind(&sid).bind(p.generation()).bind(p.credential()).bind(state).bind(mid)
            .bind(session.client_authenticated).bind(&session.server.nonce).bind(session.run_id).execute(&mut *c).await.map_err(db)?;
        notify(c).await.map_err(db)?;
    } else {
        sqlx::query("UPDATE mdm_access.management_sessions SET state=$4,last_message=$5,client_authenticated=$6,nonce=$7,run_id=$8 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3")
            .bind(&tenant).bind(&registration).bind(&sid).bind(state).bind(mid).bind(session.client_authenticated)
            .bind(&session.server.nonce).bind(session.run_id).execute(&mut *c).await.map_err(db)?;
    }
    session
        .server
        .persist_nonce(c, &tenant, session.enrollment, &session.raw)
        .await?;
    let status = match package {
        PackageState::Partial => "partial",
        PackageState::Complete => "complete",
        PackageState::Aborted => "aborted",
    };
    sqlx::query("INSERT INTO mdm_access.management_messages(tenant_id,registration,session_id,message_id,digest,response,request,package_state) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)")
        .bind(&tenant).bind(&registration).bind(&sid).bind(mid).bind(session.digest).bind(reply).bind(incoming).bind(status)
        .execute(c).await.map_err(db)?;
    Ok(Reply {
        bytes,
        facts: session.facts,
    })
}
