use super::*;
use crate::device::DevicePrincipal;
use serde_json::{Value, json};
use sqlx::Row;
impl ExecutionService {
    pub async fn management(
        &self,
        windows: Arc<dyn super::channels::Windows>,
        principal: &DevicePrincipal,
        message: &rss_mdm_windows_mdm::syncml::Message,
        bytes: &[u8],
        audit: &RequestAudit,
    ) -> std::result::Result<Vec<u8>, Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, &windows, principal, message, bytes, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, w, p, m, b, a) = *ctx;
                    let tenant = s.tenant.to_string();
                    let instance = s.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    let tenant = s.tenant.to_string();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                                .bind(tenant)
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await?;
                    storage::lock(tx, p.device()).await?;
                    actions::native_collection::settle_device(s, tx, p.device()).await?;
                    let w = w.clone();
                    let protection = s.protection.clone();
                    let source = s.source.clone();
                    let principal = p.clone();
                    let message = m.clone();
                    let bytes = b.to_vec();
                    let audit = a.clone();
                    let (reply, package) = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(manage_on(
                                    c,
                                    w,
                                    (source.as_ref(), &protection),
                                    &principal,
                                    &message,
                                    &bytes,
                                    &audit,
                                )
                                .await)
                            })
                        })
                        .await??;
                    settle_dispatch_failures(s, tx, p, a).await?;
                    settle_reports(s, tx, p, m.header.session_id, package).await?;
                    actions::native_collection::settle_device(s, tx, p.device()).await?;
                    s.reconcile_agent_install_in(tx, p.device(), a).await?;
                    if !matches!(
                        a.snapshot().management_result,
                        Some(rss_mdm_audit_integration::ManagementResult::Replayed)
                    ) {
                        s.audit_store
                            .append_request_in(tx, a, 200, "success")
                            .await?;
                    }
                    let super::channels::Reply { bytes, facts } = reply;
                    for fact in &facts {
                        s.audit_store
                            .append_in(tx, fact, false)
                            .await
                            .map_err(Error::from)?;
                    }
                    Ok(bytes)
                })
            },
        )
        .await
    }
}
async fn manage_on(
    c: &mut sqlx::PgConnection,
    windows: Arc<dyn channels::Windows>,
    authority: (
        &dyn crate::source_authority::SourceAuthority,
        &rss_mdm_native_protection::Protector,
    ),
    p: &DevicePrincipal,
    raw: &rss_mdm_windows_mdm::syncml::Message,
    bytes: &[u8],
    audit: &RequestAudit,
) -> std::result::Result<(channels::Reply, channels::PackageState), Error> {
    let (source, key) = authority;
    use channels::{PackageState as P, WindowsReception};
    use rss_mdm_windows_mdm::syncml::{self as sm, Alert, Command};
    let (mut prepared, authenticated) = match windows
        .prepare(c, key, p, raw, bytes, audit)
        .await
        .map_err(Error::from)?
    {
        WindowsReception::Replay { reply, package } => {
            native::replay_on(source, c, key, p, raw).await?;
            return Ok((reply, package));
        }
        WindowsReception::Challenge(prepared) => (prepared, false),
        WindowsReception::Authenticated(prepared) => (prepared, true),
    };
    if authenticated
        && p.purpose() == crate::device::Purpose::WindowsDeclared
        && crate::device::linked::ready_in(c, p).await?
    {
        native::wake_configuration(c, p).await?;
    }
    for reference in &prepared.continuing {
        let eligible = match prepared
            .session
            .result_eligible(c, key, p, raw.header.session_id, reference)
            .await
            .map_err(Error::from)?
        {
            Some(value) => value,
            None => {
                native::result_eligible_on(source, c, key, p, raw.header.session_id, reference)
                    .await?
            }
        };
        if !eligible {
            prepared.package = P::Aborted;
            prepared.controls = vec![Command::Alert {
                id: 0,
                alert: Alert::SessionAbort,
            }];
            prepared
                .input
                .commands
                .retain(|c| !matches!(c, Command::Results(_)));
            prepared.input.final_message = false;
            break;
        }
    }
    let filtered = native::receive_on(
        source,
        c,
        key,
        p,
        &prepared.input,
        authenticated,
        prepared.history.as_ref(),
    )
    .await?;
    let outgoing = authenticated && native::outgoing_on(c, p, raw.header.session_id).await?;
    let dispatch = authenticated && prepared.package == P::Complete && !outgoing;
    let channel_pending = prepared
        .session
        .collect(
            source,
            c,
            key,
            p,
            &filtered,
            prepared.history.as_ref(),
            &mut prepared.response,
            dispatch,
        )
        .await
        .map_err(Error::from)?;
    let continuation = if outgoing && prepared.package != P::Aborted && prepared.controls.is_empty()
    {
        retain_received_acks(&mut prepared.response, &prepared.input, &prepared.controls);
        native::continue_on(source, c, key, p, &mut prepared.response, &prepared.limits).await?
    } else if outgoing && prepared.package != P::Aborted {
        native::Continuation::Waiting
    } else {
        native::Continuation::None
    };
    if matches!(continuation, native::Continuation::Abort) {
        prepared.package = P::Aborted;
        prepared.controls.push(Command::Alert {
            id: 0,
            alert: Alert::SessionAbort,
        });
    }
    let command_pending = native::send_on(
        source,
        c,
        key,
        p,
        &mut prepared.response,
        native::Dispatch {
            enabled: dispatch,
            user_available: prepared.user_available,
            provider_id: &prepared.provider_id,
            management_urls: &prepared.management_urls,
            limits: &prepared.limits,
            declared_summaries: &prepared.declared_summaries,
        },
    )
    .await?;
    let sent = matches!(continuation, native::Continuation::Sent);
    let waiting = matches!(continuation, native::Continuation::Waiting);
    if prepared.package != P::Complete && !sent {
        retain_received_acks(&mut prepared.response, &prepared.input, &prepared.controls);
        prepared.response.final_message = false;
    }
    if waiting {
        prepared.response.final_message = false;
    }
    if (prepared.package == P::Partial || waiting) && !sent {
        let alert = if raw.header.message_id as usize >= prepared.limits.session_messages {
            prepared.package = P::Aborted;
            Alert::SessionAbort
        } else {
            Alert::MoreMessages
        };
        prepared.controls.push(Command::Alert { id: 0, alert });
    }
    for mut control in prepared.controls {
        let id = prepared
            .response
            .commands
            .iter()
            .map(Command::id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Conflict)?;
        match &mut control {
            Command::Status(status) => status.id = id,
            Command::Alert { id: command, .. } => *command = id,
            _ => return Err(Error::Malformed),
        }
        prepared.response.commands.push(control);
    }
    sm::encode(&prepared.response, &prepared.limits)
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    let package = prepared.package;
    let reply = prepared
        .session
        .finish(
            c,
            key,
            p,
            prepared.response,
            package,
            channel_pending || command_pending || outgoing,
        )
        .await
        .map_err(Error::from)?;
    Ok((reply, package))
}

fn retain_received_acks(
    response: &mut rss_mdm_windows_mdm::syncml::Message,
    input: &rss_mdm_windows_mdm::syncml::Message,
    controls: &[rss_mdm_windows_mdm::syncml::Command],
) {
    use rss_mdm_windows_mdm::syncml::{Command, CommandName};
    response.commands.retain(|command| match command {
        Command::Status(status) => match status.command {
            CommandName::SyncHdr | CommandName::Alert => true,
            CommandName::Results => input.commands.iter().any(|command| matches!(command, Command::Results(r) if r.id == status.command_ref))
                && !controls.iter().any(|command| matches!(command, Command::Status(s) if s.command == CommandName::Results && s.command_ref == status.command_ref)),
            _ => false,
        },
        _ => false,
    });
}

pub(super) async fn settle_reports(
    s: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    session: u32,
    package: channels::PackageState,
) -> Result<()> {
    let tenant = s.tenant.to_string();
    let registration = p.registration();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT DISTINCT o.id FROM mdm_commands.operations o JOIN mdm_commands.attempts a ON(a.tenant_id,a.operation)=(o.tenant_id,o.id) JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND a.session=$4 AND i.receipt_accepted AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64").bind(tenant).bind(registration).bind(generation).bind(i64::from(session)).fetch_all(c).await})).await?;
    for id in ids {
        settle_one(s, tx, id, package).await?;
    }
    Ok(())
}
async fn settle_one(
    s: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    package: channels::PackageState,
) -> Result<()> {
    let op = storage::load(tx, &s.protection, id).await?;
    let command = s.required_command(tx, &op).await?;
    if command.status().is_terminal() {
        return Ok(());
    }
    let now = storage::now(tx).await?;
    if now >= op.request.deadline
        || !storage::approval_valid(&s.source, &s.protection, tx, &op, now).await?
    {
        return Ok(());
    }
    let tenant = s.tenant.to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.phase,i.kind,i.status,i.value,i.receipt_accepted,i.result_accepted FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.ordinal=(SELECT max(last.ordinal) FROM mdm_commands.attempts last WHERE last.tenant_id=a.tenant_id AND last.operation=a.operation AND last.phase=a.phase) ORDER BY i.command,i.item_ordinal").bind(tenant).bind(id).fetch_all(c).await})).await?;
    if rows.is_empty() {
        return Ok(());
    }
    let evidence = rows
        .into_iter()
        .map(|row| {
            Ok(rss_mdm_windows_mdm::native::receipt::ItemEvidence {
                phase: AttemptPhase::parse(&row.try_get::<String, _>("phase")?)?.receipt_role(),
                kind: rss_mdm_windows_mdm::native::receipt::CommandKind::parse(
                    &row.try_get::<String, _>("kind")?,
                )
                .map_err(|_| Error::Malformed)?,
                status: row.try_get("status")?,
                receipt_accepted: row.try_get::<Option<bool>, _>("receipt_accepted")? == Some(true),
                has_value: row.try_get::<Option<Vec<u8>>, _>("value")?.is_some(),
                result_accepted: row.try_get::<Option<bool>, _>("result_accepted")? == Some(true),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let decision = rss_mdm_windows_mdm::native::receipt::settle(
        &evidence,
        package == channels::PackageState::Complete,
    );
    let (event, query_complete, values_complete) = match decision {
        rss_mdm_windows_mdm::native::receipt::Settlement::Wait => return Ok(()),
        rss_mdm_windows_mdm::native::receipt::Settlement::Reject => {
            (dc::DeviceEvent::Rejected, false, false)
        }
        rss_mdm_windows_mdm::native::receipt::Settlement::Receive {
            query_complete,
            values_complete,
        } => (dc::DeviceEvent::Received, query_complete, values_complete),
    };
    let mut report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    let result = s.store.report(tx, &report).await?;
    if result.outcome == dc::Outcome::OutOfOrder {
        return Ok(());
    }
    if (query_complete
        || (values_complete
            && effect_assessment(&s.protection, tx, &op).await?.state
                == rss_mdm_windows_mdm::native::verification::EffectState::Verified))
        && !result.command.status().is_terminal()
    {
        report.event =
            dc::DeviceEvent::Reported(op.request.digest(&s.protection, s.tenant, &op.device)?);
        if s.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    crate::wake::wake_native_in(s.source.clone(), tx, &op.device).await?;
    Ok(())
}
pub async fn observation(
    tx: &mut PgTransaction<'_>,
    protection: &rss_mdm_native_protection::Protector,
    apple_results: Arc<dyn channels::AppleResults>,
    op: &storage::Operation,
    command_status: dc::Status,
    native_values: bool,
) -> Result<crate::queries::records::NativeObservation> {
    if matches!(op.request.task, Task::Macos { .. }) {
        return super::apple::observation(tx, apple_results, op, command_status, native_values)
            .await;
    }
    let tenant = tx.tenant_id();
    let id = op.id;
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT a.id AS attempt,a.phase,a.ordinal,a.session,a.message,i.command,i.parent_command,i.item_ordinal,i.kind,i.uri,i.status,i.value,i.receipt_accepted,i.received_at,i.result_accepted,i.result_received_at,coalesce((SELECT jsonb_agg(jsonb_build_object('message',f.message,'command',f.command,'startByte',f.start_byte,'endByte',f.end_byte,'totalBytes',f.total_bytes,'status',f.status,'accepted',f.accepted,'receivedAt',f.received_at) ORDER BY f.message,f.command) FROM mdm_commands.attempt_frames f WHERE f.tenant_id=a.tenant_id AND f.attempt=a.id AND f.command=i.command),'[]'::jsonb) AS frames FROM mdm_commands.attempts a JOIN mdm_commands.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 ORDER BY a.ordinal,i.command,i.item_ordinal").bind(tenant.to_string()).bind(id).fetch_all(c).await})).await?;
    let sensitive = op.request.task.permissions()?.iter().any(|p| {
        matches!(
            p,
            crate::authorization::Permission::SecurityOperate
                | crate::authorization::Permission::Credentials
                | crate::authorization::Permission::AccountWrite
        )
    });
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if sensitive {
            None
        } else {
            result_value(protection, tenant, op, &row)?
        };
        use crate::queries::records::WindowsReceipt;
        let receipt = WindowsReceipt {
            phase: crate::AttemptPhase::parse(&row.try_get::<String, _>("phase")?)?,
            ordinal: row.try_get("ordinal")?,
            session: row.try_get("session")?,
            message: row.try_get("message")?,
            command: row.try_get("command")?,
            parent_command: row.try_get("parent_command")?,
            item: row.try_get("item_ordinal")?,
            kind: row.try_get("kind")?,
            uri: row.try_get("uri")?,
            status: row.try_get("status")?,
            value,
            accepted: row.try_get("receipt_accepted")?,
            received_at: row.try_get("received_at")?,
            result_accepted: row.try_get("result_accepted")?,
            result_received_at: row.try_get("result_received_at")?,
            frames: stored(serde_json::from_value(row.try_get::<Value, _>("frames")?))?,
            redacted: sensitive,
        };
        receipts.push(receipt);
    }
    let assessment = effect_assessment(protection, tx, op).await?;
    Ok(crate::queries::records::NativeObservation::Windows {
        receipts,
        progress: super::service::status(command_status).into(),
        effect: assessment.state,
        reason: assessment.reason,
    })
}
fn result_value(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    op: &storage::Operation,
    row: &sqlx::postgres::PgRow,
) -> Result<Option<String>> {
    let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("value")? else {
        return Ok(None);
    };
    let aad = super::native::result_aad(
        tenant,
        op.registration,
        op.registration_generation,
        row.try_get("attempt")?,
        row.try_get("command")?,
        row.try_get("item_ordinal")?,
    )?;
    let plain = protection
        .open_bytes(&sealed, &aad)
        .map_err(|_| Error::Unavailable(Failure::NativeProtection))?;
    Ok(Some(
        String::from_utf8(plain.expose().to_vec()).map_err(|_| Error::Malformed)?,
    ))
}

async fn effect_assessment(
    protection: &rss_mdm_native_protection::Protector,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<rss_mdm_windows_mdm::native::verification::EffectAssessment> {
    use rss_mdm_windows_mdm::native::{
        Context, Execution,
        verification::{EffectAssessment, EffectFact, EffectState},
    };
    let Task::Windows {
        request: Execution::SyncMl { request },
    } = &op.request.task
    else {
        return Ok(EffectAssessment {
            state: EffectState::Unverifiable,
            reason: Some("software_requires_installation_evidence"),
        });
    };
    let tenant = tx.tenant_id().to_string();
    let id = op.id;
    let state=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<Value>>("SELECT platform FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' ORDER BY ordinal DESC LIMIT 1").bind(tenant).bind(id).fetch_optional(c).await})).await?.flatten();
    let Some(state) = state else {
        return Ok(EffectAssessment::waiting("missing_target_evidence"));
    };
    let context: Context = stored(serde_json::from_value(state))?;
    let plan = request
        .effect_plan(context)
        .map_err(|_| Error::Unsupported)?;
    if plan.readback().is_none() {
        return Ok(plan.assess(&[]));
    }
    let rows = completed_observation(tx, id).await?;
    let addresses = request
        .management_addresses()
        .map_err(|_| Error::Malformed)?;
    if !addresses.is_empty() {
        let tenant = tx.tenant_id().to_string();
        let registration = op.registration;
        let generation = op.registration_generation;
        let endpoint = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT m.response,a.credential,a.session,a.message FROM mdm_commands.attempts a JOIN mdm_access.management_messages m ON(m.tenant_id,m.registration,m.session_id,m.message_id)=(a.tenant_id,$3,a.session::text,a.message) JOIN mdm_access.management_sessions s ON(s.tenant_id,s.registration,s.session_id)=(m.tenant_id,m.registration,m.session_id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.phase='observe' AND s.generation=$4 AND a.session<>(SELECT session FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' ORDER BY ordinal DESC LIMIT 1) ORDER BY a.ordinal DESC LIMIT 1")
                .bind(tenant).bind(id).bind(registration).bind(generation).fetch_optional(c).await
        })).await?;
        let Some(endpoint) = endpoint else {
            return Ok(EffectAssessment::waiting(
                "management_address_reconnect_required",
            ));
        };
        let session = endpoint.try_get::<i64, _>("session")?.to_string();
        let credential: Uuid = endpoint.try_get("credential")?;
        let message: i64 = endpoint.try_get("message")?;
        let plain = protection
            .open_bytes(
                &endpoint.try_get::<Vec<u8>, _>("response")?,
                &crate::protection::aad(
                    tx.tenant_id(),
                    "windows.management.response",
                    &(registration, generation, credential, &session, message),
                )?,
            )
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let reply = rss_mdm_windows_mdm::syncml::decode(
            plain.expose(),
            &rss_mdm_windows_mdm::CodecLimits::default(),
        )
        .map_err(|_| Error::Malformed)?;
        if !addresses.contains(&reply.header.source) {
            return Ok(EffectAssessment::waiting(
                "management_address_reconnect_required",
            ));
        }
    }
    let mut facts = Vec::new();
    for row in rows {
        facts.push(EffectFact {
            uri: row.try_get::<Option<String>, _>("uri")?.unwrap_or_default(),
            status: row.try_get("status")?,
            value: result_value(protection, tx.tenant_id(), op, &row)?,
            receipt_accepted: row.try_get::<Option<bool>, _>("receipt_accepted")? == Some(true),
            result_accepted: row.try_get::<Option<bool>, _>("result_accepted")? == Some(true),
        });
    }
    Ok(plan.assess(&facts))
}

/// A server-side native validation failure cancels dispatch; it is never a device rejection.
pub(super) async fn settle_dispatch_failures(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    audit: &RequestAudit,
) -> Result<()> {
    use rss_mdm_audit_integration::Fact;
    let tenant = tx.tenant_id().to_string();
    let registration = principal.registration();
    let generation = principal.generation();
    let ids = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_, Uuid>("SELECT o.id FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2 AND o.registration_generation=$3 AND o.dispatch_failure IS NOT NULL AND d.terminal_at IS NULL ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.protection, id).await?;
        let transition = service
            .store
            .cancel(tx, op.scope, &op.command_id()?, op.coordinate)
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
        let evidence = stored(serde_json::to_vec(&op.dispatch_failure))?;
        let fact = Fact::business(
            audit,
            &format!("native-dispatch-failure:{id}"),
            &evidence,
            200,
            "failed",
            None,
        )?
        .with_details(json!({"operation":id,"failure":op.dispatch_failure}))?;
        service.audit_store.append_in(tx, &fact, false).await?;
        crate::wake::wake_native_in(service.source.clone(), tx, &op.device).await?;
    }
    Ok(())
}

/// Storage selects identity/order; the Windows owner decides native completeness.
async fn completed_observation(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Vec<sqlx::postgres::PgRow>> {
    use rss_mdm_windows_mdm::native::receipt::{ItemEvidence, ReceiptRole};
    let mut before = i64::MAX;
    loop {
        let tenant = tx.tenant_id().to_string();
        let candidates = tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT id,ordinal FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='observe' AND ordinal<$3 ORDER BY ordinal DESC LIMIT 64")
                .bind(tenant).bind(id).bind(before).fetch_all(c).await
        })).await?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        for candidate in candidates {
            before = candidate.try_get("ordinal")?;
            let attempt: Uuid = candidate.try_get("id")?;
            let tenant = tx.tenant_id().to_string();
            let rows = tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("SELECT a.id AS attempt,i.command,i.item_ordinal,i.kind,i.uri,i.status,i.value,i.value IS NOT NULL AS has_value,i.receipt_accepted,i.result_accepted FROM mdm_commands.attempt_items i JOIN mdm_commands.attempts a ON(a.tenant_id,a.id)=(i.tenant_id,i.attempt) WHERE a.tenant_id=$1::uuid AND a.id=$2 ORDER BY i.command,i.item_ordinal")
                    .bind(tenant).bind(attempt).fetch_all(c).await
            })).await?;
            let evidence = rows
                .iter()
                .map(|r| native::item_evidence(r, ReceiptRole::Observe))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if !evidence.is_empty() && evidence.iter().all(ItemEvidence::complete) {
                return Ok(rows);
            }
        }
    }
}
