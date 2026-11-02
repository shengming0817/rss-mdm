//! Owns the complete Windows transaction, exchange and persisted response.
use crate::participants::{Business, Pending};
use crate::protocol_types::{self as protocol, Windows as _};
use crate::{Error, Failure, Windows, native};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
pub struct Delivery {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit: Arc<AuditStore>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub business: Arc<dyn Business>,
}
impl Delivery {
    pub async fn management(
        &self,
        windows: Arc<Windows>,
        p: &DevicePrincipal,
        message: &rss_mdm_windows_mdm::syncml::Message,
        bytes: &[u8],
        audit: &RequestAudit,
        ingress: Arc<dyn protocol::ManagementIngress>,
    ) -> Result<protocol::ManagementReply, Error> {
        self.run(
            audit,
            (self, windows, p, message, bytes, audit, ingress),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, w, p, m, b, a, ingress) = ctx;
                    s.business.prepare(tx, p, a).await?;
                    let retirement = w.retirement_request(p.purpose())?;
                    let work = tx
                        .with_connection_context(
                            &mut (&**s, w.clone(), *p, *m, *b, *a, ingress.clone()),
                            |(s, w, p, m, b, a, ingress), c| {
                                Box::pin(async move {
                                    Ok(manage_on(
                                        c,
                                        w.clone(),
                                        (s.business.as_ref(), &s.protection),
                                        protocol::WindowsInput {
                                            principal: p,
                                            message: m,
                                            bytes: b,
                                        },
                                        a,
                                        ingress.as_ref(),
                                    )
                                    .await)
                                })
                            },
                        )
                        .await
                        .map_err(|_| Error::Unavailable(Failure::Database))??;
                    let ManagementWork::Ready(reply, package, authenticated, runs) = work else {
                        let ManagementWork::Limited(delay) = work else {
                            unreachable!()
                        };
                        return Ok(protocol::ManagementReply::Limited(delay));
                    };
                    s.business
                        .finish(
                            tx,
                            p,
                            m.header.session_id,
                            package == protocol::PackageState::Complete,
                            authenticated,
                            retirement,
                            runs,
                            a,
                        )
                        .await?;
                    if !matches!(
                        a.snapshot().management_result,
                        Some(rss_mdm_audit_integration::ManagementResult::Replayed)
                    ) {
                        a.require_final_request();
                    }
                    for fact in &reply.facts {
                        s.audit.append_in(tx, fact).await?;
                    }
                    Ok(protocol::ManagementReply::Response(reply.bytes))
                })
            },
        )
        .await
    }
    async fn run<C: Send, R: Send, F>(
        &self,
        audit: &RequestAudit,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> Pending<'a, R> + Send,
    {
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::from_secs(6),
                ),
                (context, Some(operation), &failure, &self.audit, audit),
                |(context, operation, failure, store, audit), tx| {
                    Box::pin(async move {
                        store
                            .bind_in(tx)
                            .await
                            .map_err(|e| rejection(e.into(), failure))?;
                        match operation.take().expect("one request")(context, tx).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => Err(rejection(e, failure)),
                        }
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| {
                audit.mark_rolled_back();
                Err(failure
                    .into_inner()
                    .expect("request rejection")
                    .unwrap_or(Error::Unavailable(Failure::Database)))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )
    }
}
fn rejection(e: Error, failure: &Mutex<Option<Error>>) -> PgError {
    *failure.lock().expect("request rejection") = Some(e);
    sqlx::Error::Protocol("Windows request rejected".into()).into()
}
enum ManagementWork {
    Ready(
        crate::protocol_types::Reply,
        crate::protocol_types::PackageState,
        bool,
        Vec<Uuid>,
    ),
    Limited(std::time::Duration),
}
async fn manage_on(
    c: &mut sqlx::PgConnection,
    windows: Arc<dyn crate::protocol_types::Windows>,
    authority: (
        &dyn crate::participants::Business,
        &rss_mdm_native_protection::Protector,
    ),
    input: crate::protocol_types::WindowsInput<'_>,
    audit: &RequestAudit,
    ingress: &dyn crate::protocol_types::ManagementIngress,
) -> std::result::Result<ManagementWork, Error> {
    let (source, key) = authority;
    let crate::protocol_types::WindowsInput {
        principal: p,
        message: raw,
        ..
    } = input;
    use crate::protocol_types::{PackageState as P, WindowsReception};
    use rss_mdm_windows_mdm::syncml::{self as sm, Alert, Command};
    let (mut prepared, authenticated) = match windows.prepare(c, key, input, audit, ingress).await?
    {
        WindowsReception::Limited(delay) => return Ok(ManagementWork::Limited(delay)),
        WindowsReception::Replay { reply, package } => {
            native::replay_on(source, c, key, p, raw).await?;
            return Ok(ManagementWork::Ready(reply, package, false, Vec::new()));
        }
        WindowsReception::Challenge(prepared) => (prepared, false),
        WindowsReception::Authenticated(prepared) => (prepared, true),
    };
    if authenticated
        && p.purpose() == crate::device::Purpose::WindowsDeclared
        && crate::device::linked::ready_in(rss_mdm_install_support::StorageProfile::Mdm, c, p)
            .await?
    {
        source.wake_configuration(c, p).await?;
    }
    for reference in &prepared.continuing {
        let eligible = match prepared
            .session
            .result_eligible(c, key, p, raw.header.session_id, reference)
            .await?
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
        authenticated.then_some(prepared.package),
        prepared.history.as_ref(),
    )
    .await?;
    let outgoing = authenticated && native::outgoing_on(c, p, raw.header.session_id).await?;
    let dispatch = authenticated
        && !prepared.stopped
        && prepared.package == P::Complete
        && !outgoing
        && prepared.controls.is_empty();
    let collections = prepared
        .session
        .receive(source, c, key, p, &filtered, prepared.history.as_ref())
        .await?;
    // Fail before recording any delivery when even the required envelope cannot fit.
    sm::encode_outbound(&prepared.response, &prepared.limits).map_err(|_| Error::Malformed)?;
    let collection_pending = if dispatch {
        prepared
            .session
            .send(source, c, key, p, &mut prepared.response)
            .await?
    } else {
        false
    };
    let continuation = if !prepared.stopped
        && outgoing
        && prepared.package != P::Aborted
        && prepared.controls.is_empty()
    {
        retain_received_acks(&mut prepared.response, &prepared.input, &prepared.controls);
        native::continue_on(source, c, p, &mut prepared.response, &prepared.limits).await?
    } else if !prepared.stopped && outgoing && prepared.package != P::Aborted {
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
    if !prepared.stopped && (prepared.package == P::Partial || waiting) && !sent {
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
    if prepared.stopped {
        prepared.response.final_message = true;
    }
    let response =
        sm::encode_outbound(&prepared.response, &prepared.limits).map_err(|_| Error::Malformed)?;
    let package = prepared.package;
    let reply = prepared
        .session
        .finish(
            c,
            key,
            p,
            response,
            package,
            collection_pending || collections.pending || command_pending || outgoing,
        )
        .await?;
    Ok(ManagementWork::Ready(
        reply,
        package,
        authenticated,
        collections.runs,
    ))
}

fn retain_received_acks(
    response: &mut rss_mdm_windows_mdm::syncml::Message,
    input: &rss_mdm_windows_mdm::syncml::Message,
    controls: &[rss_mdm_windows_mdm::syncml::Command],
) {
    use rss_mdm_windows_mdm::syncml::{Command, CommandName};
    response.commands.retain(|command| match command {
        Command::Status(status) => match status.command {
            // DevInfo Replace has already been received even if its package continues.
            CommandName::SyncHdr | CommandName::Alert | CommandName::Replace => true,
            CommandName::Results => input.commands.iter().any(|command| matches!(command, Command::Results(r) if r.id == status.command_ref))
                && !controls.iter().any(|command| matches!(command, Command::Status(s) if s.command == CommandName::Results && s.command_ref == status.command_ref)),
            _ => false,
        },
        _ => false,
    });
}
