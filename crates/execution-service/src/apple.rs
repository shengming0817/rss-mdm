//! Apple tasks share the command reducer, approval, outbox and operation authority.
use super::*;
use crate::device::DevicePrincipal;
use rss_mdm_apple_mdm::{profile, protocol as wire};
use serde_json::{Value, json};

fn profile_observed(
    input: &Create,
    d: &plist::Dictionary,
    identifier: &str,
    uuid: Uuid,
) -> std::result::Result<bool, rss_mdm_apple_mdm::Error> {
    if let Task::Macos {
        request: rss_mdm_apple_mdm::native::request::Request::InstallProfile { profile },
    } = &input.task
    {
        profile.observed(d)
    } else {
        profile::presence(d, identifier, uuid)
    }
}

/// Freeze old and new object authority under the existing device/authorization locks.
pub async fn required(
    tx: &mut PgTransaction<'_>,
    key: &rss_mdm_native_protection::Protector,
    owner: Arc<dyn super::channels::AppleProfiles>,
    device: &str,
    input: &Create,
) -> Result<Vec<crate::authorization::Permission>> {
    let mut required = input.task.permissions()?;
    let Some((identifier, _, _)) = input.profile_target() else {
        return Ok(required);
    };
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let user = input.target.user_key().to_owned();
    let identifier = identifier.to_owned();
    let old = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(owner
                    .previous_profiles(c, tenant, device, user, identifier)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    for old in old {
        let old = storage::load(tx, key, old).await?;
        required.extend(old.request.task.permissions()?);
        required.extend_from_slice(old.approval.required());
    }
    required.sort();
    required.dedup();
    Ok(required)
}
pub async fn own(
    tx: &mut PgTransaction<'_>,
    owner: Arc<dyn super::channels::AppleProfiles>,
    device: &str,
    registration: Uuid,
    generation: i64,
    input: &Create,
) -> Result<()> {
    if input.profile_target().is_none() {
        return Ok(());
    }
    let Task::Macos { request } = &input.task else {
        return Err(Error::Malformed.into());
    };
    let target = super::channels::AppleRegistration {
        tenant: tx.tenant_id().to_string(),
        device: device.into(),
        registration,
        generation,
    };
    let command = super::channels::AppleCommand {
        operation: input.operation_id,
        deadline: input.deadline,
        input_version: input.input_version.clone(),
        target: input.target.clone(),
        request: request.clone(),
    };
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(owner.reserve_profile(c, target, command).await) })
    })
    .await?
    .map_err(Error::from)?;
    Ok(())
}
pub async fn observation(
    tx: &mut PgTransaction<'_>,
    apple_results: Arc<dyn super::channels::AppleResults>,
    op: &storage::Operation,
    status: dc::Status,
    native_values: bool,
) -> Result<Value> {
    let tenant = tx.tenant_id().to_string();
    let _id = op.id.to_string();
    let operation = op.id;
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(apple_results.observations(c, tenant, operation).await) })
        })
        .await?
        .map_err(Error::from)?;
    if op.request.profile_target().is_none() {
        let receipts = rows.iter().map(|r| json!({"phase":r.phase,"state":r.state,"receivedAt":r.received_at,"accepted":r.accepted,"outcome":r.native_outcome})).collect::<Vec<_>>();
        let mut value = json!({"protocol":"mdm.apple","observationScope":"native_command","receipts":receipts,"progress":super::service::status(status),"effect":"unverified"});
        if let Some(row) = rows.iter().rev().find(|row| {
            row.accepted && row.native_outcome.is_some() && !row.phase.starts_with("resolve_")
        }) {
            value["result"] = json!(row.native_outcome);
            if native_values
                && row.state == "error"
                && let Some(response) = &row.response
            {
                let body = wire::decode(response).map_err(Error::from)?;
                if let Some(error) = body.get("ErrorChain") {
                    let fields =
                        rss_mdm_apple_mdm::native::input::Fields::from_plist(&wire::dictionary([
                            ("ErrorChain", error.clone()),
                        ]))
                        .map_err(|_| Error::Malformed)?;
                    value["error"] = serde_json::to_value(fields).map_err(|_| Error::Malformed)?;
                }
            }

            if native_values
                && (row.phase == "execute"
                    && matches!(&op.request.task,Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Command{command}} if rss_mdm_apple_mdm::native::outcome::family(&command.request_type)==Ok(rss_mdm_apple_mdm::native::outcome::Family::Query)))
                && let Some(response) = &row.response
            {
                let mut result = wire::decode(response).map_err(Error::from)?;
                for key in [
                    "Status",
                    "CommandUUID",
                    "UDID",
                    "UserID",
                    "AuthToken",
                    "UserLongName",
                    "UserShortName",
                ] {
                    result.remove(key);
                }
                let fields = rss_mdm_apple_mdm::native::input::Fields::from_plist(&result)
                    .map_err(|_| Error::Malformed)?;
                value["fields"] = serde_json::to_value(fields).map_err(|_| Error::Malformed)?;
            }
        }
        return Ok(value);
    }
    let mut value = json!({"protocol":"mdm.apple","observationScope":"profile_presence","result":"unknown","effect":"unknown","progress":"unknown"});
    value["receipts"] = json!(rows.iter().map(|r|json!({"phase":r.phase,"state":r.state,"receivedAt":r.received_at,"accepted":r.accepted})).collect::<Vec<_>>());
    for row in rows {
        if !row.accepted {
            continue;
        }
        let phase = row.phase;
        let state = row.state;
        if phase == "execute" {
            value["progress"] = json!(match state.as_str() {
                "acknowledged" => "succeeded",
                "error" => "failed",
                _ => "unknown",
            });
        } else if phase == "observe" {
            let response = row.response;
            if let Some(response) = response {
                let d = wire::decode(&response).map_err(Error::from)?;
                let (identifier, profile, present) =
                    op.request.profile_target().ok_or(Error::Conflict)?;
                let presence = profile_observed(&op.request, &d, identifier, profile);
                value["result"] = json!(match presence {
                    Ok(p) if p == present && status == dc::Status::Applied => "matched",
                    Ok(p) if p != present => "mismatched",
                    Err(rss_mdm_apple_mdm::Error::Conflict) => "mismatched",
                    _ => "unknown",
                });
                value["nativeStatus"] = json!(wire::text(&d, "Status").ok());
                value["receivedAt"] = json!(row.received_at);
            }
        }
    }
    Ok(value)
}
impl ExecutionService {
    pub async fn apple_management(
        &self,
        apple: Arc<dyn super::channels::Apple>,
        p: &DevicePrincipal,
        bytes: &[u8],
        audit: &RequestAudit,
    ) -> std::result::Result<Vec<u8>, Error> {
        let dictionary = wire::decode(bytes)?;
        let message = wire::management(&dictionary)?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, &apple, p, bytes, &dictionary, &message, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, apple, p, bytes, dictionary, message, audit) = *ctx;
                    let tenant = service.tenant.to_string();
                    let instance = service.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    crate::transaction::lock(tx).await?;
                    storage::lock(tx, p.device()).await?;
                    let participant = apple.clone();
                    let principal = p.clone();
                    let udid = message.udid.to_owned();
                    let user_key = message.user.map(|id| id.to_string()).unwrap_or_default();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(participant.current(c, &principal, &udid, &user_key).await)
                        })
                    })
                    .await?
                    .map_err(Error::from)?;
                    actions::native_collection::settle_device(service, tx, p.device()).await?;
                    if let Some(id) = message.command {
                        receive(
                            service,
                            tx,
                            apple.clone(),
                            p,
                            id,
                            message.status,
                            dictionary,
                            bytes,
                        )
                        .await?;
                    }
                    service
                        .reconcile_agent_install_in(tx, p.device(), audit)
                        .await?;
                    actions::native_collection::settle_device(service, tx, p.device()).await?;
                    let user_key = message.user.map(|id| id.to_string()).unwrap_or_default();
                    let response = send(service, tx, apple.clone(), p, &user_key).await?;
                    super::protocol::settle_dispatch_failures(service, tx, p, audit).await?;
                    service
                        .audit_store
                        .append_request_in(tx, audit, 200, "success")
                        .await?;
                    Ok(response)
                })
            },
        )
        .await
    }
}
async fn eligible(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    op: &storage::Operation,
) -> Result<bool> {
    if op.registration != p.registration()
        || op.registration_generation != p.generation()
        || !matches!(op.request.task, Task::Macos { .. })
    {
        return Err(Error::Unauthorized.into());
    }
    let now = storage::now(tx).await?;
    let command = service.required_command(tx, op).await?;
    Ok(now < op.request.deadline
        && matches!(
            command.status(),
            dc::Status::Published | dc::Status::Received
        )
        && storage::approval_valid(&service.source, &service.protection, tx, op, now).await?)
}
#[allow(
    clippy::too_many_arguments,
    reason = "command receipt joins execution transaction, authenticated participant and correlated protocol evidence"
)]
async fn receive(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn super::channels::Apple>,
    p: &DevicePrincipal,
    id: Uuid,
    status: wire::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<()> {
    let participant = apple.clone();
    let principal = p.clone();
    let dictionary = d.clone();
    let response = bytes.to_vec();
    let (collected, facts) = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(participant
                    .collect(c, &principal, id, status, &dictionary, &response)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    for fact in &facts {
        service
            .audit_store
            .append_in(tx, fact, false)
            .await
            .map_err(Error::from)?;
    }
    if collected {
        return Ok(());
    }
    let principal = p.clone();
    let response = bytes.to_vec();
    let attempt = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(apple.lock_attempt(c, &principal, id, &response).await) })
        })
        .await?
        .map_err(Error::from)?
        .ok_or(Error::Conflict)?;
    let attempt = match attempt {
        super::channels::Reception::Replay => return Ok(()),
        super::channels::Reception::Ready(attempt) => attempt,
    };
    let op = storage::load(
        tx,
        &service.protection,
        attempt.operation().ok_or(Error::Conflict)?,
    )
    .await?;
    let user_key = wire::user(d)
        .map_err(Error::from)?
        .map(|id| id.to_string())
        .unwrap_or_default();
    let scope_matches = if attempt.phase().starts_with("resolve_") {
        user_key.is_empty()
    } else {
        user_key == op.request.target.user_key()
    };
    let accepted = eligible(service, tx, p, &op).await?
        && scope_matches
        && attempt.latest()
        && attempt.valid();
    let outcome = attempt.outcome();
    let phase = attempt.phase().to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(attempt.settle(c, status, accepted).await) })
    })
    .await?
    .map_err(Error::from)?;
    if !accepted {
        return Ok(());
    }
    if phase.starts_with("resolve_") && status != wire::Status::Error {
        return Ok(());
    }
    let software = match &op.request.task {
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Command { command },
        } => rss_mdm_apple_mdm::software::observation(command)
            .map_err(Error::from)?
            .is_some(),
        _ => false,
    };
    let query = matches!(&op.request.task,Task::Macos{request:rss_mdm_apple_mdm::native::request::Request::Command{command}} if rss_mdm_apple_mdm::native::outcome::family(&command.request_type)==Ok(rss_mdm_apple_mdm::native::outcome::Family::Query));
    let event = if query && phase == "execute" && status == wire::Status::Acknowledged {
        dc::DeviceEvent::Reported(op.request.digest(
            &service.protection,
            service.tenant,
            &op.device,
        )?)
    } else if outcome == Some(rss_mdm_apple_mdm::native::outcome::Outcome::Rejected)
        && op.request.profile_target().is_none()
    {
        dc::DeviceEvent::Rejected
    } else {
        match (phase.as_str(), status) {
            (_, wire::Status::NotNow) => return Ok(()),
            ("execute" | "observe", wire::Status::Error)
                if op.request.profile_target().is_some() =>
            {
                // Profile mutation errors preserve uncertain effects. The native owner may
                // query presence, but this receipt never authorizes another mutation.
                return Ok(());
            }
            ("observe", wire::Status::Error) if software => {
                return Ok(());
            }
            (_, wire::Status::Error) => dc::DeviceEvent::Rejected,
            ("execute", wire::Status::Acknowledged)
                if outcome.is_some_and(|value| value.completes_query()) =>
            {
                dc::DeviceEvent::Reported(op.request.digest(
                    &service.protection,
                    service.tenant,
                    &op.device,
                )?)
            }
            ("execute", wire::Status::Acknowledged) => dc::DeviceEvent::Received,
            ("observe", wire::Status::Acknowledged)
                if software || op.request.profile_target().is_none() =>
            {
                // Native bundle presence cannot verify a signing team or package receipt.
                return Ok(());
            }
            ("observe", wire::Status::Acknowledged) => {
                let (identifier, profile, present) =
                    op.request.profile_target().ok_or(Error::Conflict)?;
                if profile_observed(&op.request, d, identifier, profile).ok() != Some(present) {
                    return Ok(());
                }
                let owner = service.apple_profiles.clone();
                let target = super::channels::AppleRegistration {
                    tenant: service.tenant.to_string(),
                    device: op.device.clone(),
                    registration: op.registration,
                    generation: op.registration_generation,
                };
                let operation = op.id;
                tx.with_connection(move |c| {
                    Box::pin(async move { Ok(owner.confirm_profile(c, target, operation).await) })
                })
                .await?
                .map_err(Error::from)?;
                dc::DeviceEvent::Reported(op.request.digest(
                    &service.protection,
                    service.tenant,
                    &op.device,
                )?)
            }
            _ => return Err(Error::Conflict.into()),
        }
    };
    let report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    if matches!(report.event, dc::DeviceEvent::Reported(_))
        && service.required_command(tx, &op).await?.status() == dc::Status::Published
    {
        // A correlated recovery query establishes receipt of native evidence. The
        // failed mutation's own receipt stays unchanged and separately visible.
        let received = dc::DeviceReport {
            event: dc::DeviceEvent::Received,
            ..report.clone()
        };
        if service.store.report(tx, &received).await?.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    let transition = service.store.report(tx, &report).await?;
    if transition.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    if transition.command.status().is_terminal() {
        crate::wake::wake_native_in(service.source.clone(), tx, &op.device).await?;
    }
    Ok(())
}
async fn send(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn super::channels::Apple>,
    p: &DevicePrincipal,
    user_key: &str,
) -> Result<Vec<u8>> {
    let tenant = tx.tenant_id().to_string();
    let registration = p.registration().to_string();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>("SELECT o.id::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND o.dispatch_failure IS NULL AND o.input_context->>'platform'='macos' AND d.status IN ('published','received') ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, &service.protection, stored(Uuid::parse_str(&id))?).await?;
        if !eligible(service, tx, p, &op).await? {
            continue;
        }
        let approval = op.approval.clone();
        let source = service.source.clone();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(approval.dispatch_ready(source.as_ref(), c).await) })
            })
            .await??
        {
            continue;
        }
        let prerequisites = op.request.target.user_key() != user_key;
        if prerequisites && (!user_key.is_empty() || op.request.target.user_key().is_empty()) {
            continue;
        }
        match send_one(tx, apple.clone(), p, &op, prerequisites).await? {
            channels::AppleDispatch::Ready(bytes) => return Ok(bytes),
            channels::AppleDispatch::Waiting => {}
            channels::AppleDispatch::Rejected(error) => {
                let tenant = tx.tenant_id().to_string();
                let id = op.id;
                let failure = json!({"platform":"macos","reason":error.to_string()});
                tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query("UPDATE mdm_commands.operations SET dispatch_failure=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND dispatch_failure IS NULL")
                        .bind(tenant).bind(id).bind(failure).execute(c).await?;
                    Ok(())
                })).await?;
            }
        }
    }
    if !user_key.is_empty() {
        return Ok(Vec::new());
    }
    let principal = p.clone();
    let reply = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(apple.collection(c, &principal).await) })
        })
        .await?
        .map_err(Error::from)?;
    for fact in &reply.facts {
        service.audit_store.append_in(tx, fact, false).await?;
    }
    Ok(reply.bytes)
}
async fn send_one(
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn super::channels::Apple>,
    p: &DevicePrincipal,
    op: &storage::Operation,
    prerequisites: bool,
) -> Result<channels::AppleDispatch> {
    let Task::Macos { request } = &op.request.task else {
        return Err(Error::Unsupported.into());
    };
    let command = super::channels::AppleCommand {
        operation: op.id,
        deadline: op.request.deadline,
        input_version: op.request.input_version.clone(),
        target: op.request.target.clone(),
        request: request.clone(),
    };
    let principal = p.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(if prerequisites {
                    apple.prerequisites(c, &principal, &command).await
                } else {
                    apple.command(c, &principal, &command).await
                })
            })
        })
        .await?
        .map_err(Error::from)?)
}
