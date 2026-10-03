//! Apple tasks share the command reducer, approval, outbox and operation authority.
use super::*;
use crate::device::DevicePrincipal;
use rss_mdm_apple_mdm::native::{
    evidence::{Phase, ReceiptState, Settlement},
    profiles::Verification,
};
use serde_json::{Value, json};

/// Freeze old and new object authority under the existing device/authorization locks.
pub async fn required(
    tx: &mut PgTransaction<'_>,
    key: &rss_mdm_native_protection::Protector,
    owner: Arc<dyn super::channels::AppleProfiles>,
    device: &str,
    input: &Create,
    declaration_owner: Option<String>,
) -> Result<Vec<crate::authorization::Permission>> {
    let mut required = input.task.permissions()?;
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let user = input.target.user_key().to_owned();
    let old = if let Some((identifier, _, _)) = input.profile_target() {
        let identifier = identifier.to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(owner
                    .previous_profiles(c, tenant, device, user, identifier)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?
    } else if matches!(
        input.task,
        Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
        }
    ) {
        let name = declaration_owner.ok_or(Error::Malformed)?;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(owner
                    .previous_declarations(c, tenant, device, user, name)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?
    } else {
        return Ok(required);
    };
    for old in old {
        let old = storage::load(tx, key, old).await?;
        required.extend(old.request.task.permissions()?);
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
        authorized_declarations: Vec::new(),
        owner: String::new(),
        assets: Vec::new(),
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
    let operation = op.id;
    let Task::Macos { request } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    if matches!(
        request,
        rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
    ) {
        let observation = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(apple_results
                        .declarations(c, tenant, operation, native_values)
                        .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        let mut value=observation.unwrap_or_else(||json!({"protocol":"mdm.apple","observationScope":"declarations","synchronization":"unpublished","nativeStatus":null,"effect":"unverified","compliance":"unknown"}));
        value["progress"] = json!(super::service::status(status));
        return Ok(value);
    }
    let request = request.clone();
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(apple_results
                    .observations(c, tenant, operation, request, native_values)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    let receipts = rows.iter().map(|r| {
        let mut receipt = json!({"phase":r.phase,"state":r.state,"receivedAt":r.received_at,"accepted":r.accepted,"outcome":r.native_outcome});
        if let Some(fields) = &r.fields { receipt["fields"] = json!(fields); }
        receipt
    }).collect::<Vec<_>>();
    if op.request.profile_target().is_none() {
        let mut value = json!({"protocol":"mdm.apple","observationScope":"native_command","receipts":receipts,"progress":super::service::status(status),"effect":"unverified"});
        if let Some(row) = rows
            .iter()
            .rev()
            .find(|r| r.accepted && r.native_outcome.is_some() && !r.phase.prerequisite())
        {
            value["result"] = json!(row.native_outcome);
            if let Some(fields) = &row.fields {
                value["fields"] = json!(fields);
            }
            if row.state == ReceiptState::Error
                && let Some(error) = &row.error
            {
                value["error"] = json!(error);
            }
        }
        return Ok(value);
    }
    let mut value = json!({"protocol":"mdm.apple","observationScope":"profile_presence","receipts":receipts,"result":"unknown","effect":"unknown","progress":"unknown"});
    if let Some(row) = rows
        .iter()
        .rev()
        .find(|r| r.phase == Phase::Execute && r.accepted)
    {
        value["progress"] = json!(match row.state {
            ReceiptState::Acknowledged => "succeeded",
            ReceiptState::Error => "failed",
            _ => "unknown",
        });
    }
    if let Some(row) = rows.iter().rev().find(|r| r.phase == Phase::Observe) {
        value["result"] = json!(match row.profile {
            Some(Verification::Matched) if status == dc::Status::Applied => "matched",
            Some(Verification::Mismatched | Verification::Failed) => "mismatched",
            _ => "unknown",
        });
        value["nativeStatus"] = json!(match row.state {
            ReceiptState::Acknowledged => Some("Acknowledged"),
            ReceiptState::Error => Some("Error"),
            ReceiptState::NotNow => Some("NotNow"),
            _ => None,
        });
        value["receivedAt"] = json!(row.received_at);
    }
    Ok(value)
}
impl ExecutionService {
    pub async fn apple_management(
        &self,
        apple: Arc<dyn super::channels::Apple>,
        p: &DevicePrincipal,
        exchange: Box<dyn super::channels::AppleExchange>,
        audit: &RequestAudit,
    ) -> std::result::Result<Vec<u8>, Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, &apple, p, Some(exchange), audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, apple, p, exchange, audit) = ctx;
                    let service = *service;
                    let p = *p;
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
                    let exchange = exchange.take().ok_or(Error::Conflict)?;
                    let user_key = exchange.user_key().to_owned();
                    let principal = p.clone();
                    let reception = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(async {
                                    exchange.current(c, &principal).await?;
                                    exchange.reception(c, &principal).await
                                }
                                .await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                    actions::native_collection::settle_device(service, tx, p.device()).await?;
                    match reception {
                        channels::AppleReception::Command(attempt) => {
                            receive(service, tx, p, attempt).await?
                        }
                        channels::AppleReception::Collection(facts) => {
                            for fact in &facts {
                                service.audit_store.append_in(tx, fact, false).await?;
                            }
                        }
                        channels::AppleReception::Idle | channels::AppleReception::Replay => {}
                    }
                    service
                        .reconcile_agent_install_in(tx, p.device(), audit)
                        .await?;
                    actions::native_collection::settle_device(service, tx, p.device()).await?;
                    let response = send(service, tx, (*apple).clone(), p, &user_key).await?;
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
async fn receive(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    attempt: Box<dyn super::channels::AppleAttempt>,
) -> Result<()> {
    let op = storage::load(
        tx,
        &service.protection,
        attempt.operation().ok_or(Error::Conflict)?,
    )
    .await?;
    let accepted = eligible(service, tx, p, &op).await?;
    let Task::Macos { request } = &op.request.task else {
        return Err(Error::Malformed.into());
    };
    let command = channels::AppleCommand {
        operation: op.id,
        authorized_declarations: Vec::new(),
        owner: op.approval.apple_owner(op.id)?,
        assets: Vec::new(),
        deadline: op.request.deadline,
        input_version: op.request.input_version.clone(),
        target: op.request.target.clone(),
        request: request.clone(),
    };
    let target = channels::AppleRegistration {
        tenant: service.tenant.to_string(),
        device: op.device.clone(),
        registration: op.registration,
        generation: op.registration_generation,
    };
    let fact = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(attempt.settle(c, accepted, command, target).await) })
        })
        .await?
        .map_err(Error::from)?;
    let event = match fact {
        Settlement::Waiting => return Ok(()),
        Settlement::Received => dc::DeviceEvent::Received,
        Settlement::Reported => dc::DeviceEvent::Reported(op.request.digest(
            &service.protection,
            service.tenant,
            &op.device,
        )?),
        Settlement::Rejected => dc::DeviceEvent::Rejected,
        Settlement::Profile => return Err(Error::Malformed.into()),
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
    let mut after = Uuid::nil();
    loop {
        let tenant = tx.tenant_id().to_string();
        let registration = p.registration().to_string();
        let generation = p.generation();
        let scope = user_key.to_owned();
        let cursor = after;
        let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>("SELECT o.id::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND o.dispatch_failure IS NULL AND o.input_context->>'platform'='macos' AND d.status IN ('published','received') AND o.id>$4 AND ($5='' OR (o.input_context->'target'->>'kind'='user' AND o.input_context->'target'->>'userId'=$5)) AND (o.input_context->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).bind(cursor).bind(scope).fetch_all(c).await
    })).await?;
        if ids.is_empty() {
            break;
        }
        for id in ids {
            after = stored(Uuid::parse_str(&id))?;
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
            match send_one(service, tx, apple.clone(), p, &op, prerequisites).await? {
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
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn super::channels::Apple>,
    p: &DevicePrincipal,
    op: &storage::Operation,
    prerequisites: bool,
) -> Result<channels::AppleDispatch> {
    let Task::Macos { request } = &op.request.task else {
        return Err(Error::Unsupported.into());
    };
    let authorized_declarations = if !prerequisites
        && matches!(
            request,
            rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
        ) {
        let profiles = service.apple_profiles.clone();
        let principal = p.clone();
        let user = op.request.target.user_key().to_owned();
        let ids = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(profiles.declaration_candidates(c, &principal, &user).await) },
                )
            })
            .await?
            .map_err(Error::from)?;
        authorized_declarations(service, tx, p, op.request.target.user_key(), ids).await?
    } else {
        Vec::new()
    };
    let assets = if prerequisites {
        Vec::new()
    } else {
        match super::apple_assets::resolve(service, tx, request, &op.request.target).await {
            Ok(assets) => assets,
            Err(crate::transaction::Fault::Request(
                Error::Malformed | Error::NotFound | Error::Conflict | Error::Unsupported,
            )) => {
                return Ok(channels::AppleDispatch::Rejected(
                    rss_mdm_apple_mdm::native::Error::Constraint,
                ));
            }
            Err(error) => return Err(error),
        }
    };
    let command = super::channels::AppleCommand {
        operation: op.id,
        authorized_declarations,
        owner: op.approval.apple_owner(op.id)?,
        assets,
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

async fn authorized_declarations(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    user: &str,
    ids: Vec<uuid::Uuid>,
) -> Result<Vec<uuid::Uuid>> {
    let now = storage::now(tx).await?;
    let mut authorized = Vec::new();
    for id in ids {
        let op = storage::load(tx, &service.protection, id).await?;
        let progress = service.required_command(tx, &op).await?.status();
        let live = progress == dc::Status::Applied
            || (!progress.is_terminal() && now < op.request.deadline);
        if live
            && op.registration == p.registration()
            && op.registration_generation == p.generation()
            && op.request.target.user_key() == user
            && storage::approval_valid(&service.source, &service.protection, tx, &op, now).await?
        {
            if let Task::Macos { request } = &op.request.task {
                match super::apple_assets::resolve(service, tx, request, &op.request.target).await {
                    Ok(_) => {}
                    Err(crate::transaction::Fault::Request(
                        Error::Malformed | Error::NotFound | Error::Conflict | Error::Unsupported,
                    )) => continue,
                    Err(error) => return Err(error),
                }
            }
            authorized.push(id);
        }
    }
    Ok(authorized)
}
impl ExecutionService {
    pub async fn apple_ddm(
        &self,
        p: &DevicePrincipal,
        exchange: Box<dyn channels::AppleDdmExchange>,
        audit: &RequestAudit,
    ) -> std::result::Result<channels::AppleDdmReply, Error> {
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, p, Some(exchange), audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, p, exchange, audit) = ctx;
                    let service = *service;
                    let p = *p;
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
                    let exchange = exchange.take().ok_or(Error::Conflict)?;
                    let principal = p.clone();
                    let (exchange, ids) = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(async {
                                    exchange.current(c, &principal).await?;
                                    let ids = exchange.candidates(c, &principal).await?;
                                    Ok::<_, channels::Rejection>((exchange, ids))
                                }
                                .await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                    let authorized =
                        authorized_declarations(service, tx, p, exchange.user_key(), ids).await?;
                    let principal = p.clone();
                    let reply = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(exchange.respond(c, &principal, authorized).await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                    for id in &reply.synchronized {
                        let op = storage::load(tx, &service.protection, *id).await?;
                        if eligible(service, tx, p, &op).await? {
                            complete_ddm(service, tx, &op).await?;
                        }
                    }
                    service
                        .audit_store
                        .append_request_in(tx, audit, reply.status, "success")
                        .await?;
                    Ok(reply)
                })
            },
        )
        .await
    }
}

async fn complete_ddm(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<()> {
    if service.required_command(tx, op).await?.status() == dc::Status::Published {
        let transition = service
            .store
            .report(
                tx,
                &dc::DeviceReport {
                    scope: op.scope,
                    command_id: op.command_id()?,
                    coordinate: op.coordinate,
                    event: dc::DeviceEvent::Received,
                },
            )
            .await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            return Err(Error::Conflict.into());
        }
    }
    let transition = service
        .store
        .report(
            tx,
            &dc::DeviceReport {
                scope: op.scope,
                command_id: op.command_id()?,
                coordinate: op.coordinate,
                event: dc::DeviceEvent::Reported(op.request.digest(
                    &service.protection,
                    service.tenant,
                    &op.device,
                )?),
            },
        )
        .await?;
    if transition.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    crate::wake::wake_native_in(service.source.clone(), tx, &op.device).await?;
    Ok(())
}
