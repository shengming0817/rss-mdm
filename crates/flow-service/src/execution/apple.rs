//! Apple tasks share the command reducer, approval, outbox and operation authority.
use super::*;
use crate::device::DevicePrincipal;
use crate::planning::policies;
use rss_mdm_apple_mdm::{profile, protocol as wire};
use serde_json::{Value, json};
use sqlx::Row;

pub async fn own(
    tx: &mut PgTransaction<'_>,
    device: &str,
    registration: Uuid,
    input: &Create,
) -> Result<()> {
    let Some((profile, present)) = input.profile_target() else {
        return Ok(());
    };
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let operation = input.operation_id;
    let identifier = profile::identifier(&tenant, &device);
    let enabled = matches!(input.task, Task::ProfileInstall { enabled: true });
    let result=tx.with_connection(move|c|Box::pin(async move {
        let old=sqlx::query("SELECT p.profile::text,p.registration::text,d.terminal_at IS NOT NULL AS terminal FROM mdm_commands.apple_profiles p JOIN rss_device_command.commands d ON d.tenant_id=p.tenant_id AND d.command_id=p.operation::text WHERE p.tenant_id=$1::uuid AND p.device=$2 FOR UPDATE OF p")
            .bind(&tenant).bind(&device).fetch_optional(&mut *c).await?;
        if old.as_ref().is_some_and(|r|r.try_get::<bool,_>("terminal").ok()!=Some(true)) {return Ok(Err(Error::Conflict))}
        if !present && !old.as_ref().is_some_and(|r|r.try_get::<String,_>("profile").ok()==Some(profile.to_string()) && r.try_get::<String,_>("registration").ok()==Some(registration.to_string())) {return Ok(Err(Error::Conflict))}
        sqlx::query("INSERT INTO mdm_commands.apple_profiles(tenant_id,device,identifier,profile,operation,registration,version,enabled) VALUES($1::uuid,$2,$3,$4::uuid,$5::uuid,$6::uuid,1,$7) ON CONFLICT(tenant_id,device) DO UPDATE SET profile=excluded.profile,operation=excluded.operation,registration=excluded.registration,version=mdm_commands.apple_profiles.version+1,enabled=excluded.enabled")
            .bind(&tenant).bind(&device).bind(identifier).bind(profile.to_string()).bind(operation.to_string()).bind(registration.to_string()).bind(enabled).execute(c).await?;
        Ok(Ok(()))
    })).await?;
    result?;
    Ok(())
}
pub async fn observation(
    tx: &mut PgTransaction<'_>,
    apple_store: Arc<dyn super::channels::AppleStore>,
    op: &storage::Operation,
    status: dc::Status,
) -> Result<Value> {
    let tenant = tx.tenant_id().to_string();
    let _id = op.id.to_string();
    let operation = op.id;
    let rows = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(apple_store.observations(c, tenant, operation).await) })
        })
        .await?
        .map_err(Error::from)?;
    let mut value = json!({"protocol":"mdm.apple","observationScope":"profile_presence","result":"unknown","effect":"unknown","progress":"unknown"});
    for row in rows {
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
                let (profile, present) = op.request.profile_target().ok_or(Error::Conflict)?;
                let presence = profile::presence(
                    &d,
                    &profile::identifier(&tenant_name(op), &op.device),
                    profile,
                );
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
fn tenant_name(op: &storage::Operation) -> String {
    op.scope.tenant().to_string()
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
                    tx.with_connection(move |c| {
                        Box::pin(async move { Ok(participant.current(c, &principal, &udid).await) })
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
                    let response = send(service, tx, apple.clone(), p).await?;
                    service
                        .audit_store
                        .append_request_in(tx, audit, 200, "success")
                        .await?;
                    Ok(response)
                })
            },
            crate::transaction::TransactionOwner::Execution,
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
        || (op.request.profile_target().is_none()
            && !matches!(op.request.task, Task::AgentInstall { .. }))
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
        && storage::approval_valid(tx, op, now).await?)
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
    let op = storage::load(tx, attempt.operation().ok_or(Error::Conflict)?).await?;
    if !eligible(service, tx, p, &op).await? {
        return Err(Error::Forbidden.into());
    }
    let phase = attempt.phase().to_owned();
    tx.with_connection(move |c| Box::pin(async move { Ok(attempt.settle(c, status).await) }))
        .await?
        .map_err(Error::from)?;
    let event = match (phase.as_str(), status) {
        (_, wire::Status::NotNow) => return Ok(()),
        ("observe", wire::Status::Error)
            if matches!(op.request.task, Task::AgentInstall { .. }) =>
        {
            return Ok(());
        }
        (_, wire::Status::Error) => dc::DeviceEvent::Rejected,
        ("execute", wire::Status::Acknowledged) => dc::DeviceEvent::Received,
        ("observe", wire::Status::Acknowledged)
            if matches!(op.request.task, Task::AgentInstall { .. }) =>
        {
            // InstalledApplicationList cannot verify the pinned team or package receipt.
            return Ok(());
        }
        ("observe", wire::Status::Acknowledged) => {
            let (profile, present) = op.request.profile_target().ok_or(Error::Conflict)?;
            let identifier = profile::identifier(&service.tenant.to_string(), &op.device);
            if profile::presence(d, &identifier, profile).ok() != Some(present) {
                return Ok(());
            }
            dc::DeviceEvent::Reported(op.request.digest(&service.tenant.to_string(), &op.device)?)
        }
        _ => return Err(Error::Conflict.into()),
    };
    let report = dc::DeviceReport {
        scope: op.scope,
        command_id: op.command_id()?,
        coordinate: op.coordinate,
        event,
    };
    let transition = service.store.report(tx, &report).await?;
    if transition.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    if transition.command.status().is_terminal() {
        crate::planning::policies::reconcile::wake_native_in(tx, &op.device).await?;
    }
    Ok(())
}
async fn send(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    apple: Arc<dyn super::channels::Apple>,
    p: &DevicePrincipal,
) -> Result<Vec<u8>> {
    let tenant = tx.tenant_id().to_string();
    let registration = p.registration().to_string();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>("SELECT o.id::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND o.request->'task'->>'kind' IN ('profile_install','profile_remove','agent_install') AND d.status IN ('published','received') ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, stored(Uuid::parse_str(&id))?).await?;
        if !eligible(service, tx, p, &op).await? {
            continue;
        }
        let approval = op.approval.clone();
        if !tx
            .with_connection(move |c| Box::pin(async move { Ok(approval.dispatch_ready(c).await) }))
            .await??
        {
            continue;
        }
        if let Some(bytes) = send_one(tx, apple.clone(), p, &op).await? {
            return Ok(bytes);
        }
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
) -> Result<Option<Vec<u8>>> {
    let command = super::channels::AppleCommand {
        operation: op.id,
        deadline: op.request.deadline,
        task: match &op.request.task {
            Task::AgentInstall { package } => {
                let policies::agent_install::Identity::Macos { bundle, .. } = &package.identity
                else {
                    return Err(Error::Unsupported.into());
                };
                super::channels::NativeTask::AgentInstall {
                    bundle: bundle.clone(),
                    version: package.version.clone(),
                    url: package.url(op.id),
                    sha256: package.artifact.sha256,
                }
            }
            Task::ProfileInstall { enabled } => {
                super::channels::NativeTask::Install { enabled: *enabled }
            }
            Task::ProfileRemove { .. } => super::channels::NativeTask::Remove,
            _ => return Err(Error::Unsupported.into()),
        },
    };
    let principal = p.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(apple.command(c, &principal, &command).await) })
        })
        .await?
        .map_err(Error::from)?)
}
