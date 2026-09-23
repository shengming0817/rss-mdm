//! Apple tasks share the command reducer, approval, outbox and operation authority.
use super::*;
use crate::apple::{profile, protocol as wire};
use crate::device::DevicePrincipal;
use serde_json::{Value, json};
use sqlx::Row;

pub(super) async fn own(
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
        let old=sqlx::query("SELECT p.profile::text,p.registration::text,d.terminal_at IS NOT NULL AS terminal FROM mdm_apple.profiles p JOIN rss_device_command.commands d ON d.tenant_id=p.tenant_id AND d.command_id=p.operation::text WHERE p.tenant_id=$1::uuid AND p.device=$2 FOR UPDATE OF p")
            .bind(&tenant).bind(&device).fetch_optional(&mut *c).await?;
        if old.as_ref().is_some_and(|r|r.try_get::<bool,_>("terminal").ok()!=Some(true)) {return Ok(Err(Error::Conflict))}
        if !present && !old.as_ref().is_some_and(|r|r.try_get::<String,_>("profile").ok()==Some(profile.to_string()) && r.try_get::<String,_>("registration").ok()==Some(registration.to_string())) {return Ok(Err(Error::Conflict))}
        sqlx::query("INSERT INTO mdm_apple.profiles(tenant_id,device,identifier,profile,operation,registration,version,enabled) VALUES($1::uuid,$2,$3,$4::uuid,$5::uuid,$6::uuid,1,$7) ON CONFLICT(tenant_id,device) DO UPDATE SET profile=excluded.profile,operation=excluded.operation,registration=excluded.registration,version=mdm_apple.profiles.version+1,enabled=excluded.enabled")
            .bind(&tenant).bind(&device).bind(identifier).bind(profile.to_string()).bind(operation.to_string()).bind(registration.to_string()).bind(enabled).execute(c).await?;
        Ok(Ok(()))
    })).await?;
    result?;
    Ok(())
}
pub(super) async fn observation(
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
    status: dc::Status,
) -> Result<Value> {
    let tenant = tx.tenant_id().to_string();
    let id = op.id.to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT id::text,phase,state,response,received_at FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY phase").bind(tenant).bind(id).fetch_all(c).await})).await?;
    let mut value = json!({"protocol":"mdm.apple","observationScope":"profile_presence","result":"unknown","effect":"unknown","progress":"unknown"});
    for row in rows {
        let phase: String = row.try_get("phase")?;
        let state: String = row.try_get("state")?;
        if phase == "execute" {
            value["progress"] = json!(match state.as_str() {
                "acknowledged" => "succeeded",
                "error" => "failed",
                _ => "unknown",
            });
        } else if phase == "observe" {
            let response: Option<Vec<u8>> = row.try_get("response")?;
            if let Some(response) = response {
                let d = wire::decode(&response)?;
                let (profile, present) = op.request.profile_target().ok_or(Error::Conflict)?;
                let presence = profile::presence(
                    &d,
                    &profile::identifier(&tenant_name(op), &op.device),
                    profile,
                );
                value["result"] = json!(match presence {
                    Ok(p) if p == present && status == dc::Status::Applied => "matched",
                    Ok(p) if p != present => "mismatched",
                    Err(Error::Conflict) => "mismatched",
                    _ => "unknown",
                });
                value["nativeStatus"] = json!(wire::text(&d, "Status").ok());
                value["receivedAt"] = json!(row.try_get::<Option<i64>, _>("received_at")?);
            }
        }
    }
    Ok(value)
}
fn tenant_name(op: &storage::Operation) -> String {
    op.scope.tenant().to_string()
}

impl Commands {
    pub(crate) async fn apple_management(
        &self,
        apple: &crate::apple::Apple,
        p: &DevicePrincipal,
        bytes: &[u8],
        audit: &Audit,
    ) -> std::result::Result<Vec<u8>, Error> {
        let dictionary = wire::decode(bytes)?;
        let message = wire::management(&dictionary)?;
        self.transact(
            (self, apple, p, bytes, &dictionary, &message, audit),
            audit,
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
                    storage::lock(tx, p.device()).await?;
                    current(tx, p, message.udid).await?;
                    if let Some(id) = message.command {
                        receive(service, tx, p, id, message.status, dictionary, bytes).await?;
                    }
                    let response = send(service, tx, apple, p).await?;
                    storage::audit(tx, audit, 200).await?;
                    Ok(response)
                })
            },
        )
        .await
    }
}
async fn current(tx: &mut PgTransaction<'_>, p: &DevicePrincipal, udid: &str) -> Result<()> {
    let principal = p.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::device::store::lock_channel(
                c,
                &principal.tenant().to_string(),
                principal.device(),
                principal.channel(),
            )
            .await)
        })
    })
    .await??;
    let p = p.clone();
    let udid = udid.to_owned();
    let valid=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,bool>("SELECT true FROM mdm_access.registrations r JOIN mdm_access.credentials k ON (k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN mdm_apple.devices a ON (a.tenant_id,a.registration)=(r.tenant_id,r.id) JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.generation=$3 AND r.state='active' AND k.id=$4::uuid AND k.state='active' AND a.state='active' AND a.udid=$5 AND s.source='mdm.apple' AND s.enabled FOR UPDATE OF a")
            .bind(p.tenant().to_string()).bind(p.registration().to_string()).bind(p.generation()).bind(p.credential().to_string()).bind(udid).fetch_optional(c).await
    })).await?.unwrap_or(false);
    if !valid {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}
async fn eligible(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    op: &storage::Operation,
) -> Result<bool> {
    if op.registration != p.registration()
        || op.registration_generation != p.generation()
        || op.request.profile_target().is_none()
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
async fn receive(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    id: Uuid,
    status: wire::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<()> {
    let principal = p.clone();
    let dictionary = d.clone();
    let response = bytes.to_vec();
    let collected = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(crate::collection::apple::receive(
                    c,
                    &principal,
                    id,
                    status,
                    &dictionary,
                    &response,
                )
                .await)
            })
        })
        .await??;
    if collected {
        return Ok(());
    }
    use crate::apple::attempt::{self, Owner, Reception};
    let principal = p.clone();
    let response = bytes.to_vec();
    let attempt = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(attempt::lock(c, &principal, id, Owner::Command, &response).await)
            })
        })
        .await??
        .ok_or(Error::Conflict)?;
    let attempt = match attempt {
        Reception::Replay => return Ok(()),
        Reception::Ready(attempt) => attempt,
    };
    let op = storage::load(tx, attempt.operation.ok_or(Error::Conflict)?).await?;
    if !eligible(service, tx, p, &op).await? {
        return Err(Error::Forbidden.into());
    }
    let phase = attempt.phase.clone();
    tx.with_connection(move |c| Box::pin(async move { Ok(attempt.settle(c, status).await) }))
        .await??;
    let event = match (phase.as_str(), status) {
        (_, wire::Status::NotNow) => return Ok(()),
        (_, wire::Status::Error) => dc::DeviceEvent::Rejected,
        ("execute", wire::Status::Acknowledged) => dc::DeviceEvent::Received,
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
    if service.store.report(tx, &report).await?.outcome == dc::Outcome::OutOfOrder {
        return Err(Error::Conflict.into());
    }
    Ok(())
}
async fn send(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    apple: &crate::apple::Apple,
    p: &DevicePrincipal,
) -> Result<Vec<u8>> {
    let tenant = tx.tenant_id().to_string();
    let registration = p.registration().to_string();
    let generation = p.generation();
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>("SELECT o.id::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.registration_generation=$3 AND o.gateway_accepted AND o.request->'task'->>'kind' IN ('profile_install','profile_remove') AND d.status IN ('published','received') ORDER BY o.id LIMIT 64")
            .bind(tenant).bind(registration).bind(generation).fetch_all(c).await
    })).await?;
    for id in ids {
        let op = storage::load(tx, corrupt(Uuid::parse_str(&id))?).await?;
        if !eligible(service, tx, p, &op).await? {
            continue;
        }
        if let Some(bytes) = send_one(tx, apple, p, &op).await? {
            return Ok(bytes);
        }
    }
    let principal = p.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(crate::collection::apple::send(c, &principal).await) })
        })
        .await??)
}
async fn send_one(
    tx: &mut PgTransaction<'_>,
    apple: &crate::apple::Apple,
    p: &DevicePrincipal,
    op: &storage::Operation,
) -> Result<Option<Vec<u8>>> {
    let tenant = tx.tenant_id().to_string();
    let operation = op.id.to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT id::text,phase,state,request,next_attempt<=clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY phase FOR UPDATE")
            .bind(tenant).bind(operation).fetch_all(c).await
    })).await?;
    let phase = if rows.iter().any(|r| {
        r.try_get::<String, _>("phase").ok().as_deref() == Some("execute")
            && r.try_get::<String, _>("state").ok().as_deref() == Some("acknowledged")
    }) {
        "observe"
    } else {
        "execute"
    };
    if let Some(row) = rows
        .iter()
        .find(|r| r.try_get::<String, _>("phase").ok().as_deref() == Some(phase))
    {
        let state: String = row.try_get("state")?;
        if !matches!(state.as_str(), "pending" | "sent" | "not_now")
            || !row.try_get::<bool, _>("ready")?
        {
            return Ok(None);
        }
        let id = corrupt(Uuid::parse_str(&row.try_get::<String, _>("id")?))?;
        mark_sent(tx, id).await?;
        return Ok(Some(row.try_get("request")?));
    }
    let id = Uuid::new_v4();
    let now = storage::now(tx).await?;
    let payload = payload(apple, op, phase, now)?;
    let bytes = wire::command(id, payload)?;
    let request = bytes.clone();
    let tenant = tx.tenant_id().to_string();
    let registration = p.registration().to_string();
    let generation = p.generation();
    let operation = op.id.to_string();
    let deadline = op.request.deadline;
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,operation,phase,request,state,deadline,next_attempt) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,'sent',to_timestamp($8),clock_timestamp()+interval '30 seconds')")
            .bind(tenant).bind(id.to_string()).bind(registration).bind(generation).bind(operation).bind(phase).bind(request).bind(deadline as f64).execute(c).await?;Ok(())
    })).await?;
    Ok(Some(bytes))
}
fn payload(
    apple: &crate::apple::Apple,
    op: &storage::Operation,
    phase: &str,
    now: i64,
) -> std::result::Result<plist::Dictionary, Error> {
    if phase == "observe" {
        return Ok(wire::dictionary([("RequestType", "ProfileList".into())]));
    }
    let identifier = profile::identifier(&tenant_name(op), &op.device);
    match op.request.task {
        Task::ProfileInstall { enabled } => Ok(wire::dictionary([
            ("RequestType", "InstallProfile".into()),
            (
                "Payload",
                plist::Value::Data(apple.signed_firewall(&identifier, op.id, enabled, now)?),
            ),
        ])),
        Task::ProfileRemove { .. } => Ok(wire::dictionary([
            ("RequestType", "RemoveProfile".into()),
            ("Identifier", identifier.into()),
        ])),
        _ => Err(Error::Unsupported),
    }
}
async fn mark_sent(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}
