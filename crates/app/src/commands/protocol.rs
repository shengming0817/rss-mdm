use super::*;
use crate::device::DevicePrincipal;
use serde_json::{Value, json};
use sqlx::Row;
impl Commands {
    pub(crate) async fn management(
        &self,
        windows: &Arc<crate::windows::Windows>,
        principal: &DevicePrincipal,
        message: &rss_mdm_windows_mdm::syncml::Message,
        bytes: &[u8],
        audit: &Audit,
    ) -> std::result::Result<Vec<u8>, Error> {
        self.transact((self,windows,principal,message,bytes,audit),audit,|ctx,tx|Box::pin(async move {
            let (service,windows,principal,message,bytes,audit) = *ctx;
            let tenant=service.tenant.to_string();let instance=service.instance.clone();
            tx.with_connection(move|c|Box::pin(async move {Ok(crate::authorization::lock_on(c,&tenant,&instance).await)})).await??;
            storage::lock(tx,principal.device()).await?;
            replay_permitted(service,tx,principal,message.header.session_id,message.header.message_id).await?;
            let native_windows=windows.clone();let native_principal=principal.clone();let native_message=message.clone();let native_bytes=bytes.to_vec();let native_audit=audit.clone();
            let response=tx.with_connection(move|c|Box::pin(async move {Ok(crate::windows::management::management_on(c,&native_windows,&native_principal,&native_message,&native_bytes,&native_audit).await)})).await??;
            let tenant=service.tenant.to_string();let registration=principal.registration().to_string();let session=message.header.session_id.to_string();
            let run=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<String>>("SELECT run_id::text FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3").bind(tenant).bind(registration).bind(session).fetch_optional(c).await})).await?.flatten();
            if let Some(run)=run {
                let run=corrupt(Uuid::parse_str(&run))?;
                // Only a newly produced response can introduce a task attempt.
                // A cached Inventory Get may predate this operation's acceptance.
                if !response.is_replay() {attach(service,tx,principal,run,message.header.message_id).await?;}
                receive(service,tx,principal,run).await?;
            }
            storage::audit(tx,audit,200).await?;
            Ok(response.into_bytes())
        })).await
    }
}
async fn linked(tx: &mut PgTransaction<'_>, run: Uuid) -> Result<Vec<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT operation::text FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND collection=$2::uuid").bind(tenant).bind(run.to_string()).fetch_all(c).await})).await?;
    ids.iter().map(|id| corrupt(Uuid::parse_str(id))).collect()
}
async fn replay_permitted(
    s: &Commands,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    session: u32,
    message: u32,
) -> Result<()> {
    let tenant = s.tenant.to_string();
    let registration = principal.registration().to_string();
    let ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT a.operation::text FROM mdm_commands.attempts a JOIN mdm_access.collection_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.collection) WHERE r.tenant_id=$1::uuid AND r.registration=$2::uuid AND r.session_id=$3 AND r.request_message=$4").bind(tenant).bind(registration).bind(session.to_string()).bind(i64::from(message)).fetch_all(c).await})).await?;
    let now = storage::now(tx).await?;
    for id in ids {
        let op = storage::load(tx, corrupt(Uuid::parse_str(&id))?).await?;
        let command = s.required_command(tx, &op).await?;
        if now >= op.request.deadline
            || !storage::approval_valid(tx, &op, now).await?
            || !matches!(
                command.status(),
                dc::Status::Published | dc::Status::Received
            )
        {
            return Err(Error::Forbidden.into());
        }
    }
    Ok(())
}
async fn attach(
    s: &Commands,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    run: Uuid,
    message: u32,
) -> Result<()> {
    let mut after = Uuid::nil();
    loop {
        let tenant = s.tenant.to_string();
        let name = principal.device().to_owned();
        let registration = principal.registration().to_string();
        let eligible=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT o.id::text FROM mdm_commands.operations o JOIN mdm_access.collection_runs r ON r.tenant_id=o.tenant_id AND r.id=$4::uuid WHERE o.tenant_id=$1::uuid AND o.id>$6::uuid AND o.device=$2 AND o.registration=$3::uuid AND o.gateway_accepted AND r.request_message=$5 AND r.sealed_at IS NULL AND NOT EXISTS(SELECT 1 FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.collection=r.id) AND NOT EXISTS(SELECT 1 FROM mdm_commands.attempts a JOIN mdm_access.collection_runs old ON (old.tenant_id,old.id)=(a.tenant_id,a.collection) WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND old.sealed_at IS NULL) ORDER BY o.id LIMIT 64").bind(tenant).bind(name).bind(registration).bind(run.to_string()).bind(i64::from(message)).bind(after.to_string()).fetch_all(c).await})).await?;
        if eligible.is_empty() {
            return Ok(());
        }
        for id in eligible {
            after = corrupt(Uuid::parse_str(&id))?;
            if attach_one(s, tx, principal, run, after).await? {
                return Ok(());
            }
        }
    }
}
async fn attach_one(
    s: &Commands,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    run: Uuid,
    id: Uuid,
) -> Result<bool> {
    let now = storage::now(tx).await?;
    let op = storage::load(tx, id).await?;
    if op.registration_generation != principal.generation()
        || now >= op.request.deadline
        || !storage::approval_valid(tx, &op, now).await?
    {
        return Ok(false);
    }
    let command = s.required_command(tx, &op).await?;
    if !matches!(
        command.status(),
        dc::Status::Published | dc::Status::Received
    ) {
        return Ok(false);
    }
    let tenant = s.tenant.to_string();
    let credential = principal.credential().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.attempts(tenant_id,operation,ordinal,id,collection,credential) SELECT $1::uuid,$2::uuid,coalesce(max(ordinal),0)+1,$3::uuid,$4::uuid,$5::uuid FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid").bind(tenant).bind(id.to_string()).bind(Uuid::new_v4().to_string()).bind(run.to_string()).bind(credential).execute(c).await?;Ok(())})).await?;
    Ok(true)
}

async fn receive(
    s: &Commands,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
    run: Uuid,
) -> Result<()> {
    let tenant = s.tenant.to_string();
    let data = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(crate::collection::load_run(c, &tenant, run).await) })
        })
        .await??;
    for id in linked(tx, run).await? {
        let op = storage::load(tx, id).await?;
        if op.registration != principal.registration()
            || op.registration_generation != principal.generation()
        {
            return Err(Error::Forbidden.into());
        }
        // Superseded attempts retain observations, but cannot update the command.
        let tenant = s.tenant.to_string();
        let latest=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT collection::text FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY ordinal DESC LIMIT 1").bind(tenant).bind(id.to_string()).fetch_one(c).await})).await?;
        if latest != run.to_string() {
            continue;
        }
        let command = s.required_command(tx, &op).await?;
        if command.status().is_terminal() {
            continue;
        }
        let field = &data.attempts.fields[op.request.field.index()];
        let Some(status) = field.status else { continue };
        let event = if (200..300).contains(&status) {
            dc::DeviceEvent::Received
        } else {
            dc::DeviceEvent::Rejected
        };
        let mut report = dc::DeviceReport {
            scope: op.scope,
            command_id: op.command_id()?,
            coordinate: op.coordinate,
            event,
        };
        let transition = s.store.report(tx, &report).await?;
        if transition.outcome == dc::Outcome::OutOfOrder {
            continue;
        }
        if field.quality == crate::collection::Quality::Success
            && !transition.command.status().is_terminal()
            && let Some(value) = &field.value
        {
            let actual = op.request.field.digest(value)?;
            if actual == op.request.field.digest(&op.request.expected_value)? {
                report.event = dc::DeviceEvent::Reported(actual);
                let transition = s.store.report(tx, &report).await?;
                if transition.outcome == dc::Outcome::OutOfOrder {
                    return Err(Error::Conflict.into());
                }
            }
        }
    }
    Ok(())
}
pub(super) async fn observation(
    tx: &mut PgTransaction<'_>,
    op: &storage::Operation,
) -> Result<Value> {
    let tenant = tx.tenant_id().to_string();
    let id = op.id;
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT id::text,ordinal,collection::text FROM mdm_commands.attempts WHERE tenant_id=$1::uuid AND operation=$2::uuid ORDER BY ordinal DESC LIMIT 1").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?;
    let Some(row) = row else {
        return Ok(json!({"result":"unknown"}));
    };
    let run = corrupt(Uuid::parse_str(&row.try_get::<String, _>("collection")?))?;
    let tenant = tx.tenant_id().to_string();
    let data = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(crate::collection::load_run(c, &tenant, run).await) })
        })
        .await??;
    let field = &data.attempts.fields[op.request.field.index()];
    let result = match (&field.value, field.quality) {
        (Some(v), crate::collection::Quality::Success) if v == &op.request.expected_value => {
            "matched"
        }
        (Some(_), crate::collection::Quality::Success) => "mismatched",
        _ => "unknown",
    };
    Ok(
        json!({"attemptId":row.try_get::<String,_>("id")?,"attempt":row.try_get::<i64,_>("ordinal")?,"collectionRun":run,"result":result,"quality":field.quality,"nativeStatus":field.status,"value":field.value,"receivedAt":field.received_at}),
    )
}
