use super::*;
use crate::authorization::Approval;
use sqlx::{PgConnection, Row};

pub(super) struct Operation {
    pub id: Uuid,
    pub device: String,
    pub request: Create,
    pub approval: Approval,
    pub revision: i64,
    pub scope: dc::Scope,
    pub coordinate: dc::Coordinate,
    pub registration: Uuid,
    pub registration_generation: i64,
}
impl Operation {
    pub fn command_id(&self) -> Result<dc::CommandId> {
        invalid(dc::CommandId::parse(&self.id.to_string()))
    }
}
pub(super) async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub(super) async fn lock(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let key = format!("{}:{device}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub(super) async fn load(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Operation> {
    let tenant = tx.tenant_id();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT o.device,o.request::text,o.approval::text,o.revision,o.generation,o.epoch,o.registration::text,o.registration_generation,o.gateway_accepted,d.command_device::text FROM mdm_commands.operations o JOIN mdm_commands.devices d USING(tenant_id,device) WHERE o.tenant_id=$1::uuid AND o.id=$2::uuid").bind(tenant.to_string()).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::ManagementNotFound(crate::management::Missing::Operation))?;
    Ok(Operation {
        id,
        device: row.try_get("device")?,
        request: corrupt(serde_json::from_str(&row.try_get::<String, _>("request")?))?,
        approval: corrupt(serde_json::from_str(&row.try_get::<String, _>("approval")?))?,
        revision: row.try_get("revision")?,
        scope: dc::Scope::new(
            tenant,
            corrupt(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        ),
        coordinate: corrupt(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?,
        registration: corrupt(Uuid::parse_str(&row.try_get::<String, _>("registration")?))?,
        registration_generation: row.try_get("registration_generation")?,
    })
}
pub(super) async fn audit(tx: &mut PgTransaction<'_>, audit: &Audit, status: u16) -> Result<()> {
    let audit = audit.clone();
    let outcome = audit
        .snapshot()
        .management_result
        .map_or("success", |r| r.audit_tag());
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::access_store::append_on_connection(c, &audit, status, outcome, None).await)
        })
    })
    .await??;
    Ok(())
}
pub(super) async fn authorized(
    tx: &mut PgTransaction<'_>,
    proof: &crate::identity::Principal,
    device: &str,
    permission: crate::authorization::Permission,
) -> Result<crate::authorization::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::authorization::lock_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??;
    snapshot.require(proof, permission, Some(device))?;
    Ok(snapshot)
}
pub(super) async fn approval_valid(
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
    now: i64,
) -> Result<bool> {
    let approval = operation.approval.clone();
    Ok(tx
        .with_connection(move |c| Box::pin(async move { Ok(approval.valid(c, now).await) }))
        .await??)
}
pub(super) async fn current_registration(
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<(Uuid, i64)> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let t = tenant.clone();
    let d = device.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::device::store::lock_channel(c, &t, &d, crate::device::Channel::Mdm).await)
        })
    })
    .await??;
    let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT id::text,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND state='active' ORDER BY id").bind(tenant).bind(device).fetch_all(c).await})).await?;
    if rows.len() != 1 {
        return Err(Error::Conflict.into());
    }
    Ok((
        corrupt(Uuid::parse_str(&rows[0].try_get::<String, _>("id")?))?,
        rows[0].try_get("generation")?,
    ))
}
pub(super) async fn authority(
    service: &Commands,
    tx: &mut PgTransaction<'_>,
    device: &str,
    registration: Uuid,
    registration_generation: i64,
) -> Result<(dc::Scope, dc::Coordinate)> {
    let tenant = tx.tenant_id();
    let name = device.to_owned();
    let row=tx.with_connection(|c|Box::pin(async move {sqlx::query("SELECT command_device::text,generation,epoch,registration::text,registration_generation FROM mdm_commands.devices WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(tenant.to_string()).bind(&name).fetch_optional(c).await})).await?;
    if let Some(row) = row {
        let scope = dc::Scope::new(
            tenant,
            corrupt(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        );
        let old = corrupt(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?;
        if row.try_get::<String, _>("registration")? == registration.to_string()
            && row.try_get::<i64, _>("registration_generation")? == registration_generation
        {
            return Ok((scope, old));
        }
        let next = corrupt(dc::Coordinate::new(
            old.generation(),
            old.epoch().checked_add(1).ok_or(Error::Conflict)?,
        ))?;
        service.store.advance(tx, scope, old, next).await?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.devices SET epoch=$3,registration=$4::uuid,registration_generation=$5,recovery_after=NULL WHERE tenant_id=$1::uuid AND device=$2").bind(tenant.to_string()).bind(name).bind(next.epoch()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        Ok((scope, next))
    } else {
        let uuid = Uuid::new_v4();
        let scope = dc::Scope::new(tenant, invalid(dc::DeviceId::parse(&uuid.to_string()))?);
        let coordinate = invalid(dc::Coordinate::new(1, 1))?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.devices(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1::uuid,$2,$3::uuid,1,1,$4::uuid,$5)").bind(tenant.to_string()).bind(name).bind(uuid.to_string()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        service.store.initialize(tx, scope, coordinate).await?;
        Ok((scope, coordinate))
    }
}
pub(super) async fn read_on(
    conn: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<Option<(Vec<u8>, serde_json::Value)>, sqlx::Error> {
    let row=sqlx::query("SELECT fingerprint,response::text FROM mdm_commands.requests WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).fetch_optional(conn).await?;
    row.map(|r| {
        Ok((
            r.try_get("fingerprint")?,
            serde_json::from_str(&r.try_get::<String, _>("response")?)
                .map_err(|_| sqlx::Error::Protocol("stored request".into()))?,
        ))
    })
    .transpose()
}

pub(super) async fn admit(tx: &mut PgTransaction<'_>) -> Result<()> {
    let (allowed, raw) = tx
        .with_connection(|c| {
            Box::pin(async move {
                let allowed = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                    .fetch_one(&mut *c)
                    .await?;
                let raw = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                    .fetch_one(c)
                    .await?;
                Ok((allowed, raw))
            })
        })
        .await?;
    let actual: serde_json::Value = corrupt(serde_json::from_str(&raw))?;
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("catalog.json")).expect("canonical catalog");
    if !allowed || actual != expected {
        return Err(Error::Unavailable(Failure::CommandStorage).into());
    }
    Ok(())
}
