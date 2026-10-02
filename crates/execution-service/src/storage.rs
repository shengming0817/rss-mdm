use super::*;
pub use crate::action_admission::{authorized, lock, now};
use crate::authority::ExecutionAuthority;
use sqlx::{PgConnection, Row};

pub struct Operation {
    pub id: Uuid,
    pub device: String,
    pub request: Create,
    pub approval: ExecutionAuthority,
    pub revision: i64,
    pub dispatch_failure: Option<serde_json::Value>,
    pub scope: dc::Scope,
    pub coordinate: dc::Coordinate,
    pub registration: Uuid,
    pub registration_generation: i64,
}
impl Operation {
    pub fn command_id(&self) -> Result<dc::CommandId> {
        checked_input(dc::CommandId::parse(&self.id.to_string()))
    }
}

pub async fn load(
    tx: &mut PgTransaction<'_>,
    protection: &rss_mdm_native_protection::Protector,
    id: Uuid,
) -> Result<Operation> {
    let tenant = tx.tenant_id();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT o.device,o.dispatch_failure,o.request,o.input_context,o.approval::text,o.revision,o.generation,o.epoch,o.registration,o.registration_generation,o.gateway_accepted,d.command_device::text FROM mdm_commands.operations o JOIN mdm_commands.devices d USING(tenant_id,device) WHERE o.tenant_id=$1::uuid AND o.id=$2::uuid").bind(tenant.to_string()).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Execution(crate::missing::ExecutionError::MissingOperation))?;
    Ok(Operation {
        id,
        device: row.try_get("device")?,
        request: super::input_storage::open_row(protection, tenant, id, &row, "request")?,
        approval: stored(serde_json::from_str(&row.try_get::<String, _>("approval")?))?,
        revision: row.try_get("revision")?,
        dispatch_failure: row.try_get("dispatch_failure")?,
        scope: dc::Scope::new(
            tenant,
            stored(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        ),
        coordinate: stored(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?,
        registration: row.try_get("registration")?,
        registration_generation: row.try_get("registration_generation")?,
    })
}

pub async fn approval_valid(
    source: &Arc<dyn crate::source_authority::SourceAuthority>,
    key: &Arc<rss_mdm_native_protection::Protector>,
    tx: &mut PgTransaction<'_>,
    operation: &Operation,
    now: i64,
) -> Result<bool> {
    let key = key.clone();
    let source = source.clone();
    let approval = operation.approval.clone();
    let permission = operation.request.task.permissions()?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(approval
                    .valid(source.as_ref(), c, &key, &permission, now)
                    .await)
            })
        })
        .await??)
}
pub async fn current_registration(tx: &mut PgTransaction<'_>, device: &str) -> Result<(Uuid, i64)> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let t = tenant.clone();
    let d = device.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(
                crate::device::store::lock_channel(c, &t, &d, rss_mdm_inventory::Channel::Mdm)
                    .await,
            )
        })
    })
    .await??;
    let rows = tx
        .with_connection(move |c| {
            Box::pin(crate::device::read::active_channel_in(
                c,
                tenant,
                vec![device],
                rss_mdm_inventory::Channel::Mdm,
            ))
        })
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict.into());
    }
    Ok((rows[0].1, rows[0].2))
}
pub async fn authority(
    service: &ExecutionService,
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
            stored(dc::DeviceId::parse(
                &row.try_get::<String, _>("command_device")?,
            ))?,
        );
        let old = stored(dc::Coordinate::new(
            row.try_get("generation")?,
            row.try_get("epoch")?,
        ))?;
        if row.try_get::<String, _>("registration")? == registration.to_string()
            && row.try_get::<i64, _>("registration_generation")? == registration_generation
        {
            return Ok((scope, old));
        }
        let next = stored(dc::Coordinate::new(
            old.generation(),
            old.epoch().checked_add(1).ok_or(Error::Conflict)?,
        ))?;
        service.store.advance(tx, scope, old, next).await?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.devices SET epoch=$3,registration=$4::uuid,registration_generation=$5,recovery_after=NULL WHERE tenant_id=$1::uuid AND device=$2").bind(tenant.to_string()).bind(name).bind(next.epoch()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        Ok((scope, next))
    } else {
        let uuid = Uuid::new_v4();
        let scope = dc::Scope::new(
            tenant,
            checked_input(dc::DeviceId::parse(&uuid.to_string()))?,
        );
        let coordinate = checked_input(dc::Coordinate::new(1, 1))?;
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.devices(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1::uuid,$2,$3::uuid,1,1,$4::uuid,$5)").bind(tenant.to_string()).bind(name).bind(uuid.to_string()).bind(registration.to_string()).bind(registration_generation).execute(c).await?;Ok(())})).await?;
        service.store.initialize(tx, scope, coordinate).await?;
        Ok((scope, coordinate))
    }
}
pub async fn read_on(
    conn: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    actor: &str,
) -> std::result::Result<Option<(Vec<u8>, serde_json::Value)>, sqlx::Error> {
    let row=sqlx::query("SELECT fingerprint,response::text FROM mdm_commands.requests WHERE tenant_id=$1::uuid AND id=$2::uuid AND actor=$3").bind(tenant).bind(id.to_string()).bind(actor).fetch_optional(conn).await?;
    row.map(|r| {
        Ok((
            r.try_get("fingerprint")?,
            serde_json::from_str(&r.try_get::<String, _>("response")?)
                .map_err(|_| sqlx::Error::Protocol("stored request".into()))?,
        ))
    })
    .transpose()
}

pub async fn admit(tx: &mut PgTransaction<'_>) -> Result<()> {
    tx.with_connection(|c| {
        Box::pin(async move {
            rss_mdm_inventory_postgres::verify_collections(c)
                .await
                .map_err(|_| sqlx::Error::Protocol("collection execution admission".into()))
        })
    })
    .await?;
    let (allowed, raw, dependencies) = tx
        .with_connection(|c| {
            Box::pin(async move {
                let allowed = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                    .fetch_one(&mut *c)
                    .await?;
                let raw = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                    .fetch_one(&mut *c)
                    .await?;
                let dependencies =
                    sqlx::query_scalar::<_, String>(include_str!("dependencies.sql"))
                        .fetch_one(c)
                        .await?;
                Ok((allowed, raw, dependencies))
            })
        })
        .await?;
    let actual: serde_json::Value = stored(serde_json::from_str(&raw))?;
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("catalog.json")).expect("canonical catalog");
    let dependencies: serde_json::Value = stored(serde_json::from_str(&dependencies))?;
    let expected_dependencies: serde_json::Value =
        serde_json::from_str(include_str!("dependencies.json")).expect("canonical dependencies");
    if !allowed || actual != expected || dependencies != expected_dependencies {
        eprintln!(
            "{}",
            serde_json::json!({"event":"command_admission_rejected","authority":allowed,"catalog":actual==expected,"dependencies":dependencies==expected_dependencies})
        );
        return Err(Error::Unavailable(Failure::CommandInvariant).into());
    }
    Ok(())
}

pub async fn require_source(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    source: rss_mdm_inventory::ReportSource,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let valid = tx
        .with_connection(move |c| {
            Box::pin(crate::device::read::enabled_source_in(
                c,
                tenant,
                registration,
                source,
            ))
        })
        .await?;
    if !valid {
        return Err(Error::Conflict.into());
    }
    Ok(())
}

pub async fn authorized_native(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
    device: &str,
    permissions: &[crate::authorization::Permission],
) -> Result<crate::authorization::Snapshot> {
    if permissions.is_empty() {
        return Err(Error::Forbidden.into());
    }
    let snapshot = crate::action_admission::current(tx, proof).await?;
    for &permission in permissions {
        snapshot.require(proof, permission, Some(device))?;
    }
    Ok(snapshot)
}
