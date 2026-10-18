//! Device retirement is accepted once; command delivery remains execution-owned.
//! ref: sqlx sqlx-core/src/transaction.rs (borrowed atomic acceptance).
use crate::{Error, Result};
use rss_mdm_authorization_service::{Permission, UserGrant};
use rss_mdm_inventory_service::objects::{DeviceObject, ObjectReader};
use rss_mdm_registration_service::lifecycle;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct Acceptance<'a> {
    pub policy: Uuid,
    pub version: Uuid,
    pub occurrence: &'a str,
    pub target: &'a DeviceObject,
    pub authority: &'a UserGrant,
    pub delivery_seconds: u32,
    pub now: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelResult {
    pub device: String,
    pub channel: rss_mdm_inventory::Channel,
    pub registration: Uuid,
    pub generation: i64,
    pub stage: Stage,
    pub effect: Effect,
    pub execution: Option<Uuid>,
    pub reason: Option<String>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Cleanup,
    Unenroll,
    Revoke,
    Complete,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Pending,
    Confirmed,
    Unknown,
    Blocked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retirement {
    pub id: Uuid,
    pub policy: Uuid,
    pub version: Uuid,
    pub target: DeviceObject,
    pub created_at: i64,
    pub forced_at: Option<i64>,
    pub channels: Vec<ChannelResult>,
}

/// Caller owns Audit and the original transaction. No independent commit occurs.
pub async fn accept_in(
    c: &mut PgConnection,
    tenant: TenantId,
    objects: &dyn ObjectReader,
    input: &Acceptance<'_>,
) -> Result<(Uuid, bool)> {
    if input.policy.is_nil()
        || input.version.is_nil()
        || input.occurrence.is_empty()
        || input.occurrence.len() > 256
        || !(60..=604800).contains(&input.delivery_seconds)
        || input.authority.user().tenant_id != tenant.to_string()
        || !input.target.verified
        || input.target.members.is_empty()
        || input.target.members.len() > 2
    {
        return Err(Error::Malformed);
    }
    let tenant = tenant.to_string();
    let mut members = input.target.members.iter().collect::<Vec<_>>();
    members.sort_by(|a, b| (&a.device, a.channel.as_str()).cmp(&(&b.device, b.channel.as_str())));
    // Owner identity fence precedes all endpoint locks, as in ObjectReader::validate.
    let tenant_id = TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::lock_watermark_in(c, tenant_id).await?;
    if !input
        .authority
        .valid(c, Permission::DeviceUnmanage, input.now)
        .await?
    {
        return Err(Error::Forbidden);
    }
    for member in &members {
        lifecycle::lock_device_in(c, &tenant, &member.device).await?;
    }
    if let Some(id)=sqlx::query_scalar("SELECT id FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND version=$2 AND object=$3 AND occurrence=$4")
        .bind(&tenant).bind(input.version).bind(input.target.object.key()).bind(input.occurrence).fetch_optional(&mut *c).await? {
        return Ok((id,true));
    }
    let mut existing = std::collections::BTreeSet::new();
    for member in &members {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(&member.device)
        .fetch_optional(&mut *c)
        .await?
        .flatten();
        if let Some(id) = id {
            existing.insert(id);
        }
    }
    if existing.len() == 1 {
        let id = *existing.first().ok_or(Error::Conflict)?;
        let prior = read_in(c, tenant_id, id).await?;
        if prior.target.members == input.target.members {
            return Ok((id, true));
        }
        return Err(Error::Conflict);
    }
    if !existing.is_empty() {
        return Err(Error::Conflict);
    }
    for member in &members {
        if objects
            .validate(c, tenant_id, input.target, member.channel)
            .await?
            .as_ref()
            != Some(*member)
        {
            return Err(Error::Conflict);
        }
        lifecycle::require_work_in(c, &tenant, &member.device).await?;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_devices.retirements(tenant_id,id,policy,version,object,occurrence,target,authority,delivery_seconds,created_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(&tenant).bind(id).bind(input.policy).bind(input.version).bind(input.target.object.key()).bind(input.occurrence)
        .bind(serde_json::to_value(input.target).map_err(|_|Error::Malformed)?)
        .bind(serde_json::to_value(input.authority).map_err(|_|Error::Malformed)?)
        .bind(input.delivery_seconds as i32).bind(input.now).execute(&mut *c).await?;
    for member in members {
        lifecycle::begin_retirement_in(c, &tenant, &member.device, id).await?;
        sqlx::query("INSERT INTO mdm_devices.retirement_channels(tenant_id,operation,device,channel,registration,generation,stage,effect) VALUES($1::uuid,$2,$3,$4,$5,$6,'cleanup','pending')")
            .bind(&tenant).bind(id).bind(&member.device).bind(member.channel.as_str())
            .bind(member.registration_id).bind(member.generation).execute(&mut *c).await?;
    }
    Ok((id, false))
}

pub async fn policy_operations_in(
    c: &mut PgConnection,
    tenant: TenantId,
    _policy: Uuid,
    object: &str,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT id FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND object=$2 ORDER BY created_at DESC,id DESC LIMIT 100")
        .bind(tenant.to_string()).bind(object).fetch_all(c).await?)
}

pub async fn read_in(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<Retirement> {
    let t = tenant.to_string();
    let row=sqlx::query("SELECT policy,version,target,created_at,forced_at FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2")
        .bind(&t).bind(id).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
    let rows=sqlx::query("SELECT device,channel,registration,generation,stage,effect,execution,reason FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY device,channel")
        .bind(&t).bind(id).fetch_all(c).await?;
    let mut channels = Vec::new();
    for r in rows {
        let parse = |name| -> Result<serde_json::Value> {
            Ok(serde_json::Value::String(r.try_get::<String, _>(name)?))
        };
        channels.push(ChannelResult {
            device: r.try_get("device")?,
            channel: serde_json::from_value(parse("channel")?).map_err(|_| Error::Storage)?,
            registration: r.try_get("registration")?,
            generation: r.try_get("generation")?,
            stage: serde_json::from_value(parse("stage")?).map_err(|_| Error::Storage)?,
            effect: serde_json::from_value(parse("effect")?).map_err(|_| Error::Storage)?,
            execution: r.try_get("execution")?,
            reason: r.try_get("reason")?,
        });
    }
    Ok(Retirement {
        id,
        policy: row.try_get("policy")?,
        version: row.try_get("version")?,
        target: serde_json::from_value(row.try_get("target")?).map_err(|_| Error::Storage)?,
        created_at: row.try_get("created_at")?,
        forced_at: row.try_get("forced_at")?,
        channels,
    })
}

/// A selected endpoint refers to its confirmed managed-device association, when
/// present. Both members participate even if only one endpoint was selected.
pub async fn complete_target_in(
    c: &mut PgConnection,
    tenant: TenantId,
    input: &DeviceObject,
) -> Result<DeviceObject> {
    use rss_mdm_inventory_service::objects::ObjectRef;
    let ObjectRef::Endpoint(device) = &input.object else {
        return Ok(input.clone());
    };
    rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let row=sqlx::query("SELECT a.id,a.version,a.state FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released AND a.state<>'revoked'")
        .bind(tenant.to_string()).bind(device).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return Ok(input.clone());
    };
    let id: Uuid = row.try_get("id")?;
    let frozen:Option<serde_json::Value>=sqlx::query_scalar("SELECT o.input FROM mdm_devices.input_objects o JOIN mdm_devices.input_snapshots s ON(s.tenant_id,s.id)=(o.tenant_id,o.snapshot) JOIN mdm_devices.checkpoints k ON k.tenant_id=s.tenant_id WHERE s.tenant_id=$1::uuid AND s.phase='sealed' AND s.watermark>=k.identity_watermark AND s.relation_revision=k.relation_revision AND o.object=$2 ORDER BY s.watermark DESC LIMIT 1")
        .bind(tenant.to_string()).bind(format!("association:{id}")).fetch_optional(&mut *c).await?;
    if let Some(frozen) = frozen {
        let mut full: DeviceObject = serde_json::from_value(frozen).map_err(|_| Error::Storage)?;
        full.verified &= input.verified && input.members.iter().all(|m| full.members.contains(m));
        return Ok(full);
    }

    let rows=sqlx::query("SELECT device,channel,registration_id,generation FROM mdm_devices.members WHERE tenant_id=$1::uuid AND association_id=$2 AND NOT released ORDER BY device,channel")
        .bind(tenant.to_string()).bind(id).fetch_all(c).await?;
    let mut members = Vec::new();
    for r in rows {
        members.push(
            rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
                device: r.try_get("device")?,
                channel: serde_json::from_value(serde_json::Value::String(r.try_get("channel")?))
                    .map_err(|_| Error::Storage)?,
                registration_id: r.try_get("registration_id")?,
                generation: r.try_get("generation")?,
            },
        );
    }
    Ok(DeviceObject {
        object: ObjectRef::Association(id),
        association_version: Some(row.try_get("version")?),
        verified: row.try_get::<String, _>("state")? == "confirmed" && members.len() == 2,
        members,
    })
}

/// Only the exact owner-linked cleanup command may bypass the ordinary-work fence.
pub async fn execution_allowed_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    execution: uuid::Uuid,
) -> Result<bool> {
    lifecycle::lock_device_in(c, tenant, device).await?;
    let exit: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(device)
    .fetch_optional(&mut *c)
    .await?
    .flatten();
    let Some(exit) = exit else {
        return Ok(true);
    };
    // The relation is exposed by the product lifecycle owner at installation.
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 AND device=$3 AND execution=$4 AND stage IN('cleanup','unenroll'))")
        .bind(tenant).bind(exit).bind(device).bind(execution).fetch_one(c).await?)
}
