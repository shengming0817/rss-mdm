//! Device accepts and advances retirement; Registration owns credential retirement fences.
//! ref: sqlx sqlx-core/src/transaction.rs (borrowed atomic acceptance).
use crate::{Error, Result};
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_authorization_service::Actor;
use rss_mdm_inventory_service::objects::{DeviceObject, ObjectReader};
use rss_mdm_registration_service::lifecycle;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub struct Acceptance<'a> {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub policy: Uuid,
    pub version: Uuid,
    pub occurrence: &'a str,
    pub target: &'a DeviceObject,
    pub actor: &'a Actor,
    pub delivery_seconds: u32,
    pub now: i64,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelResult {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub channel: rss_mdm_inventory::Channel,
    pub stage: Stage,
    pub effect: Effect,
    pub execution: Option<Uuid>,
    pub blocking_execution: Option<Uuid>,
    pub reason: Option<String>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Cleanup,
    Unenroll,
    Revoke,
    Complete,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Pending,
    Confirmed,
    Unknown,
    Blocked,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retirement {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
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
        || input.actor.tenant_id() != tenant.to_string()
        || !input.target.verified
        || input.target.members.is_empty()
        || input.target.members.len() > 2
    {
        return Err(Error::Malformed);
    }
    let tenant = tenant.to_string();
    let mut members = input.target.members.iter().collect::<Vec<_>>();
    members.sort_by(|a, b| (&a.device, a.channel.as_str()).cmp(&(&b.device, b.channel.as_str())));
    // Device exclusion precedes the short, nonblocking publication fence.
    let tenant_id = TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
    let devices = members.iter().map(|m| m.device).collect::<Vec<_>>();
    if !lifecycle::try_lock_devices_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &tenant,
        &devices,
    )
    .await?
    {
        return Err(Error::Storage);
    }
    if let Some(id)=sqlx::query_scalar("SELECT id FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND version=$2 AND (object_kind,object_id)=($3,$4) AND occurrence=$5")
        .bind(&tenant).bind(input.version).bind(input.target.object.kind()).bind(input.target.object.uuid()).bind(input.occurrence).fetch_optional(&mut *c).await? {
        let replay = link_policy_in(c, &tenant, input, id).await?;
        return Ok((id,replay));
    }
    let mut existing = std::collections::BTreeSet::new();
    for member in &members {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(member.device.into_uuid())
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
            let replay = link_policy_in(c, &tenant, input, id).await?;
            return Ok((id, replay));
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
        lifecycle::require_work_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            &member.device,
        )
        .await?;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_devices.retirements(tenant_id,id,policy,version,object_kind,object_id,occurrence,target,authority,delivery_seconds,created_at,origin) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(&tenant).bind(id).bind(input.policy).bind(input.version).bind(input.target.object.kind()).bind(input.target.object.uuid()).bind(input.occurrence)
        .bind(serde_json::to_value(input.target).map_err(|_|Error::Malformed)?)
        .bind(serde_json::to_value(input.actor).map_err(|_|Error::Malformed)?)
        .bind(input.delivery_seconds as i32).bind(input.now).bind(serde_json::to_value(input.origin).map_err(|_|Error::Malformed)?).execute(&mut *c).await?;
    for member in members {
        lifecycle::begin_retirement_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            &member.device,
            id,
        )
        .await?;
        sqlx::query("INSERT INTO mdm_devices.retirement_channels (tenant_id, operation, device, channel, stage, effect) VALUES (CAST($1 AS uuid), $2, $3, $4, 'cleanup', 'pending')")
            .bind(&tenant).bind(id).bind(member.device.into_uuid()).bind(member.channel.as_str()).execute(&mut *c).await?;
    }
    link_policy_in(c, &tenant, input, id).await?;
    Ok((id, false))
}

async fn link_policy_in(
    c: &mut PgConnection,
    tenant: &str,
    input: &Acceptance<'_>,
    operation: Uuid,
) -> Result<bool> {
    let inserted = sqlx::query("INSERT INTO mdm_devices.retirement_policies(tenant_id,policy,version,operation) VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(input.policy).bind(input.version).bind(operation).execute(c).await?;
    Ok(inserted.rows_affected() == 0)
}

pub async fn policy_operations_in(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    object: &ObjectRef,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT o.id FROM mdm_devices.retirements o JOIN mdm_devices.retirement_policies p ON(p.tenant_id,p.operation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND (o.object_kind,o.object_id)=($2,$3) AND p.policy=$4 GROUP BY o.id,o.created_at ORDER BY o.created_at DESC,o.id DESC LIMIT 100")
        .bind(tenant.to_string()).bind(object.kind()).bind(object.uuid()).bind(policy).fetch_all(c).await?)
}

pub(crate) struct RetirementHeader {
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub id: Uuid,
    pub policy: Uuid,
    pub version: Uuid,
    pub target: DeviceObject,
    pub created_at: i64,
    pub forced_at: Option<i64>,
}
pub(crate) async fn read_header_in(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<RetirementHeader> {
    let row=sqlx::query("SELECT policy,version,target,created_at,forced_at,origin FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant.to_string()).bind(id).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    Ok(RetirementHeader {
        origin: serde_json::from_value(row.try_get("origin")?).map_err(|_| Error::Storage)?,
        id,
        policy: row.try_get("policy")?,
        version: row.try_get("version")?,
        target: serde_json::from_value(row.try_get("target")?).map_err(|_| Error::Storage)?,
        created_at: row.try_get("created_at")?,
        forced_at: row.try_get("forced_at")?,
    })
}
pub async fn read_in(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<Retirement> {
    let header = read_header_in(c, tenant, id).await?;
    let t = tenant.to_string();
    let rows=sqlx::query("SELECT device, channel, stage, effect, execution, blocking_execution, reason FROM mdm_devices.retirement_channels WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 ORDER BY device, channel")
        .bind(&t).bind(id).fetch_all(c).await?;
    let mut channels = Vec::new();
    for r in rows {
        let parse = |name| -> Result<serde_json::Value> {
            Ok(serde_json::Value::String(r.try_get::<String, _>(name)?))
        };
        channels.push(ChannelResult {
            device: r.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })?,
            channel: serde_json::from_value(parse("channel")?).map_err(|_| Error::Storage)?,

            stage: serde_json::from_value(parse("stage")?).map_err(|_| Error::Storage)?,
            effect: serde_json::from_value(parse("effect")?).map_err(|_| Error::Storage)?,
            execution: r.try_get("execution")?,
            blocking_execution: r.try_get("blocking_execution")?,
            reason: r.try_get("reason")?,
        });
    }
    Ok(Retirement {
        origin: header.origin,
        id: header.id,
        policy: header.policy,
        version: header.version,
        target: header.target,
        created_at: header.created_at,
        forced_at: header.forced_at,
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
    use rss_mdm_agent_wire::ObjectRef;
    let ObjectRef::Endpoint(device) = &input.object else {
        return Ok(input.clone());
    };
    let row=sqlx::query("SELECT a.id,a.version,a.state FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released AND a.state<>'revoked'")
        .bind(tenant.to_string()).bind(device.into_uuid()).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return Ok(input.clone());
    };
    let id: Uuid = row.try_get("id")?;
    let frozen:Option<serde_json::Value>=sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object_kind,object_id,revision) WHERE h.tenant_id=$1::uuid AND h.object_kind=1 AND h.object_id=$2")
        .bind(tenant.to_string()).bind(id).fetch_optional(&mut *c).await?.flatten();
    if let Some(frozen) = frozen {
        let mut full: DeviceObject = serde_json::from_value(frozen).map_err(|_| Error::Storage)?;
        full.verified &= input.verified && input.members.iter().all(|m| full.members.contains(m));
        return Ok(full);
    }

    let rows=sqlx::query("SELECT device, channel, device_id FROM mdm_devices.members WHERE tenant_id = CAST($1 AS uuid) AND association_id = $2 AND NOT released ORDER BY device, channel")
        .bind(tenant.to_string()).bind(id).fetch_all(c).await?;
    let mut members = Vec::new();
    for r in rows {
        members.push(
            rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
                device: r.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                    rss_mdm_agent_wire::DeviceId::try_from(id)
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?,
                channel: serde_json::from_value(serde_json::Value::String(r.try_get("channel")?))
                    .map_err(|_| Error::Storage)?,
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
    device: &rss_mdm_agent_wire::DeviceId,
    execution: uuid::Uuid,
) -> Result<bool> {
    lifecycle::lock_device_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        device,
    )
    .await?;
    Ok(
        execution_permissions_in(c, tenant, &[(execution, device.to_owned())])
            .await?
            .get(&execution)
            .copied()
            .unwrap_or(false),
    )
}

/// Current lifecycle facts for a read batch. Writers retain the device lock above.
pub async fn execution_permissions_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    targets: &[(uuid::Uuid, rss_mdm_agent_wire::DeviceId)],
) -> Result<std::collections::BTreeMap<uuid::Uuid, bool>> {
    let ids = targets.iter().map(|v| v.0).collect::<Vec<_>>();
    let devices = targets.iter().map(|v| v.1).collect::<Vec<_>>();
    let rows = sqlx::query_as::<_,(uuid::Uuid,bool)>(
        "SELECT x.id, d.retirement IS NULL OR EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w INNER JOIN mdm_devices.retirement_channels AS t ON (t.tenant_id, t.operation, t.device) = (w.tenant_id, w.operation, w.device) WHERE w.tenant_id = CAST($1 AS uuid) AND w.operation = d.retirement AND t.device = x.device AND w.execution = x.id AND t.stage IN ('cleanup', 'unenroll')) FROM unnest(CAST($2 AS uuid[]), CAST($3 AS uuid[])) AS x (id, device) LEFT JOIN mdm_access.devices AS d ON (d.tenant_id, d.id) = (CAST($1 AS uuid), x.device)"
    ).bind(tenant).bind(ids).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await?;
    Ok(rows.into_iter().collect())
}

/// Attach exactly one current execution. Previous results remain in execution history.
async fn bind_execution_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
    execution: Uuid,
    stage: Stage,
) -> Result<()> {
    if execution.is_nil() {
        return Err(Error::Malformed);
    }
    let stage = serde_json::to_value(stage).map_err(|_| Error::Malformed)?;
    let stage = stage.as_str().ok_or(Error::Malformed)?;
    let changed=sqlx::query("UPDATE mdm_devices.retirement_channels SET execution = $4, reason = NULL, effect = 'pending' WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 AND device = $3 AND stage = $5 AND execution IS NULL")
        .bind(tenant.to_string()).bind(operation).bind(registration.into_uuid()).bind(execution).bind(stage).execute(c).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Facts reported by execution; lifecycle transitions remain owned here.
pub enum Observation {
    CleanupReady,
    CleanupWaiting {
        execution: Option<Uuid>,
    },
    CleanupBlocked {
        reason: &'static str,
        execution: Option<Uuid>,
        unknown: bool,
    },
    Uninstalled,
    UnenrollmentBlocked {
        reason: &'static str,
    },
    UnenrollmentUnknown {
        reason: &'static str,
    },
}
pub async fn observe_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
    observation: Observation,
) -> Result<()> {
    let t = tenant.to_string();
    let device: rss_mdm_agent_wire::DeviceId = sqlx::query_scalar("SELECT device FROM mdm_devices.retirement_channels WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 AND device = $3")
        .bind(&t).bind(operation).bind(registration.into_uuid()).fetch_one(&mut *c).await.and_then(crate::device_id)?;
    lifecycle::lock_device_in(rss_mdm_install_support::StorageProfile::Mdm, c, &t, &device).await?;
    let row = sqlx::query("SELECT t.stage, o.forced_at FROM mdm_devices.retirement_channels AS t INNER JOIN mdm_devices.retirements AS o ON (o.tenant_id, o.id) = (t.tenant_id, t.operation) WHERE t.tenant_id = CAST($1 AS uuid) AND t.operation = $2 AND t.device = $3 FOR UPDATE OF t")
        .bind(&t).bind(operation).bind(registration.into_uuid()).fetch_one(&mut *c).await?;
    let current: String = row.try_get("stage")?;
    if row.try_get::<Option<i64>, _>("forced_at")?.is_some()
        || matches!(current.as_str(), "revoke" | "complete")
    {
        return Ok(());
    }
    let (expected, stage, effect, reason, blocking) = match observation {
        Observation::CleanupReady => ("cleanup", "unenroll", "pending", None, None),
        Observation::CleanupWaiting { execution } => (
            "cleanup",
            "cleanup",
            "pending",
            Some("cleanup_in_progress"),
            execution,
        ),
        Observation::CleanupBlocked {
            reason,
            execution,
            unknown,
        } => (
            "cleanup",
            "cleanup",
            if unknown { "unknown" } else { "blocked" },
            Some(reason),
            execution,
        ),
        Observation::Uninstalled => ("unenroll", "revoke", "confirmed", None, None),
        Observation::UnenrollmentBlocked { reason } => {
            ("unenroll", "unenroll", "blocked", Some(reason), None)
        }
        Observation::UnenrollmentUnknown { reason } => {
            ("unenroll", "unenroll", "unknown", Some(reason), None)
        }
    };
    if current != expected {
        return Ok(());
    }
    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage = $4, effect = $5, reason = $6, blocking_execution = $7 WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 AND device = $3 AND stage = $8")
        .bind(t).bind(operation).bind(registration.into_uuid()).bind(stage).bind(effect).bind(reason).bind(blocking).bind(expected).execute(c).await?;
    Ok(())
}

/// One final credential settlement, borrowed from the Device owner claim transaction.
pub(crate) async fn settle_retirement_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    participant: &dyn rss_mdm_registration_service::Retirement,
) -> Result<Vec<rss_mdm_audit_integration::Fact>> {
    let t = tenant.to_string();
    let row:Option<(Uuid,Uuid)>=sqlx::query_as("SELECT t.operation, t.device FROM mdm_devices.retirement_channels AS t INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (t.tenant_id, t.device) WHERE t.tenant_id = CAST($1 AS uuid) AND t.operation = $2 AND (t.stage = 'revoke' OR (r.state <> 'active' AND t.stage <> 'complete')) ORDER BY t.device LIMIT 1").bind(&t).bind(operation).fetch_optional(&mut *c).await?;
    let Some((id, registration)) = row else {
        return Ok(vec![]);
    };
    let registration = crate::device_id(registration)?;
    if !lifecycle::try_lock_devices_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &t,
        std::slice::from_ref(&registration),
    )
    .await?
    {
        return Err(Error::Conflict);
    }
    let active:bool=sqlx::query_scalar("SELECT state = 'active' FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 FOR UPDATE").bind(&t).bind(registration.into_uuid()).fetch_one(&mut *c).await?;
    let mut facts = Vec::new();
    if active {
        lifecycle::retire(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &mut facts,
            &t,
            &registration,
            "revoked",
            participant,
        )
        .await?;
    }
    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage = 'complete', effect = CASE WHEN effect = 'confirmed' THEN effect ELSE 'unknown' END, reason = CASE WHEN effect = 'confirmed' THEN reason ELSE COALESCE(reason, 'device_cleanup_unconfirmed') END WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 AND device = $3").bind(t).bind(id).bind(registration.into_uuid()).execute(c).await?;
    Ok(facts)
}
/// References existing execution work; this table owns no attempt or retry state.
pub async fn authorize_execution_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
    execution: Uuid,
) -> Result<()> {
    let changed=sqlx::query("INSERT INTO mdm_devices.retirement_work (tenant_id, operation, device, execution) SELECT CAST($1 AS uuid), $2, $3, $4 WHERE EXISTS (SELECT 1 FROM mdm_devices.retirement_channels AS t INNER JOIN mdm_access.devices AS d ON (d.tenant_id, d.id, d.retirement) = (t.tenant_id, t.device, t.operation) WHERE t.tenant_id = CAST($1 AS uuid) AND t.operation = $2 AND t.device = $3 AND t.stage IN ('cleanup', 'unenroll')) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(operation).bind(registration.into_uuid()).bind(execution).execute(c).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub async fn prepare_unenrollment_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
    execution: Uuid,
) -> Result<()> {
    authorize_execution_in(c, tenant, operation, registration, execution).await?;
    bind_execution_in(
        c,
        tenant,
        operation,
        registration,
        execution,
        Stage::Unenroll,
    )
    .await
}

/// A trusted protocol departure can settle only the corresponding accepted exit.
/// Windows alerts confirm intent to disconnect, not completed device cleanup.
pub async fn native_departure_in(
    c: &mut PgConnection,
    tenant: &str,
    registration: rss_mdm_agent_wire::DeviceId,
    confirmed: bool,
) -> Result<()> {
    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage = 'revoke', effect = CASE WHEN $3 THEN 'confirmed' ELSE 'unknown' END, reason = CASE WHEN $3 THEN NULL ELSE 'native_unenrollment_unverified' END WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND stage = 'unenroll'")
        .bind(tenant).bind(registration.into_uuid()).bind(confirmed).execute(c).await?;
    Ok(())
}

/// Exact cleanup admission; ordinary lifecycle eligibility also admits unenrollment and is wider.
pub async fn cleanup_allowed_in(
    c: &mut PgConnection,
    tenant: &str,
    retirement: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
    execution: Option<Uuid>,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_devices.retirement_channels AS t INNER JOIN mdm_access.devices AS d ON (d.tenant_id, d.id, d.retirement) = (t.tenant_id, t.device, t.operation) INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (t.tenant_id, t.device) WHERE t.tenant_id = CAST($1 AS uuid) AND t.operation = $2 AND t.device = $3 AND t.stage = 'cleanup' AND r.state = 'active' AND (CAST($4 AS uuid) IS NULL OR EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w WHERE (w.tenant_id, w.operation, w.device, w.execution) = (t.tenant_id, t.operation, t.device, $4))))").bind(tenant).bind(retirement).bind(device.into_uuid()).bind(execution).fetch_one(c).await?)
}
pub async fn cleanup_context_in(
    c: &mut PgConnection,
    tenant: TenantId,
    retirement: Uuid,
) -> Result<(Retirement, u32)> {
    let context = read_in(c, tenant, retirement).await?;
    let lifetime: i32 = sqlx::query_scalar(
        "SELECT delivery_seconds FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant.to_string())
    .bind(retirement)
    .fetch_one(c)
    .await?;
    Ok((context, lifetime.try_into().map_err(|_| Error::Malformed)?))
}

/// Retained retirement targets for this Policy's current read page.
pub async fn retained_targets_on(
    c: &mut PgConnection,
    tenant: TenantId,
    policy: Uuid,
    after: Option<&ObjectRef>,
    limit: usize,
) -> Result<Vec<serde_json::Value>> {
    if !(1..=1000).contains(&limit) {
        return Err(Error::Malformed);
    }
    Ok(sqlx::query_scalar("SELECT DISTINCT ON(o.object_kind,o.object_id) o.target FROM mdm_devices.retirements o JOIN mdm_devices.retirement_policies p ON(p.tenant_id,p.operation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND p.policy=$2 AND ($3::smallint IS NULL OR (o.object_kind,o.object_id)>($3,$4::uuid)) ORDER BY o.object_kind,o.object_id,o.created_at DESC LIMIT $5")
        .bind(tenant.to_string()).bind(policy).bind(after.map(|o|o.kind())).bind(after.map(|o|o.uuid())).bind((limit+1) as i64).fetch_all(c).await?)
}
