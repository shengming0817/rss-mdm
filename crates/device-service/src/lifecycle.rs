//! Device retirement is accepted once; command delivery remains execution-owned.
//! ref: sqlx sqlx-core/src/transaction.rs (borrowed atomic acceptance).
use crate::{Error, Result};
use rss_mdm_authorization_service::Actor;
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
    pub actor: &'a Actor,
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
    pub parent_registration: Option<Uuid>,
    pub stage: Stage,
    pub effect: Effect,
    pub execution: Option<Uuid>,
    pub blocking_execution: Option<Uuid>,
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
    // Owner identity fence precedes all endpoint locks, as in ObjectReader::validate.
    let tenant_id = TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::lock_watermark_in(c, tenant_id).await?;
    for member in &members {
        lifecycle::lock_device_in(c, &tenant, &member.device).await?;
    }
    if let Some(id)=sqlx::query_scalar("SELECT id FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND version=$2 AND object=$3 AND occurrence=$4")
        .bind(&tenant).bind(input.version).bind(input.target.object.key()).bind(input.occurrence).fetch_optional(&mut *c).await? {
        let replay = link_policy_in(c, &tenant, input, id).await?;
        return Ok((id,replay));
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
        lifecycle::require_work_in(c, &tenant, &member.device).await?;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_devices.retirements(tenant_id,id,policy,version,object,occurrence,target,authority,delivery_seconds,created_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(&tenant).bind(id).bind(input.policy).bind(input.version).bind(input.target.object.key()).bind(input.occurrence)
        .bind(serde_json::to_value(input.target).map_err(|_|Error::Malformed)?)
        .bind(serde_json::to_value(input.actor).map_err(|_|Error::Malformed)?)
        .bind(input.delivery_seconds as i32).bind(input.now).execute(&mut *c).await?;
    for member in members {
        lifecycle::begin_retirement_in(c, &tenant, &member.device, id).await?;
        sqlx::query("INSERT INTO mdm_devices.retirement_channels(tenant_id,operation,device,channel,registration,generation,stage,effect) VALUES($1::uuid,$2,$3,$4,$5,$6,'cleanup','pending')")
            .bind(&tenant).bind(id).bind(&member.device).bind(member.channel.as_str())
            .bind(member.registration_id).bind(member.generation).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_devices.retirement_channels(tenant_id,operation,device,channel,registration,generation,parent_registration,stage,effect) SELECT tenant_id,$2,device,channel,id,generation,parent_id,'cleanup','pending' FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND parent_id=$3 AND state='active'")
            .bind(&tenant).bind(id).bind(member.registration_id).execute(&mut *c).await?;
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
    object: &str,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT o.id FROM mdm_devices.retirements o JOIN mdm_devices.retirement_policies p ON(p.tenant_id,p.operation)=(o.tenant_id,o.id) WHERE o.tenant_id=$1::uuid AND o.object=$2 AND p.policy=$3 GROUP BY o.id,o.created_at ORDER BY o.created_at DESC,o.id DESC LIMIT 100")
        .bind(tenant.to_string()).bind(object).bind(policy).fetch_all(c).await?)
}

pub async fn read_in(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<Retirement> {
    let t = tenant.to_string();
    let row=sqlx::query("SELECT policy,version,target,created_at,forced_at FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2")
        .bind(&t).bind(id).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
    let rows=sqlx::query("SELECT device,channel,registration,generation,parent_registration,stage,effect,execution,blocking_execution,reason FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 ORDER BY device,channel")
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
            parent_registration: r.try_get("parent_registration")?,
            stage: serde_json::from_value(parse("stage")?).map_err(|_| Error::Storage)?,
            effect: serde_json::from_value(parse("effect")?).map_err(|_| Error::Storage)?,
            execution: r.try_get("execution")?,
            blocking_execution: r.try_get("blocking_execution")?,
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
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w JOIN mdm_devices.retirement_channels t ON(t.tenant_id,t.operation,t.registration)=(w.tenant_id,w.operation,w.registration) WHERE w.tenant_id=$1::uuid AND w.operation=$2 AND t.device=$3 AND w.execution=$4 AND t.stage IN('cleanup','unenroll'))")
        .bind(tenant).bind(exit).bind(device).bind(execution).fetch_one(c).await?)
}

/// Attach exactly one current execution. Previous results remain in execution history.
async fn bind_execution_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: Uuid,
    execution: Uuid,
    stage: Stage,
) -> Result<()> {
    if execution.is_nil() {
        return Err(Error::Malformed);
    }
    let stage = serde_json::to_value(stage).map_err(|_| Error::Malformed)?;
    let stage = stage.as_str().ok_or(Error::Malformed)?;
    let changed=sqlx::query("UPDATE mdm_devices.retirement_channels SET execution=$4,reason=NULL,effect='pending' WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND stage=$5 AND execution IS NULL")
        .bind(tenant.to_string()).bind(operation).bind(registration).bind(execution).bind(stage).execute(c).await?;
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
    registration: Uuid,
    observation: Observation,
) -> Result<()> {
    let t = tenant.to_string();
    let device: String = sqlx::query_scalar("SELECT device FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3")
        .bind(&t).bind(operation).bind(registration).fetch_one(&mut *c).await?;
    lifecycle::lock_device_in(c, &t, &device).await?;
    let row = sqlx::query("SELECT t.stage,o.forced_at FROM mdm_devices.retirement_channels t JOIN mdm_devices.retirements o ON(o.tenant_id,o.id)=(t.tenant_id,t.operation) WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.registration=$3 FOR UPDATE OF t")
        .bind(&t).bind(operation).bind(registration).fetch_one(&mut *c).await?;
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
    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage=$4,effect=$5,reason=$6,blocking_execution=$7 WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND stage=$8")
        .bind(t).bind(operation).bind(registration).bind(stage).bind(effect).bind(reason).bind(blocking).bind(expected).execute(c).await?;
    Ok(())
}

impl crate::Associations {
    /// Final revocation uses the access owner's Audit transaction and the original
    /// registration participant. A command worker cannot commit credentials itself.
    pub async fn finalize_retirements(
        &self,
        participant: &dyn rss_mdm_registration_service::Retirement,
    ) -> Result<usize> {
        use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
        let budget = AuditBudget::new(std::time::Duration::from_secs(8));
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "device_retirement_revoked",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("device-lifecycle");
        let attempt=self.audit.write(self.tenant,&budget.source_control(),(self,participant,&audit),|(service,participant,audit),tx|Box::pin(async move {
            let service=*service;let participant=*participant;let audit=*audit;
            let (count,facts)=tx.with_connection_context(&mut (service,participant),|ctx,c|Box::pin(async move {
                let (service,participant)=*ctx;
                let tenant=service.tenant.to_string();
                let rows=sqlx::query("SELECT t.operation,t.registration,t.device FROM mdm_devices.retirement_channels t JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(t.tenant_id,t.registration) WHERE t.tenant_id=$1::uuid AND (t.stage='revoke' OR (r.state<>'active' AND t.stage<>'complete')) ORDER BY t.device,t.registration LIMIT 32")
                    .bind(&tenant).fetch_all(&mut *c).await?;
                let mut facts=Vec::new();
                for row in &rows {
                    let id:Uuid=row.try_get("operation")?;let registration:Uuid=row.try_get("registration")?;let device:String=row.try_get("device")?;
                    lifecycle::lock_device_in(c,&tenant,&device).await?;
                    let active:bool=sqlx::query_scalar("SELECT state='active' FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
                        .bind(&tenant).bind(registration).fetch_one(&mut *c).await?;
                    if active {lifecycle::retire(c,&mut facts,&tenant,registration,"revoked",participant).await?;}
                    // Already revoked without a correlated endpoint result remains unverified.
                    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage='complete',effect=CASE WHEN effect='confirmed' THEN effect ELSE 'unknown' END,reason=CASE WHEN effect='confirmed' THEN reason ELSE coalesce(reason,'device_cleanup_unconfirmed') END WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3")
                        .bind(&tenant).bind(id).bind(registration).execute(&mut *c).await?;
                }
                Ok::<_,Error>((rows.len(),facts))
            })).await?;
            for fact in facts {service.audit.append(tx, &fact).await?;}
            if count>0 {
                let id=Uuid::new_v4();
                let fact=Fact::business(audit, &format!("retirement:revoked:{id}"), 200, "success", None)?;
                service.audit.append(tx, &fact).await?;
            }
            audit.mark_commit_started();Ok(count)
        })).await;
        let result = attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |e| Err(crate::model::transaction_error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(crate::model::transaction_error(e))
            },
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |e| Err(crate::model::transaction_error(e)),
        );
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}

/// References existing execution work; this table owns no attempt or retry state.
pub async fn authorize_execution_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: Uuid,
    execution: Uuid,
) -> Result<()> {
    let changed=sqlx::query("INSERT INTO mdm_devices.retirement_work(tenant_id,operation,registration,execution) SELECT $1::uuid,$2,$3,$4 WHERE EXISTS(SELECT 1 FROM mdm_devices.retirement_channels t JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.retirement)=(t.tenant_id,t.device,t.operation) WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.registration=$3 AND t.stage IN('cleanup','unenroll')) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(operation).bind(registration).bind(execution).execute(c).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub async fn prepare_unenrollment_in(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    registration: Uuid,
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
    registration: Uuid,
    confirmed: bool,
) -> Result<()> {
    sqlx::query("UPDATE mdm_devices.retirement_channels SET stage='revoke',effect=CASE WHEN $3 THEN 'confirmed' ELSE 'unknown' END,reason=CASE WHEN $3 THEN NULL ELSE 'native_unenrollment_unverified' END WHERE tenant_id=$1::uuid AND registration=$2 AND stage='unenroll'")
        .bind(tenant).bind(registration).bind(confirmed).execute(c).await?;
    Ok(())
}
