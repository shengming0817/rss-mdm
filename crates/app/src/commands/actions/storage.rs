use super::{model::*, state::RunState};
use crate::commands::{Result, corrupt, invalid, storage};
use crate::{
    Error,
    authorization::{Approval, Permission, User},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

pub(super) struct Plan {
    pub id: Uuid,
    pub frozen: Frozen,
    pub author: User,
    pub author_approvals: Vec<Approval>,
    pub reviewer: Option<User>,
    pub reviewer_approvals: Vec<Approval>,
    pub active: bool,
    pub scan_at: i64,
    pub blocked_at: Option<i64>,
}
pub(super) struct Run {
    pub id: Uuid,
    pub plan: Uuid,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<Value>,
}
pub(super) async fn registration(tx: &mut PgTransaction<'_>, device: &str) -> Result<Target> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let target_device = device.clone();
    let d = device.clone();
    let t = tenant.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(
                crate::device::store::lock_channel(c, &t, &d, rss_mdm_inventory::Channel::Agent)
                    .await,
            )
        })
    })
    .await??;
    let row=tx.with_connection(move|c|Box::pin(async move{
        let row=sqlx::query("SELECT r.id::text,r.generation FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND c.state='active')").bind(&tenant).bind(&device).fetch_optional(&mut *c).await?;
        if let Some(row)=&row {
            let registration:String=row.try_get("id")?;
            if !crate::device::store::task_capable(c,&tenant,&registration).await? {return Ok(None);}
        }
        Ok(row)
    })).await?.ok_or(Error::Conflict)?;
    Ok(Target {
        device: target_device,
        registration: corrupt(Uuid::parse_str(&row.try_get::<String, _>("id")?))?,
        generation: row.try_get("generation")?,
    })
}
pub(super) async fn load_plan(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Plan> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT document,author,author_approvals,reviewer,reviewer_approvals,active,scan_at,blocked_at FROM mdm_commands.action_plans WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
    Ok(Plan {
        id,
        frozen: corrupt(serde_json::from_value(row.try_get("document")?))?,
        author: corrupt(serde_json::from_value(row.try_get("author")?))?,
        author_approvals: corrupt(serde_json::from_value(row.try_get("author_approvals")?))?,
        reviewer: row
            .try_get::<Option<Value>, _>("reviewer")?
            .map(|v| corrupt(serde_json::from_value(v)))
            .transpose()?,
        reviewer_approvals: row
            .try_get::<Option<Value>, _>("reviewer_approvals")?
            .map(|v| corrupt(serde_json::from_value(v)))
            .transpose()?
            .unwrap_or_default(),
        active: row.try_get("active")?,
        scan_at: row.try_get("scan_at")?,
        blocked_at: row.try_get("blocked_at")?,
    })
}
pub(super) async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT plan::text,device,registration::text,generation,available_at,deadline,state,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
    Ok(Run {
        id,
        plan: corrupt(Uuid::parse_str(&row.try_get::<String, _>("plan")?))?,
        target: Target {
            device: row.try_get("device")?,
            registration: corrupt(Uuid::parse_str(&row.try_get::<String, _>("registration")?))?,
            generation: row.try_get("generation")?,
        },
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: corrupt(serde_json::from_value(row.try_get("state")?))?,
        result: row.try_get("result")?,
    })
}
pub(super) async fn valid(
    tx: &mut PgTransaction<'_>,
    plan: &Plan,
    device: &str,
    now: i64,
) -> Result<bool> {
    if !plan.active
        || plan.reviewer.is_none()
        || plan.reviewer.as_ref() == Some(&plan.author)
        || now >= plan.frozen.input.schedule.until
    {
        return Ok(false);
    }
    let Some(index) = plan.frozen.input.devices.iter().position(|t| t == device) else {
        return Ok(false);
    };
    let (Some(author), Some(reviewer)) = (
        plan.author_approvals.get(index),
        plan.reviewer_approvals.get(index),
    ) else {
        return Ok(false);
    };
    let author = author.clone();
    let reviewer = reviewer.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(async {
                    Ok::<_, Error>(
                        author.valid(c, Permission::ScriptExecute, now).await?
                            && reviewer.valid(c, Permission::ScriptApprove, now).await?,
                    )
                }
                .await)
            })
        })
        .await??)
}
pub(super) async fn save_run(tx: &mut PgTransaction<'_>, run: &Run) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id.to_string();
    let state = invalid(serde_json::to_value(&run.state))?;
    let result = run.result.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id).bind(state).bind(result).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub(super) async fn replay(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    storage::lock(tx, &format!("action-request:{actor}:{id}")).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_optional(c).await})).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub(super) async fn receipt(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_receipts(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3::uuid,$4,$5)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).execute(c).await?;Ok(())})).await?;
    Ok(())
}
