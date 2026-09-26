use super::model::*;
use crate::action_admission as storage;
use crate::transaction::{Result, checked_input, stored};
use crate::{
    Error,
    authorization::{Approval, Permission, User},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;
pub(crate) struct Plan {
    pub id: Uuid,
    pub frozen: Frozen,
    pub author: User,
    pub author_approvals: Vec<Approval>,
    pub reviewer: Option<User>,
    pub reviewer_approvals: Vec<Approval>,
    pub active: bool,
}
pub(crate) async fn load_plan(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Plan> {
    // This lock is shared by every plan mutation and action transition. Readers need no SQL UPDATE privilege.
    storage::lock(tx, "action-owner").await?;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT document,author,author_approvals,reviewer,reviewer_approvals,active FROM mdm_planning.action_plans WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Action)))?;
    Ok(Plan {
        id,
        frozen: stored(serde_json::from_value(row.try_get("document")?))?,
        author: stored(serde_json::from_value(row.try_get("author")?))?,
        author_approvals: stored(serde_json::from_value(row.try_get("author_approvals")?))?,
        reviewer: row
            .try_get::<Option<Value>, _>("reviewer")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
        reviewer_approvals: row
            .try_get::<Option<Value>, _>("reviewer_approvals")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?
            .unwrap_or_default(),
        active: row.try_get("active")?,
    })
}
pub(crate) async fn valid(
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
    let Some(index) = plan.frozen.targets.devices.iter().position(|t| t == device) else {
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
pub(crate) async fn replay(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    storage::lock(tx, &format!("action-request:{actor}:{id}")).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT fingerprint,response FROM mdm_planning.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3::uuid").bind(tenant).bind(actor).bind(id.to_string()).fetch_optional(c).await})).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub(crate) async fn receipt(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.action_receipts(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3::uuid,$4,$5)").bind(tenant).bind(actor).bind(id.to_string()).bind(fingerprint).bind(response).execute(c).await?;Ok(())})).await?;
    Ok(())
}

pub(super) async fn insert_plan_in(
    tx: &mut PgTransaction<'_>,
    frozen: &Frozen,
    author: &User,
    approvals: &[Approval],
    hash: &[u8],
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let document = checked_input(serde_json::to_value(frozen))?;
    let author = checked_input(serde_json::to_value(author))?;
    let approvals = checked_input(serde_json::to_value(approvals))?;
    let digest = hash.to_vec();
    let id = frozen.input.operation_id.to_string();
    let resource = frozen.input.resource.clone();
    let version = frozen.input.version.clone();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.action_plans(tenant_id,id,resource,version,document,fingerprint,author,author_approvals) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)").bind(tenant).bind(id).bind(resource).bind(version).bind(document).bind(digest).bind(author).bind(approvals).execute(c).await?;Ok(())})).await?;
    Ok(())
}
