//! Compliance run facts; all writes borrow the caller's connection.
use super::*;

pub struct Task<I> {
    pub input: I,
    pub completed: bool,
    pub failure: Option<String>,
    pub cursor: Option<String>,
    pub started: bool,
    pub detail: Option<Value>,
}
pub async fn read<I: DeserializeOwned>(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
) -> Result<Option<Task<I>>> {
    tenant(c, t).await?;
    let row = sqlx::query("SELECT input,completed,failure,cursor,started,detail FROM mdm_compliance.runs WHERE tenant_id=$1::uuid AND id=$2")
        .bind(t.to_string()).bind(id).fetch_optional(c).await?;
    row.map(|r| {
        Ok(Task {
            input: serde_json::from_value(r.try_get("input")?).map_err(|_| corrupt())?,
            completed: r.try_get("completed")?,
            failure: r.try_get("failure")?,
            cursor: r.try_get("cursor")?,
            started: r.try_get("started")?,
            detail: r.try_get("detail")?,
        })
    })
    .transpose()
}
pub async fn enqueue<I: Serialize>(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    rule: Uuid,
    revision: i64,
    input: &I,
) -> Result<()> {
    tenant(c, t).await?;
    if id.is_nil() || rule.is_nil() || revision < 1 {
        return Err(corrupt());
    }
    let input = serde_json::to_string(input).map_err(|_| corrupt())?;
    if input.len() > 1_048_576 {
        return Err(corrupt());
    }
    sqlx::query("INSERT INTO mdm_compliance.runs(tenant_id,id,rule_id,rule_revision,input) VALUES($1::uuid,$2,$3,$4,$5::jsonb)")
        .bind(t.to_string()).bind(id).bind(rule).bind(revision).bind(input).execute(c).await?;
    Ok(())
}
pub async fn finish(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    reason: Option<&str>,
) -> Result<bool> {
    tenant(c, t).await?;
    Ok(sqlx::query("UPDATE mdm_compliance.runs SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
        .bind(t.to_string()).bind(id).bind(reason).execute(c).await?.rows_affected()==1)
}
pub async fn cursor(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    cursor: Option<&str>,
) -> Result<()> {
    tenant(c, t).await?;
    if sqlx::query("UPDATE mdm_compliance.runs SET started=true,cursor=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
        .bind(t.to_string()).bind(id).bind(cursor).execute(c).await?.rows_affected()!=1 { return Err(corrupt()); }
    Ok(())
}
pub async fn detail(c: &mut PgConnection, t: TenantId, id: Uuid, detail: Value) -> Result<()> {
    tenant(c, t).await?;
    if sqlx::query("UPDATE mdm_compliance.runs SET detail=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
        .bind(t.to_string()).bind(id).bind(detail).execute(c).await?.rows_affected()!=1 { return Err(corrupt()); }
    Ok(())
}
pub struct HistoryRow {
    pub task: Uuid,
    pub evaluated_at: i64,
    pub document: String,
    pub failure: Option<String>,
}
pub async fn history(
    c: &mut PgConnection,
    t: TenantId,
    device: &str,
    bounds: (Option<i64>, Option<i64>),
    after: Option<(i64, Uuid)>,
    limit: usize,
) -> Result<Vec<HistoryRow>> {
    tenant(c, t).await?;
    if !(1..=1000).contains(&limit) {
        return Err(corrupt());
    }
    sqlx::query("SELECT r.task,r.evaluated_at,r.document::text,j.failure FROM mdm_compliance.results r JOIN mdm_compliance.runs j ON (j.tenant_id,j.id)=(r.tenant_id,r.task) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND j.completed AND ($3::bigint IS NULL OR r.evaluated_at>=$3) AND ($4::bigint IS NULL OR r.evaluated_at<=$4) AND ($5::bigint IS NULL OR (r.evaluated_at,r.task)<($5,$6::uuid)) ORDER BY r.evaluated_at DESC,r.task DESC LIMIT $7")
        .bind(t.to_string()).bind(device).bind(bounds.0).bind(bounds.1).bind(after.map(|a|a.0)).bind(after.map(|a|a.1)).bind((limit+1) as i64).fetch_all(c).await?
        .into_iter().map(|r|Ok(HistoryRow {task:r.try_get("task")?,evaluated_at:r.try_get("evaluated_at")?,document:r.try_get("document")?,failure:r.try_get("failure")?})).collect()
}

/// One fixed difference window with bounded event and rule fanout pages.
pub struct Dispatch {
    pub to_cut: Value,
    pub event_after: i64,
    pub through: i64,
    pub cursor: Option<String>,
}
pub async fn lock_dispatch(
    c: &mut PgConnection,
    t: TenantId,
    candidate: Value,
) -> Result<Option<Dispatch>> {
    tenant(c, t).await?;
    sqlx::query(
        "INSERT INTO mdm_compliance.dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(t.to_string())
    .execute(&mut *c)
    .await?;
    let (from_cut, to_cut, event_after, through, cursor): (Option<Value>, Option<Value>, i64, Option<i64>, Option<String>) =
        sqlx::query_as("SELECT from_cut,to_cut,event_after,page_through,cursor FROM mdm_compliance.dispatch WHERE tenant_id=$1::uuid FOR UPDATE")
        .bind(t.to_string()).fetch_one(&mut *c).await?;
    let to_cut = to_cut.unwrap_or(candidate);
    let through = match through {
        Some(value) => Some(value),
        None => sqlx::query_scalar("SELECT max(revision) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 AND mdm.asset_visible($3::jsonb,revision) AND NOT mdm.asset_visible($4::jsonb,revision) ORDER BY revision LIMIT 1000) page")
            .bind(t.to_string()).bind(event_after).bind(&to_cut).bind(from_cut).fetch_one(&mut *c).await?,
    };
    let Some(through) = through else {
        sqlx::query("UPDATE mdm_compliance.dispatch SET from_cut=$2,to_cut=NULL,event_after=0,page_through=NULL,cursor=NULL WHERE tenant_id=$1::uuid")
            .bind(t.to_string()).bind(to_cut).execute(c).await?;
        return Ok(None);
    };
    sqlx::query(
        "UPDATE mdm_compliance.dispatch SET to_cut=$2,page_through=$3 WHERE tenant_id=$1::uuid",
    )
    .bind(t.to_string())
    .bind(&to_cut)
    .bind(through)
    .execute(c)
    .await?;
    Ok(Some(Dispatch {
        to_cut,
        event_after,
        through,
        cursor,
    }))
}
pub async fn save_dispatch(
    c: &mut PgConnection,
    t: TenantId,
    page: &Dispatch,
    cursor: Option<&str>,
) -> Result<()> {
    tenant(c, t).await?;
    sqlx::query("UPDATE mdm_compliance.dispatch SET event_after=$2,page_through=$3,cursor=$4 WHERE tenant_id=$1::uuid")
        .bind(t.to_string()).bind(if cursor.is_none() { page.through } else { page.event_after })
        .bind(cursor.map(|_| page.through)).bind(cursor).execute(c).await?;
    Ok(())
}

/// Frozen input binding and version-specific scan state, owned by one unfinished run.
pub async fn evaluation(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
) -> Result<Option<(String, Vec<(String, Value)>)>> {
    tenant(c, t).await?;
    let binding: Option<String> = sqlx::query_scalar(
        "SELECT binding FROM mdm_compliance.evaluations WHERE tenant_id=$1::uuid AND task=$2",
    )
    .bind(t.to_string())
    .bind(id)
    .fetch_optional(&mut *c)
    .await?;
    let Some(binding) = binding else {
        return Ok(None);
    };
    let arrays=sqlx::query_as("SELECT version,state FROM mdm_compliance.evaluation_arrays WHERE tenant_id=$1::uuid AND task=$2 ORDER BY version").bind(t.to_string()).bind(id).fetch_all(c).await?;
    Ok(Some((binding, arrays)))
}
pub async fn save_evaluation(
    c: &mut PgConnection,
    t: TenantId,
    id: Uuid,
    binding: &str,
    arrays: Vec<(String, Value)>,
) -> Result<()> {
    tenant(c, t).await?;
    if sqlx::query("INSERT INTO mdm_compliance.evaluations(tenant_id,task,binding) SELECT $1::uuid,$2,$3 WHERE EXISTS(SELECT 1 FROM mdm_compliance.runs WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed) ON CONFLICT(tenant_id,task) DO UPDATE SET binding=EXCLUDED.binding WHERE evaluations.binding=EXCLUDED.binding")
        .bind(t.to_string()).bind(id).bind(binding).execute(&mut *c).await?.rows_affected()!=1 {return Err(corrupt());}
    for (version, state) in arrays {
        sqlx::query("INSERT INTO mdm_compliance.evaluation_arrays(tenant_id,task,version,state) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,task,version) DO UPDATE SET state=EXCLUDED.state WHERE evaluation_arrays.state IS DISTINCT FROM EXCLUDED.state").bind(t.to_string()).bind(id).bind(version).bind(state).execute(&mut *c).await?;
    }
    Ok(())
}
pub async fn clear_evaluation(c: &mut PgConnection, t: TenantId, id: Uuid) -> Result<()> {
    tenant(c, t).await?;
    sqlx::query("DELETE FROM mdm_compliance.evaluations WHERE tenant_id=$1::uuid AND task=$2")
        .bind(t.to_string())
        .bind(id)
        .execute(c)
        .await?;
    Ok(())
}

/// Read the Compliance owner's durable input lag and invalidation queue.
pub async fn inputs_pending(c: &mut PgConnection, t: TenantId) -> Result<bool> {
    tenant(c, t).await?;
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible((SELECT from_cut FROM mdm_compliance.dispatch WHERE tenant_id=$1::uuid),revision)) OR EXISTS(SELECT 1 FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND enabled AND desired IS NULL)")
        .bind(t.to_string()).fetch_one(c).await
}
