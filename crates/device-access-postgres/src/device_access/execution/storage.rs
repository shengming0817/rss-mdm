//! Access run state and its immutable binding snapshot share one owner and one transaction.
use super::*;
use rss_mdm_task_state::RunState;
use sqlx::Row;
pub struct Run {
    pub id: Uuid,
    pub policy_version: Uuid,
    pub target: Target,
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<rss_mdm_agent_wire::runtime::AccessResult>,
}
pub struct TaskIssue {
    pub run: Uuid,
    pub attempt: Uuid,
    pub permit: rss_mdm_agent_wire::runtime::TaskPermit,
    pub expiry: i64,
}
pub async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
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
pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, lock: bool) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        if lock { sqlx::query("SELECT id FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(&tenant).bind(id).fetch_optional(&mut *c).await?; }
        sqlx::query("SELECT * FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await
    })).await?.ok_or(Error::NotFound)?;
    Ok(Run {
        id,
        policy_version: row.try_get("policy_version")?,
        target: Target {
            device: row.try_get("device")?,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
        },
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        result: row
            .try_get::<Option<serde_json::Value>, _>("result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}
pub async fn save_run(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    run: &Run,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let state = stored(serde_json::to_value(&run.state))?;
    let result = run
        .result
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Invariant)?;
    let changed=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE rss_da.access_runs SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2 AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)").bind(tenant).bind(id).bind(state).bind(result).execute(c).await
    })).await?;
    if changed.rows_affected() > 0 {
        wake::run_in(reconcile, tx, id).await?;
    }
    Ok(())
}
pub async fn agent_profile_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<(rss_mdm_policy::Platform, rss_mdm_policy::Architecture)>> {
    Ok(
        agent_facts::agent_binding_in(tx, service.agent_store.clone(), registration)
            .await?
            .and_then(|b| {
                let platform = match b.platform.as_str() {
                    "windows" => rss_mdm_policy::Platform::Windows,
                    "macos" => rss_mdm_policy::Platform::Macos,
                    _ => return None,
                };
                let arch = match b.architecture.as_str() {
                    "x86_64" => rss_mdm_policy::Architecture::X86_64,
                    "aarch64" => rss_mdm_policy::Architecture::Aarch64,
                    _ => return None,
                };
                Some((platform, arch))
            }),
    )
}
pub async fn owned_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[Uuid],
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=ANY($2)")
        .bind(tenant.to_string())
        .bind(ids)
        .fetch_all(c)
        .await
}
pub async fn active_count_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running','unknown','waiting_reboot') AND (deadline>$3 OR state->>'startedAt' IS NOT NULL) AND state->>'cancellation'<>'confirmed'").bind(tenant.to_string()).bind(device).bind(now).fetch_one(c).await
}

pub async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    crate::device_access::execution::agent::lock_device(tx, device).await
}

pub async fn association_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<Option<(String, Option<Uuid>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT device,NULL::uuid FROM rss_da.access_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(c)
    .await
}
