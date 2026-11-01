//! Credential history evaluated on the caller's authorization snapshot.
use super::{Error, Result};
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub task_id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub device: String,
    pub registration_id: Uuid,
    pub generation: i64,
    pub occurrence: String,
    pub available_at: i64,
    pub deadline: i64,
    pub state: rss_mdm_task_state::RunState,
    pub authorization: Option<w::TaskAuthorization>,
    pub attempt_id: Option<Uuid>,
    pub result: Option<super::actions::result::RunResult>,
}
const METADATA: &str = "'taskId',r.id,'policyId',v.policy,'versionId',v.id,'device',r.device,'registrationId',r.registration,'generation',r.generation,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'authorization',NULL::jsonb,'attemptId',r.state->'delivery'->>'attempt'";
pub async fn page_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    after: Option<(i64, Uuid)>,
    limit: usize,
) -> Result<Vec<Record>> {
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query.push(METADATA).push(",'result',r.result) FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5");
    query
        .build_query_scalar::<serde_json::Value>()
        .bind(tenant)
        .bind(policy)
        .bind(after.map(|p| p.0))
        .bind(after.map(|p| p.1))
        .bind(limit as i64)
        .fetch_all(c)
        .await?
        .into_iter()
        .map(|v| super::stored(serde_json::from_value(v)))
        .collect()
}
pub async fn detail_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    id: Uuid,
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
) -> Result<Record> {
    let device:Option<String>=sqlx::query_scalar("SELECT r.device FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3").bind(tenant).bind(policy).bind(id).fetch_optional(&mut *c).await?;
    grant.require(
        proof,
        Permission::OperationRead,
        Some(&device.ok_or(Error::NotFound)?),
    )?;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query.push(METADATA).push(",'result',r.result) FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3");
    super::stored(serde_json::from_value(
        query
            .build_query_scalar::<serde_json::Value>()
            .bind(tenant)
            .bind(policy)
            .bind(id)
            .fetch_one(c)
            .await?,
    ))
}

/// Correlate only the original Agent registration and generation.
pub async fn assignment_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    channel: rss_mdm_inventory::Channel,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT r.id FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND $6='agent' AND r.registration=$4 AND r.generation=$5 ORDER BY r.id").bind(tenant.to_string()).bind(policy).bind(&target.device).bind(target.registration_id).bind(target.generation).bind(channel.as_str()).fetch_all(c).await?)
}

pub const RELATION_SQL: &str = "SELECT r.id,r.device,'action_run'::text AS kind,r.registration,r.generation,'policy'::text AS source_kind,r.policy_version,v.policy,r.deadline,coalesce(r.state->>'execution','unknown') AS status,0::bigint AS input_bytes FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid";
