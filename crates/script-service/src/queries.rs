//! Bounded Script history reads; summary types contain no output or diagnostic streams.
use crate::{Error, Result};
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record<R> {
    pub task_id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub device: String,
    pub registration_id: Uuid,
    pub generation: i64,
    pub occurrence: String,
    pub available_at: i64,
    pub deadline: i64,
    pub resource_id: String,
    pub state: rss_mdm_task_state::RunState,
    pub authorization: Option<w::TaskAuthorization>,
    pub attempt_id: Option<Uuid>,
    pub result: Option<R>,
}
pub type Summary = Record<ScriptSummary>;
pub type Detail = Record<w::ScriptRunResult>;
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptSummary {
    collected_at: i64,
    received_at: i64,
    exit_code: Option<i32>,
    quality: w::OutputQuality,
    schema_valid: bool,
    budget_valid: bool,
    output_reference: Option<w::ScriptOutputReference>,
    diagnostics: Diagnostics,
    trusted: bool,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Diagnostics {
    duration_ms: u64,
    executed_at: i64,
    failure: Option<w::TaskFailure>,
}
const METADATA: &str = "'taskId',r.id,'policyId',v.policy,'versionId',v.id,'device',r.device,'registrationId',r.registration,'generation',r.generation,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'resourceId',r.resource_id,'state',r.state,'authorization',r.invocation->'authorization','attemptId',r.state->'delivery'->>'attempt'";
pub async fn page_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    after: Option<(i64, Uuid)>,
    limit: usize,
) -> Result<Vec<Summary>> {
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query.push(METADATA).push(",'result',CASE WHEN r.result IS NULL THEN NULL ELSE (r.result-'output') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END) FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5");
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
        .map(|v| crate::stored(serde_json::from_value(v)))
        .collect()
}
pub async fn detail_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    id: Uuid,
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
) -> Result<Detail> {
    let row:Option<(String,bool)>=sqlx::query_as("SELECT r.device,(v.frozen->'action'->'collection') IS NOT NULL AND v.frozen->'action'->'collection'<>'null'::jsonb FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3").bind(tenant).bind(policy).bind(id).fetch_optional(&mut *c).await?;
    let (device, collection) = row.ok_or(Error::NotFound)?;
    grant.require(proof, Permission::OperationRead, Some(&device))?;
    if collection {
        grant.require(proof, Permission::InventoryRead, Some(&device))?;
        grant.require(proof, Permission::InventorySensitiveRead, None)?;
    }
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query.push(METADATA).push(",'result',r.result) FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3");
    crate::stored(serde_json::from_value(
        query
            .build_query_scalar::<serde_json::Value>()
            .bind(tenant)
            .bind(policy)
            .bind(id)
            .fetch_one(c)
            .await?,
    ))
}

/// Correlate only original registration/generation coordinates, including declared Windows children.
pub async fn assignment_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    channel: rss_mdm_inventory::Channel,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT r.id FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND $6='agent' AND ((r.registration=$4 AND r.generation=$5) OR ($6='mdm' AND EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=r.tenant_id AND child.id=r.registration AND child.generation=r.generation AND child.device=r.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5))) ORDER BY r.id").bind(tenant.to_string()).bind(policy).bind(&target.device).bind(target.registration_id).bind(target.generation).bind(channel.as_str()).fetch_all(c).await?)
}
