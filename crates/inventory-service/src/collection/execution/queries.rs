//! Collection task history separates Agent execution, report intake and projection work.
use crate::{Error, transaction::Result};
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub task_id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub occurrence: String,
    pub available_at: i64,
    pub deadline: i64,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRecord<R> {
    #[serde(flatten)]
    pub metadata: Metadata,
    pub state: rss_mdm_task_state::RunState,
    pub attempt_id: Option<Uuid>,
    pub result: Option<R>,
    /// Intake quality is independent of whether Inventory has applied the report to assets.
    pub report: Option<Report>,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeRecord {
    #[serde(flatten)]
    pub metadata: Metadata,
    pub delivery: super::model::NativeDelivery,
    pub report: Option<Report>,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub id: Uuid,
    pub result: String,
    pub reason: Option<String>,
    pub sealed_at: Option<i64>,
    pub projection_pending: bool,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSummary {
    queries: std::collections::BTreeMap<String, super::result::NativeQuerySummary>,
    plan_digest: [u8; 32],
    output_reference: rss_mdm_agent_wire::runtime::ScriptOutputReference,
    trusted: bool,
    received_at: i64,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "channel", rename_all = "snake_case")]
pub enum Record<R> {
    Agent(AgentRecord<R>),
    Mdm(NativeRecord),
}
pub type Summary = Record<AgentSummary>;
pub type Detail = Record<super::result::AgentCollection>;
impl<R> Record<R> {
    pub fn metadata(&self) -> &Metadata {
        match self {
            Self::Agent(r) => &r.metadata,
            Self::Mdm(r) => &r.metadata,
        }
    }
}
const METADATA: &str = "'taskId',r.id,'policyId',v.policy,'versionId',v.id,'device',r.device,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline";
const REPORT: &str = "CASE WHEN report.id IS NULL THEN NULL ELSE jsonb_build_object('id',report.id,'result',report.result,'reason',report.reason,'sealedAt',report.sealed_at,'projectionPending',report.delivery_pending) END";
fn select(summary: bool) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut query = sqlx::QueryBuilder::new("SELECT jsonb_build_object(");
    query.push(METADATA).push(",'channel',r.channel,'report',").push(REPORT).push(") || CASE WHEN r.channel='agent' THEN jsonb_build_object('state',r.agent_state,'attemptId',r.agent_state->'delivery'->>'attempt','result',").push(if summary {"r.agent_result-'native'"}else{"r.agent_result"}).push(") ELSE jsonb_build_object('delivery',r.native_delivery) END AS document FROM mdm_inventory.collection_tasks r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN mdm_access.collection_runs report ON report.tenant_id=r.tenant_id AND report.device=r.device AND report.id=CASE WHEN r.channel='agent' THEN (r.agent_state->'delivery'->>'attempt')::uuid ELSE r.collection_run END WHERE r.tenant_id=$1::uuid");
    query
}
pub async fn page_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    after: Option<(i64, Uuid)>,
    limit: usize,
) -> Result<Vec<Summary>> {
    select(true).push(" AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5").build_query_scalar::<serde_json::Value>().bind(tenant).bind(policy).bind(after.map(|p|p.0)).bind(after.map(|p|p.1)).bind(limit as i64).fetch_all(c).await?.into_iter().map(|v|crate::transaction::stored(serde_json::from_value(v))).collect()
}
pub async fn detail_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    id: Uuid,
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
) -> Result<Detail> {
    let target:Option<(Uuid,bool)>=sqlx::query_as("SELECT r.device,r.channel='agent' FROM mdm_inventory.collection_tasks r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3").bind(tenant).bind(policy).bind(id).fetch_optional(&mut *c).await?;
    let (device, raw_evidence) = target.ok_or(Error::NotFound)?;
    let device = crate::database::device_id(device)?;
    grant.require(proof, Permission::OperationRead, Some(&device))?;
    grant.require(proof, Permission::InventoryRead, Some(&device))?;
    if raw_evidence {
        grant.require(proof, Permission::InventorySensitiveRead, None)?;
    }
    let mut record: Detail = crate::transaction::stored(serde_json::from_value(
        select(false)
            .push(" AND v.policy=$2 AND r.id=$3")
            .build_query_scalar::<serde_json::Value>()
            .bind(tenant)
            .bind(policy)
            .bind(id)
            .fetch_one(&mut *c)
            .await?,
    ))?;
    if let Record::Agent(agent) = &mut record
        && let Some(result) = &mut agent.result
        && result.native.is_none()
    {
        result.native = Some(
            super::output::restore_on(
                c,
                tenant,
                agent.attempt_id.ok_or(Error::Conflict)?,
                &result.output_reference,
            )
            .await?,
        );
    }
    Ok(record)
}

/// Latest historical run for the original device and channel.
pub async fn latest_assignment_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    channel: rss_mdm_inventory::Channel,
) -> Result<Option<Summary>> {
    select(true).push(" AND v.policy=$2 AND r.device=$3 AND r.channel=$4 ORDER BY r.available_at DESC,r.id DESC LIMIT 1")
        .build_query_scalar::<serde_json::Value>().bind(tenant.to_string()).bind(policy).bind(target.device.into_uuid())
        .bind(channel.as_str()).fetch_optional(c).await?
        .map(|v|crate::transaction::stored(serde_json::from_value(v))).transpose()
}
/// SQL counterpart of model::native_terminal_status; T2 compares their complete truth table.
pub const NATIVE_STATUS_SQL: &str = "CASE WHEN report.sealed_at IS NULL THEN r.native_delivery WHEN report.reason='complete' THEN CASE WHEN report.result='failed' THEN 'failed' ELSE 'succeeded' END WHEN report.reason='timeout' THEN 'expired' ELSE 'cancelled' END";
pub fn relation_sql() -> String {
    format!(
        "SELECT r.id,r.device,'action_run'::text AS kind,'policy'::text AS source_kind,r.policy_version,v.policy,r.deadline,CASE WHEN r.channel='agent' THEN r.agent_state->>'execution' ELSE {NATIVE_STATUS_SQL} END AS status,0::bigint AS input_bytes FROM mdm_inventory.collection_tasks r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN mdm_access.collection_runs report ON report.tenant_id=r.tenant_id AND report.device=r.device AND report.id=r.collection_run WHERE r.tenant_id=$1::uuid"
    )
}

/// Bounded, redacted evidence for directory rows already selected under device authorization.
pub async fn run_summaries_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: Vec<Uuid>,
) -> Result<std::collections::BTreeMap<Uuid, Summary>> {
    use sqlx::Row;
    if ids.is_empty() {
        return Ok(Default::default());
    }
    if ids.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let expected = ids.len();
    let mut selected = select(true);
    selected.push(" AND r.id=ANY($2)");
    let mut query = sqlx::QueryBuilder::new("WITH selected AS MATERIALIZED (");
    query.push(selected.sql().as_str()).push("),budget AS(SELECT coalesce(sum(octet_length(document::text)),0)::bigint AS bytes FROM selected) SELECT document,bytes FROM budget LEFT JOIN selected ON bytes<=16777216");
    let rows = query
        .build()
        .bind(tenant.to_string())
        .bind(ids)
        .fetch_all(c)
        .await?;
    let bytes: i64 = rows.first().ok_or(Error::Conflict)?.try_get("bytes")?;
    if !(0..=16 * 1024 * 1024).contains(&bytes) {
        return Err(Error::Unavailable(crate::Failure::Capacity).into());
    }
    if rows.len() != expected {
        return Err(Error::Conflict.into());
    }
    rows.into_iter()
        .map(|r| {
            let summary: Summary =
                crate::transaction::stored(serde_json::from_value(r.try_get("document")?))?;
            let id = summary.metadata().task_id;
            Ok((id, summary))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn summaries_reject_native_values_and_round_trip_both_collection_channels() {
        let value = json!({"queries":{},"planDigest":vec![1;32],"outputReference":{"bytes":5,"sha256":"digest"},"trusted":true,"receivedAt":1});
        let result: AgentSummary = serde_json::from_value(value.clone()).unwrap();
        let output = serde_json::to_value(result).unwrap();
        assert!(output.get("native").is_none());
        let mut private = value.clone();
        private["native"] = json!({"private":"device-data"});
        assert!(serde_json::from_value::<AgentSummary>(private).is_err());
        assert!(
            serde_json::from_value::<AgentSummary>(
                json!({"nested":[{"native":{"secret":"value"}}]})
            )
            .is_err()
        );
        let id = Uuid::new_v4();
        let common = json!({"taskId":id,"policyId":id,"versionId":id,"device":id,"occurrence":"once","availableAt":1,"deadline":100,"report":null});
        let mut agent = common.clone();
        agent["channel"] = json!("agent");
        agent["state"] =
            serde_json::to_value(rss_mdm_task_state::RunState::new(100, 1).unwrap()).unwrap();
        agent["attemptId"] = json!(null);
        agent["result"] = value;
        let mut native = common;
        native["channel"] = json!("mdm");
        native["delivery"] = json!("sent");
        for record in [agent, native] {
            let typed: Summary = serde_json::from_value(record.clone()).unwrap();
            assert_eq!(serde_json::to_value(typed).unwrap(), record);
        }
    }
}
