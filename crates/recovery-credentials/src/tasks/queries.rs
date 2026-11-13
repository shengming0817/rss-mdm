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
    pub device: rss_mdm_agent_wire::DeviceId,
    pub occurrence: String,
    pub available_at: i64,
    pub deadline: i64,
    pub state: rss_mdm_task_state::RunState,
    pub authorization: Option<w::TaskAuthorization>,
    pub attempt_id: Option<Uuid>,
    pub result: Option<super::actions::result::RunResult>,
}
const METADATA: &str = "'taskId',r.id,'policyId',v.policy,'versionId',v.id,'device',r.device,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'authorization',NULL::jsonb,'attemptId',r.state->'delivery'->>'attempt'";
pub async fn page_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    after: Option<(i64, Uuid)>,
    limit: usize,
) -> Result<Vec<Record>> {
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query
        .push(METADATA)
        .push(crate::storage_profile::sql(profile).tasks_queries_page_on_1);
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    policy: Uuid,
    id: Uuid,
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
) -> Result<Record> {
    let device: Option<rss_mdm_agent_wire::DeviceId> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).tasks_queries_detail_on_1)
            .bind(tenant)
            .bind(policy)
            .bind(id)
            .fetch_optional(&mut *c)
            .await
            .and_then(|id| id.map(crate::storage::device_id).transpose())?;
    grant.require(
        proof,
        Permission::OperationRead,
        Some(&device.ok_or(Error::NotFound)?),
    )?;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query
        .push(METADATA)
        .push(crate::storage_profile::sql(profile).tasks_queries_detail_on_2);
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
/// Exact task lookup for diagnostics, retaining the owner's existing bounded projection.
pub async fn diagnostic_on(
    c: &mut sqlx::PgConnection,
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
    locator: &rss_mdm_audit_integration::operation::OperationLocator,
) -> Result<Option<Record>> {
    if locator.product != proof.profile()
        || locator.owner != rss_mdm_audit_integration::operation::OperationOwner::CredentialTask
    {
        return Err(Error::Forbidden.into());
    }
    let device = locator.device.as_ref().ok_or(Error::Malformed)?;
    grant.require(proof, Permission::OperationRead, Some(device))?;
    let relation = match proof.profile() {
        rss_mdm_install_support::StorageProfile::Mdm => RELATION_SQL,
        rss_mdm_install_support::StorageProfile::Da => DA_RELATION_SQL,
    };
    let mut sql = sqlx::QueryBuilder::<sqlx::Postgres>::new("WITH owned AS (");
    sql.push(relation)
        .push(") SELECT policy FROM owned WHERE id=$2 AND device=$3");
    let policy: Option<Uuid> = sql
        .build_query_scalar()
        .bind(proof.tenant_id())
        .bind(locator.operation_id)
        .bind(device.into_uuid())
        .fetch_optional(&mut *c)
        .await?;
    match policy {
        Some(policy) => detail_on(
            proof.profile(),
            c,
            proof.tenant_id(),
            policy,
            locator.operation_id,
            proof,
            grant,
        )
        .await
        .map(Some),
        None => Ok(None),
    }
}

/// Correlate only the original Agent device.
pub async fn assignment_ids_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    channel: rss_mdm_inventory::Channel,
) -> Result<Vec<Uuid>> {
    Ok(
        sqlx::query_scalar(crate::storage_profile::sql(profile).tasks_queries_assignment_ids_on_1)
            .bind(tenant.to_string())
            .bind(policy)
            .bind(target.device.into_uuid())
            .bind(channel.as_str())
            .fetch_all(c)
            .await?,
    )
}

pub const RELATION_SQL: &str = "SELECT r.id,r.device,'action_run'::text AS kind,'policy'::text AS source_kind,r.policy_version,v.policy,r.deadline,coalesce(r.state->>'execution','unknown') AS status,0::bigint AS input_bytes FROM mdm_recovery_tasks.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid";

pub const DA_RELATION_SQL: &str = "SELECT r.id,r.device,'action_run'::text AS kind,'policy'::text AS source_kind,r.policy_version,v.policy,r.deadline,coalesce(r.state->>'execution','unknown') AS status,0::bigint AS input_bytes FROM rss_da.credential_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid";
