//! Enrollment history and current admission, evaluated on the caller's read snapshot.
use super::{Error, Materials, Result};
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
    pub occurrence: String,
    pub available_at: i64,
    pub deadline: i64,
    pub state: rss_mdm_task_state::RunState,
    pub authorization: Option<w::TaskAuthorization>,
    pub attempt_id: Option<Uuid>,
    pub result: Option<w::EnrollmentEntryOutcome>,
}
const METADATA: &str = "'taskId',r.id,'policyId',v.policy,'versionId',v.id,'device',r.device,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'authorization',r.invocation->'authorization','attemptId',r.state->'delivery'->>'attempt'";
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
        .push(crate::storage_profile::sql(profile).enrollment_tasks_queries_page_on_1);
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
    if profile != proof.profile() {
        return Err(crate::Error::Forbidden.into());
    }

    let device: Option<String> = sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_tasks_queries_detail_on_1,
    )
    .bind(tenant)
    .bind(policy)
    .bind(id)
    .fetch_optional(&mut *c)
    .await?;
    grant.require(
        proof,
        Permission::OperationRead,
        Some(&device.ok_or(Error::NotFound)?),
    )?;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object(");
    query
        .push(METADATA)
        .push(crate::storage_profile::sql(profile).enrollment_tasks_queries_detail_on_2);
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

/// Correlate only the original device identity.
pub async fn assignment_ids_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    target: &crate::device::endpoints::PrimaryRegistration,
    channel: rss_mdm_inventory::Channel,
) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_tasks_queries_assignment_ids_on_1,
    )
    .bind(tenant.to_string())
    .bind(policy)
    .bind(&target.device)
    .bind(&target.device)
    .bind(channel.as_str())
    .fetch_all(c)
    .await?)
}

pub async fn state_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    materials: &Materials,
    device: &str,
    frozen: &crate::enrollment::task::FrozenEnrollment,
    now: i64,
) -> Result<rss_mdm_policy::pages::TaskAdmission> {
    use rss_mdm_policy::pages::{TaskAdmission as Admission, TaskAdmissionState as State};
    if now < frozen.schedule.not_before || now >= frozen.schedule.ends_at() {
        return Ok(Admission::new(State::OutsideWindow, None));
    }
    let targets = super::agent_facts::agent_targets_on(
        profile,
        c,
        tenant,
        materials.agent_store.clone(),
        vec![device.to_owned()],
    )
    .await?;
    let target = match targets.as_slice() {
        [] => return Ok(Admission::new(State::MissingRegistration, None)),
        [target] => target,
        _ => return Ok(Admission::new(State::AmbiguousRegistration, None)),
    };
    let platform = match target.binding.platform.as_str() {
        "windows" => rss_mdm_policy::Platform::Windows,
        "macos" => rss_mdm_policy::Platform::Macos,
        _ => return Ok(Admission::new(State::UnsupportedCapability, None)),
    };
    if !target.binding.inventory()
        || !target.binding.enrollment()
        || frozen.entries.for_platform(platform).is_none()
    {
        return Ok(Admission::new(State::UnsupportedCapability, None));
    }
    let state = match materials
        .inventory
        .enrollment_on(c, tenant, target.device.clone())
        .await?
    {
        rss_mdm_inventory::channel::Observation::ProjectionPending { .. } => {
            State::ProjectionPending
        }
        rss_mdm_inventory::channel::Observation::Unavailable => State::ChannelUnknown,
        rss_mdm_inventory::channel::Observation::Ready(fact) => match fact.state.as_str() {
            "unenrolled" => State::Eligible,
            "this_organization" => State::AlreadySatisfied,
            "other_organization" => State::OrganizationConflict,
            _ => State::ChannelUnknown,
        },
    };
    Ok(Admission::new(state, None))
}
pub async fn assignment_state_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    materials: &Materials,
    policy: &rss_mdm_policy::Policy,
    device: &str,
    now: i64,
) -> Result<rss_mdm_policy::pages::TaskAdmission> {
    let value: serde_json::Value = sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_tasks_queries_assignment_state_on_1,
    )
    .bind(tenant.to_string())
    .bind(policy.version)
    .fetch_one(&mut *c)
    .await?;
    let super::policy::Published::Enrollment { action } =
        super::stored(serde_json::from_value(value))?;
    state_on(profile, c, tenant, materials, device, &action, now).await
}

pub const RELATION_SQL: &str = "SELECT r.id, r.device, CAST('action_run' AS text) AS kind, CAST('policy' AS text) AS source_kind, r.policy_version, v.policy, r.deadline, COALESCE(r.state ->> 'execution', 'unknown') AS status, CAST(0 AS bigint) AS input_bytes FROM mdm_registration_tasks.runs AS r INNER JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (r.tenant_id, r.policy_version) WHERE r.tenant_id = CAST($1 AS uuid)";
