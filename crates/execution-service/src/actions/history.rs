//! Bounded run summaries and separately authorized full execution evidence.
use crate::queries::Queries;
use crate::{Error, authorization::Permission, authorization::context::AuthorizedPrincipal};
use serde_json::{Value, json};
use uuid::Uuid;

pub const RESULT_SUMMARY_SQL: &str = "CASE WHEN r.result IS NULL THEN NULL WHEN r.result->'evidence' IS NOT NULL THEN jsonb_set(r.result,'{evidence,steps}',(SELECT jsonb_agg(value || jsonb_build_object('diagnostics',(value->'diagnostics')-'stdout'-'stderr') ORDER BY position) FROM jsonb_array_elements(r.result#>'{evidence,steps}') WITH ORDINALITY AS item(value,position))) ELSE (r.result-'output'-'native') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END";

impl Queries {
    /// Bounded remaining-owner facts on the application's authorized read snapshot.
    pub async fn run_page_on(
        &self,
        c: &mut sqlx::PgConnection,
        policy: Uuid,
        after: Option<(i64, Uuid)>,
        limit: usize,
        _now: i64,
    ) -> crate::Result<Vec<crate::queries::records::RunSummary>> {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT jsonb_build_object('taskId',r.id,'attemptId',r.state->'delivery'->>'attempt','device',r.device,'registrationId',r.registration,'generation',r.generation,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'userAction',NULL,'result',",
        );
        query.push(RESULT_SUMMARY_SQL).push(") FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5");
        query
            .build_query_scalar::<Value>()
            .bind(self.tenant.to_string())
            .bind(policy)
            .bind(after.map(|v| v.0))
            .bind(after.map(|v| v.1))
            .bind(limit as i64)
            .fetch_all(c)
            .await?
            .into_iter()
            .map(crate::queries::records::decode)
            .collect()
    }
    /// Full evidence is authorized for its original device, independent of today's Policy kind.
    pub async fn run_detail_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &crate::authorization::Snapshot,
        policy: Uuid,
        id: Uuid,
        _now: i64,
    ) -> crate::Result<crate::queries::records::RunDetail> {
        use sqlx::Row;
        let row=sqlx::query("SELECT r.device,r.state,v.frozen FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3").bind(self.tenant.to_string()).bind(policy).bind(id).fetch_optional(&mut *c).await?.ok_or(Error::Execution(crate::missing::ExecutionError::MissingTask))?;
        let device: String = row.try_get("device")?;
        grant.require(proof, Permission::OperationRead, Some(&device))?;
        let _state: rss_mdm_task_state::RunState =
            crate::stored(serde_json::from_value(row.try_get("state")?))?;
        let _frozen: crate::frozen::Frozen =
            crate::stored(serde_json::from_value(row.try_get("frozen")?))?;
        let mut value:Value=sqlx::query_scalar("SELECT jsonb_build_object('taskId',r.id,'attemptId',r.state->'delivery'->>'attempt','device',r.device,'registrationId',r.registration,'generation',r.generation,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'result',r.result) FROM mdm_commands.action_runs r WHERE r.tenant_id=$1::uuid AND r.id=$2").bind(self.tenant.to_string()).bind(id).fetch_one(c).await?;
        value["policyId"] = json!(policy);
        value["userAction"] = Value::Null;
        crate::queries::records::decode(value)
    }
}
