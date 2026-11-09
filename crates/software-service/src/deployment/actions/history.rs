//! Bounded run summaries and separately authorized full execution evidence.
use crate::deployment::queries::Queries;
use crate::deployment::{
    Error, authorization::Permission, authorization::context::AuthorizedPrincipal,
};
use rss_mdm_audit_integration::RequestAudit;
use serde_json::{Value, json};
use uuid::Uuid;

pub const RESULT_SUMMARY_SQL: &str = "CASE WHEN r.result IS NULL THEN NULL WHEN r.result->'evidence' IS NOT NULL THEN jsonb_set(r.result,'{evidence,steps}',(SELECT jsonb_agg(value || jsonb_build_object('diagnostics',(value->'diagnostics')-'stdout'-'stderr') ORDER BY position) FROM jsonb_array_elements(r.result#>'{evidence,steps}') WITH ORDINALITY AS item(value,position))) ELSE (r.result-'output'-'native') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END";

impl Queries {
    pub async fn software_rollout(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<crate::deployment::queries::records::Rollout, crate::deployment::queries::QueryError>
    {
        self.snapshot(proof,(self,proof,id,audit),|ctx,c,basis|Box::pin(async move {
            let (service,proof,id,_audit)=*ctx;
            let current=&basis.grant;
            current.require(proof,Permission::PolicyRead,None)?;
            current.require_all_devices(proof,Permission::OperationRead)?;
            let policy=crate::deployment::sources::storage::read_on(&service.policy_reader,c,id).await?.ok_or(Error::Execution(crate::deployment::missing::ExecutionError::MissingTask))?;
            let software=crate::deployment::sources::software::read_on(&service.policy_reader,c,policy.version).await?;
            let now=basis.now;
            let mut stages=Vec::new();
            let mut prior=(0,0);
            let mut prior_ready=true;
            for (index,stage) in software.assignment.stages().iter().enumerate() {
                let counts=software.assignment.counts_on(service.source.as_ref(),c,service.tenant,index).await?;
                stages.push(json!({"id":stage.id,"scope":stage.scope,"opensAt":stage.opens_at,
                    "minimumVerifiedPercent":stage.minimum_verified_percent,
                    "open":policy.state.is_enabled() && (stage.minimum_verified_percent.is_none() || prior_ready) && stage.open(now,prior.0,prior.1),
                    "ready":counts.ready,"asOf":counts.as_of,
                    "totalTargets":counts.total,"reported":counts.reported,
                    "unknown":counts.unknown,"waitingUser":counts.waiting_user,"waitingReboot":counts.waiting_reboot,"failed":counts.failed,"verifiedSuccess":counts.verified,
                    "unsupportedCapability":counts.unsupported_capability}));
                prior=(counts.total,counts.verified);
                prior_ready=counts.ready;
            }

            crate::deployment::queries::records::decode(json!({"policyId":id,"versionId":policy.version,"paused":!policy.state.is_enabled(),"asOf":now,"stages":stages}))
        })).await.map_err(Into::into)
    }
    /// Bounded remaining-owner facts on the application's authorized read snapshot.
    pub async fn run_page_on(
        &self,
        c: &mut sqlx::PgConnection,
        policy: Uuid,
        after: Option<(i64, Uuid)>,
        limit: usize,
        now: i64,
    ) -> crate::deployment::Result<Vec<crate::deployment::queries::records::RunSummary>> {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT jsonb_build_object('taskId',r.id,'authorization',r.invocation->'authorization','attemptId',r.state->'delivery'->>'attempt','device',r.device,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'userAction',CASE WHEN v.frozen->>'kind'='software' AND v.frozen->'action'->>'intent'='available_install' AND r.state->>'execution'='not_started' AND r.state->>'cancellation'='none' AND r.state->'delivery'->>'kind' IN ('claimed','received') AND (r.state->'delivery'->>'leaseUntil')::bigint>$5 THEN 'waiting_user' ELSE NULL END,'result',",
        );
        query.push(RESULT_SUMMARY_SQL).push(") FROM mdm_software_deployment.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $6");
        query
            .build_query_scalar::<Value>()
            .bind(self.tenant.to_string())
            .bind(policy)
            .bind(after.map(|v| v.0))
            .bind(after.map(|v| v.1))
            .bind(now)
            .bind(limit as i64)
            .fetch_all(c)
            .await?
            .into_iter()
            .map(crate::deployment::queries::records::decode)
            .collect()
    }
    /// Full evidence is authorized for its original device, independent of today's Policy kind.
    pub async fn run_detail_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &crate::deployment::authorization::Snapshot,
        policy: Uuid,
        id: Uuid,
        now: i64,
    ) -> crate::deployment::Result<crate::deployment::queries::records::RunDetail> {
        use sqlx::Row;
        let row=sqlx::query("SELECT r.device,r.state,v.frozen FROM mdm_software_deployment.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3").bind(self.tenant.to_string()).bind(policy).bind(id).fetch_optional(&mut *c).await?.ok_or(Error::Execution(crate::deployment::missing::ExecutionError::MissingTask))?;
        let device: String = row.try_get("device")?;
        grant.require(proof, Permission::OperationRead, Some(&device))?;
        let state: rss_mdm_task_state::RunState =
            crate::deployment::stored(serde_json::from_value(row.try_get("state")?))?;
        let frozen: crate::deployment::frozen::Published =
            crate::deployment::stored(serde_json::from_value(row.try_get("frozen")?))?;
        let user_action=matches!(&frozen,crate::deployment::frozen::Published::Software{action} if action.intent==rss_mdm_policy::SoftwareIntent::AvailableInstall).then(||state.awaits_user(now)).filter(|v|*v).map(|_|"waiting_user");
        let nodes = if let Some(attempt) = state.attempt() {
            if matches!(&frozen,crate::deployment::frozen::Published::Software{action} if action.channel==rss_mdm_policy::SoftwareChannel::Agent)
            {
                let payload = self
                    .agent_store
                    .payload(c, self.tenant.to_string(), id, attempt)
                    .await?;
                let super::evidence::Material::Software { steps, .. } =
                    super::evidence::Material::from_payload(&payload).ok_or(Error::Conflict)?;
                steps
                    .into_iter()
                    .map(|step| json!({"stepId":step.step_id,"definition":step.definition}))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        } else {
            vec![]
        };
        let mut value:Value=sqlx::query_scalar("SELECT jsonb_build_object('taskId', r.id, 'authorization', r.invocation -> 'authorization', 'attemptId', r.state -> 'delivery' ->> 'attempt', 'device', r.device, 'availableAt', r.available_at, 'deadline', r.deadline, 'state', r.state, 'effect', COALESCE(r.result ->> 'effect', 'unverified'), 'result', r.result) FROM mdm_software_deployment.action_runs AS r WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2").bind(self.tenant.to_string()).bind(id).fetch_one(c).await?;
        value["nodes"] = json!(nodes);
        value["policyId"] = json!(policy);
        value["userAction"] = json!(user_action);
        crate::deployment::queries::records::decode(value)
    }
}
