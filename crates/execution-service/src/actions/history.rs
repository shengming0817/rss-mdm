//! Bounded run summaries and separately authorized full execution evidence.
use super::storage as db;
use crate::{Error, authorization::Permission, authorization::context::AuthorizedPrincipal};
use crate::{queries::Queries, storage};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub const RESULT_SUMMARY_SQL: &str = "CASE WHEN r.result IS NULL THEN NULL WHEN r.result->'evidence' IS NOT NULL THEN jsonb_set(r.result,'{evidence,steps}',(SELECT jsonb_agg(value || jsonb_build_object('diagnostics',(value->'diagnostics')-'stdout'-'stderr') ORDER BY position) FROM jsonb_array_elements(r.result#>'{evidence,steps}') WITH ORDINALITY AS item(value,position))) ELSE (r.result-'output'-'native') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END";

pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_runs",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "available_at DESC, task_id DESC",
    context: &[],
};
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    available_at: i64,
    task_id: Uuid,
}
impl Queries {
    pub async fn software_rollout(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<crate::queries::records::Rollout, crate::queries::QueryError> {
        crate::transaction::inspect(&self.runtime, self.tenant,(self,proof,id,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,id,_audit)=*ctx;
            let current=crate::action_admission::current(tx,proof).await?;
            current.require(proof,Permission::PolicyRead,None)?;
            current.require_all_devices(proof,Permission::OperationRead)?;
            let policy=crate::sources::storage::read_in(&service.policy_reader,tx,id).await?.ok_or(Error::Execution(crate::missing::ExecutionError::MissingTask))?;
            let software=crate::sources::software::read_in(&service.policy_reader,tx,policy.version).await?;
            let now=storage::now(tx).await?;
            let mut stages=Vec::new();
            let mut prior=(0,0);
            let mut prior_ready=true;
            for (index,stage) in software.assignment.stages().iter().enumerate() {
                let counts=software.assignment.stage_counts_in(tx,index,&service.admission).await?;
                stages.push(json!({"scope":stage.scope,"opensAt":stage.opens_at,
                    "minimumVerifiedPercent":stage.minimum_verified_percent,
                    "open":policy.state.is_enabled() && (stage.minimum_verified_percent.is_none() || prior_ready) && stage.open(now,prior.0,prior.1),
                    "ready":counts.ready,"asOf":counts.as_of,
                    "totalTargets":counts.total,"reported":counts.reported,
                    "unknown":counts.unknown,"waitingUser":counts.waiting_user,"waitingReboot":counts.waiting_reboot,"failed":counts.failed,"verifiedSuccess":counts.verified,
                    "unsupportedCapability":counts.unsupported_capability}));
                prior=(counts.total,counts.verified);
                prior_ready=counts.ready;
            }

            crate::queries::records::decode(json!({"policyId":id,"versionId":policy.version,"paused":!policy.state.is_enabled(),"asOf":now,"stages":stages}))
        })).await.map_err(Into::into)
    }
    pub async fn action_runs(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        page: &rss_mdm_query::window::Query,
        codec: &rss_mdm_query::cursor::CursorCodec,
        audit: &RequestAudit,
    ) -> Result<crate::queries::records::RunPage, crate::queries::QueryError> {
        page.require_schema(&SCHEMA).map_err(|_| Error::Malformed)?;
        self.snapshot(proof,(proof,id,page,audit,codec),|ctx,c,basis|Box::pin(async move {
            let (proof,id,page,_audit,codec)=*ctx;
            let current=&basis.grant;
            current.require(proof,Permission::PolicyRead,None)?;
            current.require_all_devices(proof,Permission::OperationRead)?;
            let binding=rss_mdm_query::cursor::fingerprint(&("live-policy-runs",SCHEMA.id,proof.tenant_id(),proof.instance_id(),proof.principal_id(),current.query_binding(proof)?,id)).map_err(|_|Error::Malformed)?;
            let position:Option<Position>=page.cursor().as_ref().map(|v|codec.decode(&rss_contract::PageCursor::parse(v).map_err(|_|Error::Malformed)?,&binding).map_err(|_|Error::CursorInvalidated)).transpose()?;
            let tenant=proof.tenant_id().to_owned();let at=position.as_ref().map(|p|p.available_at);let after=position.as_ref().map(|p|p.task_id.to_string());let now=basis.now;let limit=page.limit();
            let mut rows={ let c = &mut *c;
                let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object('taskId',r.id,'authorization',r.invocation->'authorization','attemptId',r.state->'delivery'->>'attempt','device',r.device,'registrationId',r.registration,'generation',r.generation,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'userAction',CASE WHEN v.frozen->>'kind'='software' AND v.frozen->'action'->>'intent'='available_install' AND r.state->>'execution'='not_started' AND r.state->>'cancellation'='none' AND r.state->'delivery'->>'kind' IN ('claimed','received') AND (r.state->'delivery'->>'leaseUntil')::bigint>$5 THEN 'waiting_user' ELSE NULL END,'result',");
                query.push(RESULT_SUMMARY_SQL).push(") FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4::uuid)) ORDER BY r.available_at DESC,r.id DESC LIMIT $6");
                query.build_query_scalar::<Value>()
                    .bind(tenant).bind(id.to_string()).bind(at).bind(after).bind(now).bind((limit+1) as i64).fetch_all(c).await
             }?;
            let more=rows.len()>limit;rows.truncate(limit);
            let next=if more {rows.last().map(|row| -> Result<String,Error> {
                let position=Position {available_at:row["availableAt"].as_i64().ok_or(Error::Malformed)?,task_id:serde_json::from_value(row["taskId"].clone()).map_err(|_|Error::Malformed)?};
                codec.encode(&binding,&position).map(|v|v.as_str().to_owned()).map_err(|_|Error::Malformed)
            }).transpose()?}else{None};

            crate::queries::records::decode(json!({"items":rows,"nextCursor":next}))
        })).await.map_err(Into::into)
    }
    pub async fn action_run(
        &self,
        proof: &AuthorizedPrincipal,
        policy: Uuid,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<crate::queries::records::RunDetail, crate::queries::QueryError> {
        crate::transaction::inspect(&self.runtime, self.tenant,(&self.policy_reader,proof,policy,id,audit),|ctx,tx|Box::pin(async move {
            let (reader,proof,policy,id,_audit)=*ctx;
            let mut run=db::read_run(tx,id).await?;
            let plan=db::load_source(reader,tx,run.source).await?;
            if plan.owner()!=policy {
                return Err(Error::Execution(crate::missing::ExecutionError::MissingTask).into());
            }
            storage::authorized(tx,proof,&run.target.device,Permission::OperationRead).await?;
            let collection = match &plan { db::ScheduledPolicy::Script(script) => script.frozen.collection.as_ref(), _ => None };
            let native = matches!(&plan, db::ScheduledPolicy::AgentCollection(_));
            if native {
                // Unmapped native evidence is not a classified inventory field.
                crate::action_admission::current(tx,proof).await?.require(proof,Permission::InventorySensitiveRead,None)?;
            }
            if native || collection.is_some() {
                storage::authorized(tx,proof,&run.target.device,Permission::InventoryRead).await?;
            }

            if let Some(native)=super::output::restore_native(tx,&plan,&run).await? {
                let Some(super::result::RunResult::AgentCollection(result))=run.result.as_mut() else {return Err(Error::Malformed.into());};
                result.native=Some(native);
            }

            let effect=run.result.as_ref().and_then(super::result::RunResult::effect).unwrap_or("unverified").to_owned();
            let user_action=if matches!(plan,db::ScheduledPolicy::Software(ref software) if matches!(software.assignment.intent(),rss_mdm_policy::SoftwareIntent::AvailableInstall)) && run.state.awaits_user(storage::now(tx).await?) {Some("waiting_user")}else{None};
            let nodes = if let Some(attempt) = run.state.attempt() {
                if matches!(&plan, db::ScheduledPolicy::Software(software) if software.assignment.channel() == rss_mdm_inventory::Channel::Agent) {
                    let super::evidence::Material::Software {steps,..} = super::evidence::load_in(tx,id,attempt).await? else { return Err(Error::Malformed.into()); };
                    steps.into_iter().map(|step| json!({"stepId":step.step_id,"definition":step.definition})).collect::<Vec<_>>()
                } else { vec![] }
            } else { vec![] };
            let mut value=json!({"nodes":nodes,"taskId":id,"authorization":run.invocation.as_ref().map(|i|&i.authorization),"attemptId":run.state.attempt(),"device":run.target.device,"registrationId":run.target.registration,"generation":run.target.generation,"availableAt":run.available_at,"deadline":run.deadline,"state":run.state,"effect":effect,"userAction":user_action,"result":run.result});
            value["policyId"]=json!(policy);crate::queries::records::decode(value)
        })).await.map_err(Into::into)
    }
}

use rss_mdm_audit_integration::RequestAudit;
