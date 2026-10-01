//! Bounded run summaries and separately authorized full execution evidence.
use super::storage as db;
use crate::execution::{ExecutionService, storage};
use crate::{Error, authorization::Permission, authorization::context::AuthorizedPrincipal};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub const RESULT_SUMMARY_SQL: &str = "CASE WHEN r.result IS NULL THEN NULL WHEN r.result->'evidence' IS NOT NULL THEN jsonb_set(r.result,'{evidence,steps}',(SELECT jsonb_agg(value || jsonb_build_object('diagnostics',(value->'diagnostics')-'stdout'-'stderr') ORDER BY position) FROM jsonb_array_elements(r.result#>'{evidence,steps}') WITH ORDINALITY AS item(value,position))) ELSE (r.result-'output') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END";

#[derive(Clone, Copy)]
enum RunOwner {
    Policy(Uuid),
    Remote(Uuid),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page {
    pub after_at: Option<i64>,
    pub after_id: Option<Uuid>,
}
impl ExecutionService {
    pub async fn software_rollout(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,id,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,id,audit)=*ctx;
            proof.manage(Permission::PolicyRead)?;
            proof.require_all_devices(Permission::OperationRead)?;
            let policy=crate::planning::policies::storage::read_in(&service.policy_reader,tx,id).await?.ok_or(Error::Execution(crate::execution::error::ExecutionError::MissingTask))?;
            let software=crate::planning::policies::software::read_in(&service.policy_reader,tx,policy.version).await?;
            let now=storage::now(tx).await?;
            let mut stages=Vec::new();
            let mut prior=(0,0);
            for (index,stage) in software.stages()?.iter().enumerate() {
                let counts=software.stage_counts_in(tx,index,service).await?;
                stages.push(json!({"scope":stage.scope,"opensAt":stage.opens_at,
                    "minimumVerifiedPercent":stage.minimum_verified_percent,
                    "open":policy.enabled && stage.open(now,prior.0,prior.1),
                    "totalTargets":counts.total,"reported":counts.reported,
                    "unknown":counts.unknown,"waitingUser":counts.waiting_user,"waitingReboot":counts.waiting_reboot,"failed":counts.failed,"verifiedSuccess":counts.verified,
                    "unsupportedCapability":counts.unsupported_capability}));
                prior=(counts.total,counts.verified);
            }
            service.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"policyId":id,"versionId":policy.version,"paused":!policy.enabled,"asOf":now,"stages":stages}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub async fn action_runs(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        page: &Page,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        if page.after_at.is_some() != page.after_id.is_some()
            || page.after_at.is_some_and(|at| at < 0)
            || page.after_id.is_some_and(|id| id.is_nil())
        {
            return Err(Error::Malformed);
        }
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(&self.audit_store,proof,id,page,audit),|ctx,tx|Box::pin(async move {
            let (store,proof,id,page,audit)=*ctx;
            proof.manage(Permission::PolicyRead)?;
            proof.require_all_devices(Permission::OperationRead)?;
            let tenant=tx.tenant_id().to_string();let at=page.after_at;let after=page.after_id.map(|id|id.to_string());let now=storage::now(tx).await?;
            let mut rows=tx.with_connection(move |c|Box::pin(async move {
                let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object('taskId',r.id,'device',r.device,'registrationId',r.registration,'generation',r.generation,'occurrence',r.occurrence,'availableAt',r.available_at,'deadline',r.deadline,'state',r.state,'effect',coalesce(r.result->>'effect','unverified'),'userAction',CASE WHEN v.frozen->>'kind'='software' AND v.frozen->'action'->>'intent'='available_install' AND r.state->>'execution'='not_started' AND r.state->>'cancellation'='none' AND r.state->'delivery'->>'kind' IN ('claimed','received') AND (r.state->'delivery'->>'leaseUntil')::bigint>$5 THEN 'waiting_user' ELSE NULL END,'result',");
                query.push(RESULT_SUMMARY_SQL).push(") FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4::uuid)) ORDER BY r.available_at DESC,r.id DESC LIMIT 21");
                query.build_query_scalar::<Value>()
                    .bind(tenant).bind(id.to_string()).bind(at).bind(after).bind(now).fetch_all(c).await
            })).await?;
            let more=rows.len()>20;rows.truncate(20);
            let next=if more {rows.last().map(|row|json!({"availableAt":row["availableAt"],"taskId":row["taskId"]}))}else{None};
            store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"items":rows,"nextCursor":next}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub async fn action_run(
        &self,
        proof: &AuthorizedPrincipal,
        policy: Uuid,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        self.run_detail(proof, RunOwner::Policy(policy), id, audit)
            .await
    }
    pub async fn remote_action_run(
        &self,
        proof: &AuthorizedPrincipal,
        operation: Uuid,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        self.run_detail(proof, RunOwner::Remote(operation), id, audit)
            .await
    }
    async fn run_detail(
        &self,
        proof: &AuthorizedPrincipal,
        owner: RunOwner,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(&self.audit_store,&self.policy_reader,proof,owner,id,audit),|ctx,tx|Box::pin(async move {
            let (store,reader,proof,owner,id,audit)=*ctx;
            let run=db::load_run(tx,id).await?;
            let plan=db::load_source(reader,tx,run.source).await?;
            let (field,parent)=match (owner,run.source) {
                (RunOwner::Policy(policy),db::Source::Policy {..}) if plan.owner()==policy=>("policyId",policy),
                (RunOwner::Remote(parent),db::Source::RemoteOperation {operation}) if parent==operation=>("operationId",parent),
                _=>return Err(Error::Execution(crate::execution::error::ExecutionError::MissingTask).into()),
            };
            storage::authorized(tx,proof,&run.target.device,Permission::OperationRead).await?;
            if let db::ScheduledPolicy::Script(script)=&plan && let Some(collection)=&script.frozen.collection {
                storage::authorized(tx,proof,&run.target.device,Permission::InventoryRead).await?;
                if collection.fields().iter().any(|f|f.sensitivity==rss_mdm_inventory::Sensitivity::Sensitive) {
                    proof.manage(Permission::InventorySensitiveRead)?;
                }
            }

            store.append_request_in(tx,audit,200,"success").await?;
            let effect=run.result.as_ref().and_then(|r|r["effect"].as_str()).unwrap_or("unverified").to_owned();
            let user_action=if matches!(plan,db::ScheduledPolicy::Software(ref software) if matches!(software.intent(),rss_mdm_policy::SoftwareIntent::AvailableInstall)) && run.state.awaits_user(storage::now(tx).await?) {Some("waiting_user")}else{None};
            let mut value=json!({"taskId":id,"device":run.target.device,"registrationId":run.target.registration,"generation":run.target.generation,"availableAt":run.available_at,"deadline":run.deadline,"state":run.state,"effect":effect,"userAction":user_action,"result":run.result});
            value[field]=json!(parent);Ok(value)
        }),crate::transaction::TransactionOwner::Execution).await
    }
}

use rss_mdm_audit_integration::RequestAudit;
