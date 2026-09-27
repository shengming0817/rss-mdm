//! Bounded run summaries and separately authorized full execution evidence.
use super::storage as db;
use crate::execution::{ExecutionService, storage};
use crate::{Error, authorization::Permission, authorization::context::AuthorizedPrincipal};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) const RESULT_SUMMARY_SQL: &str = "CASE WHEN r.result IS NULL THEN NULL ELSE (r.result-'output') || jsonb_build_object('diagnostics',(r.result->'diagnostics')-'stdout'-'stderr') END";
#[derive(Clone, Copy)]
enum RunOwner {
    Policy(Uuid),
    Remote(Uuid),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Page {
    pub after_at: Option<i64>,
    pub after_id: Option<Uuid>,
}
impl ExecutionService {
    pub(super) async fn software_rollout(
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
                let counts=software.stage_counts_in(tx,index).await?;
                stages.push(json!({"scope":stage.scope,"opensAt":stage.opens_at,
                    "minimumVerifiedPercent":stage.minimum_verified_percent,
                    "open":policy.enabled && stage.open(now,prior.0,prior.1),
                    "totalTargets":counts.total,"reported":counts.reported,
                    "unknown":counts.unknown,"verifiedSuccess":counts.verified,
                    "unsupportedCapability":counts.unsupported_capability}));
                prior=(counts.total,counts.verified);
            }
            service.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"policyId":id,"versionId":policy.version,"paused":!policy.enabled,"asOf":now,"stages":stages}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub(super) async fn action_runs(
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
            let tenant=tx.tenant_id().to_string();let at=page.after_at;let after=page.after_id.map(|id|id.to_string());
            let mut rows=tx.with_connection(move |c|Box::pin(async move {
                let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT jsonb_build_object('taskId',id,'device',device,'registrationId',registration,'generation',generation,'occurrence',occurrence,'availableAt',available_at,'deadline',deadline,'state',state,'effect','unverified','result',");
                query.push(RESULT_SUMMARY_SQL).push(") FROM mdm_commands.action_runs r WHERE tenant_id=$1::uuid AND policy_version IN (SELECT id FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND policy=$2::uuid) AND ($3::bigint IS NULL OR (available_at,id)<($3,$4::uuid)) ORDER BY available_at DESC,id DESC LIMIT 21");
                query.build_query_scalar::<Value>()
                    .bind(tenant).bind(id.to_string()).bind(at).bind(after).fetch_all(c).await
            })).await?;
            let more=rows.len()>20;rows.truncate(20);
            let next=if more {rows.last().map(|row|json!({"availableAt":row["availableAt"],"taskId":row["taskId"]}))}else{None};
            store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"items":rows,"nextCursor":next}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub(super) async fn action_run(
        &self,
        proof: &AuthorizedPrincipal,
        policy: Uuid,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        self.run_detail(proof, RunOwner::Policy(policy), id, audit)
            .await
    }
    pub(crate) async fn remote_action_run(
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
            let (field,parent)=match (owner,run.source) {
                (RunOwner::Policy(policy),db::Source::Policy {..}) if db::load_source(reader,tx,run.source).await?.owner()==policy=>("policyId",policy),
                (RunOwner::Remote(parent),db::Source::RemoteOperation {operation}) if parent==operation=>("operationId",parent),
                _=>return Err(Error::Execution(crate::execution::error::ExecutionError::MissingTask).into()),
            };
            storage::authorized(tx,proof,&run.target.device,Permission::OperationRead).await?;
            store.append_request_in(tx,audit,200,"success").await?;
            let mut value=json!({"taskId":id,"device":run.target.device,"registrationId":run.target.registration,"generation":run.target.generation,"availableAt":run.available_at,"deadline":run.deadline,"state":run.state,"effect":"unverified","result":run.result});
            value[field]=json!(parent);Ok(value)
        }),crate::transaction::TransactionOwner::Execution).await
    }
}

use rss_mdm_audit_integration::RequestAudit;
