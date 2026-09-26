use super::ActionPlans;
use super::{model::*, schedule::Trigger, storage as db};
use crate::action_admission as storage;
use crate::execution_transaction::fingerprint;
use crate::execution_transaction::{Result, invalid, rejection, settle};
use crate::{
    Error,
    authorization::context::AuthorizedPrincipal,
    authorization::{Approval, Permission},
};
use rss_mdm_audit_integration::Fact;
use rss_mdm_resource as r;
use serde_json::{Value, json};
use std::{sync::Mutex, time::Duration};
use uuid::Uuid;

impl ActionPlans {
    pub(crate) async fn create_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        input: &Create,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if self.content.is_none() {
            return Err(Error::Unsupported);
        }
        crate::execution_transaction::transact(&self.runtime, &self.audit_store, self.tenant, (self,proof,input,audit),audit,|ctx,tx|Box::pin(async move{
            let (service,proof,input,audit)=*ctx;crate::mutation::lock(tx).await.map_err(|_|Error::Unavailable(crate::Failure::ManagementStorage))?;storage::lock(tx,"action-owner").await?;
            let now=storage::now(tx).await?;input.validate(now)?;
            let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&(proof.user(),input))?;
            let event_key = format!("action-plan:{actor}:{}:create", input.operation_id);
            if let Some(value)=db::replay(tx,&actor,input.operation_id,&hash).await?{
                let old=db::load_plan(tx,input.operation_id).await?;
                for device in &old.frozen.targets.devices {storage::authorized(tx,proof,device,Permission::ScriptExecute).await?;}
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,202,"success",None)?;
                service.audit_store.append_in(tx,&fact,true).await?;proof.check_live()?;return Ok(value);
            }
            if matches!(input.targets,Targets::Scope{..}) {proof.manage(Permission::ScopeRead)?;}
            let targets=super::targets::freeze_in(tx,&input.targets).await?;
            let mut approvals=Vec::new();
            for device in &targets.devices {
                let snapshot=storage::authorized(tx,proof,device,Permission::ScriptExecute).await?;
                approvals.push(Approval::from_proof(&snapshot,proof,device,Permission::ScriptExecute)?);
            }
            if matches!(input.schedule.trigger,Trigger::Registration|Trigger::CheckIn{..}) {
                let tenant=tx.tenant_id().to_string();let devices=targets.devices.clone();
                let full=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT device FROM mdm_planning.action_plans CROSS JOIN LATERAL jsonb_array_elements_text(document->'targets'->'devices') device WHERE tenant_id=$1::uuid AND active AND (document->'input'->'schedule'->>'until')::bigint>$3 AND document->'input'->'schedule'->'trigger'->>'kind' IN ('check_in','registration') AND device=ANY($2) GROUP BY device HAVING count(*)>=128)").bind(tenant).bind(devices).bind(now).fetch_one(c).await})).await?;
                if full{return Err(Error::Conflict.into());}
            }
            let (version,state)=rss_mdm_resource_postgres::lock_reference_in(tx,&invalid(r::Id::new(&input.resource))?,&invalid(r::Id::new(&input.version))?).await?.map_err(|_|Error::Conflict)?;
            if state!=r::State::Active{return Err(Error::Conflict.into());}
            let variant=input.variant(&version)?;
            let r::Declaration::Script{artifact,definition}=variant.declaration() else{return Err(Error::Malformed.into())};
            definition.validate_parameters(&input.parameters).map_err(|_|Error::Malformed)?;
            if artifact.length()>16_777_216{return Err(Error::Malformed.into());}
            let content=service.content.clone().ok_or(Error::Unsupported)?;let item=artifact.clone();
            let bytes=tokio::task::spawn_blocking(move||content.read(&item)).await.map_err(|_|Error::Unavailable(crate::Failure::CommandStorage))??;
            if definition.spec().profile==r::ScriptProfile::OsqueryInfoV1 && bytes!=b"SELECT version FROM osquery_info;\n" {return Err(Error::Malformed.into());}
            let target_count=targets.devices.len();let frozen=Frozen{targets,input:input.clone(),definition:definition.clone(),resource_digest:version.digest().bytes(),artifact_reference:artifact.reference().as_str().into(),content:rss_mdm_agent_wire::TaskContent{length:artifact.length(),sha256:artifact.digest().bytes()}};
            let tenant=tx.tenant_id().to_string();let document=invalid(serde_json::to_value(frozen))?;let author=invalid(serde_json::to_value(proof.user()))?;let approvals=invalid(serde_json::to_value(approvals))?;let digest=hash.clone();let id=input.operation_id.to_string();let resource=input.resource.clone();let version=input.version.clone();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.action_plans(tenant_id,id,resource,version,document,fingerprint,author,author_approvals) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)").bind(tenant).bind(id).bind(resource).bind(version).bind(document).bind(digest).bind(author).bind(approvals).execute(c).await?;Ok(())})).await?;
            service.dispatch.initialize_in(tx,input.operation_id,now).await?;
            let response=json!({"operationId":input.operation_id,"planId":input.operation_id,"revision":1,"authorization":"pending_review","targetCount":target_count,"nextStage":"review"});
            let fact = Fact::business(audit, &event_key, &hash, 202, "success", None)?; service.audit_store.append_in(tx, &fact, false).await?;db::receipt(tx,&actor,input.operation_id,hash,&response).await?;proof.check_live()?;Ok(response)
        })).await
    }
    pub(crate) async fn approve_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        change: &Change,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        let failure = Mutex::new(None);
        let timer = crate::planning::automation::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let attempt=self.runtime.local_tx_with_context(
    self.tenant,
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),
    (self, self.dispatch.target(id), (self,proof,id,change,audit,&failure)),
    |(service, target, context), tx| Box::pin(async move {
        if let Err(error) = service.audit_store.lock_in(tx).await {
       return Err(rejection(Error::from(error).into(), context.5));
   }
        rss_reconcile_postgres::messaging::wake_in(tx, target, context, |ctx,tx|Box::pin(async move{
            let (service,proof,id,change,audit,failure)=**ctx;
            let result:Result<Value>=async{
                service.dispatch.admit_in(tx).await?;storage::lock(tx,"action-owner").await?;let mut plan=db::load_plan(tx,id).await?;
                if plan.author==proof.user(){return Err(Error::Forbidden.into());}
                let now=storage::now(tx).await?;
                if !plan.active || now>=plan.frozen.input.schedule.until{return Err(Error::Conflict.into());}
                let mut approvals=Vec::new();
                for device in &plan.frozen.targets.devices {let snapshot=storage::authorized(tx,proof,device,Permission::ScriptApprove).await?;approvals.push(Approval::from_proof(&snapshot,proof,device,Permission::ScriptApprove)?);}
                let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&("approve",id,proof.user()))?;
            let event_key = format!("action-plan:{actor}:{}:approve", change.operation_id);
                if let Some(value)=db::replay(tx,&actor,change.operation_id,&hash).await?{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?; service.audit_store.append_in(tx, &fact, true).await?;return Ok(value);}
                if plan.reviewer.is_some(){return Err(Error::Conflict.into());}
                let tenant=tx.tenant_id().to_string();let reviewer=invalid(serde_json::to_value(proof.user()))?;let approvals_value=invalid(serde_json::to_value(&approvals))?;
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.action_plans SET reviewer=$3,reviewer_approvals=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(reviewer).bind(approvals_value).execute(c).await?;Ok(())})).await?;
                plan.reviewer=Some(proof.user());plan.reviewer_approvals=approvals;
                if matches!(plan.frozen.input.schedule.trigger,Trigger::Manual) && !service.dispatch.manual_in(tx,&plan,now).await?{return Err(Error::Conflict.into());}
                let response=json!({"planId":id,"revision":1,"authorization":"approved"});let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?; service.audit_store.append_in(tx, &fact, false).await?;db::receipt(tx,&actor,change.operation_id,hash,&response).await?;proof.check_live()?;Ok(response)
            }.await;
            match result{Ok(value)=>{audit.mark_commit_started();Ok(value)},Err(error)=>Err(rejection(error,failure))}
        })).await
    }),
).await;
        settle(attempt, audit, failure)
    }
    pub(crate) async fn read_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::execution_transaction::transact(&self.runtime, &self.audit_store, self.tenant, (&self.audit_store,proof,id,audit),audit,|ctx,tx|Box::pin(async move{
            let (store,proof,id,audit)=*ctx;storage::lock(tx,"action-owner").await?;let plan=db::load_plan(tx,id).await?;
            for device in &plan.frozen.targets.devices{storage::authorized(tx,proof,device,Permission::OperationRead).await?;}
            store.append_request_in(tx,audit,200,"success").await?;Ok(json!({"planId":id,"revision":1,"active":plan.active,"approved":plan.reviewer.is_some(),"definition":plan.frozen,"runsUrl":format!("/api/v3/script-plans/{id}/runs")}))
        })).await
    }
    pub(crate) async fn cancel_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        change: &Change,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        crate::execution_transaction::transact(&self.runtime, &self.audit_store, self.tenant, (&self.audit_store,proof,id,change,audit),audit,|ctx,tx|Box::pin(async move{
            let (store,proof,id,change,audit)=*ctx;storage::lock(tx,"action-owner").await?;let plan=db::load_plan(tx,id).await?;
            for device in &plan.frozen.targets.devices{storage::authorized(tx,proof,device,Permission::OperationCancel).await?;}
            let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&("cancel",id,proof.user()))?;
            let event_key = format!("action-plan:{actor}:{}:cancel", change.operation_id);
            if let Some(value)=db::replay(tx,&actor,change.operation_id,&hash).await?{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?; store.append_in(tx, &fact, true).await?;return Ok(value);}
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_planning.action_plans SET active=false WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())})).await?;
            let response=json!({"planId":id,"cancelRequested":true});let fact = Fact::business(audit, &event_key, &hash, 200, "success", None)?; store.append_in(tx, &fact, false).await?;db::receipt(tx,&actor,change.operation_id,hash,&response).await?;proof.check_live()?;Ok(response)
        })).await
    }
}

use rss_mdm_audit_integration::RequestAudit;
