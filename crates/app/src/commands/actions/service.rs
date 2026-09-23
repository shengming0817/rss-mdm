use super::{model::*, schedule::Trigger, storage as db};
use crate::commands::{Commands, Result, invalid, recovery, rejection, settle, storage};
use crate::{
    Error,
    audit::Audit,
    authorization::{Approval, Permission},
    identity::Principal,
};
use rss_mdm_resource as r;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Mutex, time::Duration};
use uuid::Uuid;

pub(super) fn fingerprint(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(invalid(serde_json::to_vec(value))?).to_vec())
}
pub(super) fn target(tenant: rss_request_context::TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        crate::commands::recovery_scope(tenant),
        format!("action.{id}"),
    )
    .expect("bounded task target")
}
impl Commands {
    pub(super) async fn create_action_plan(
        &self,
        proof: &Principal,
        input: &Create,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        if self.content.is_none() {
            return Err(Error::Unsupported);
        }
        self.transact((self,proof,input,audit),audit,|ctx,tx|Box::pin(async move{
            let (service,proof,input,audit)=*ctx;storage::lock(tx,"action-owner").await?;
            let now=storage::now(tx).await?;input.validate(now)?;
            let mut approvals=Vec::new();
            for device in &input.devices {
                let snapshot=storage::authorized(tx,proof,device,Permission::ScriptExecute).await?;
                approvals.push(Approval::from_proof(&snapshot,proof,device,Permission::ScriptExecute)?);
            }
            let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&(proof.user(),input))?;
            if let Some(value)=db::replay(tx,&actor,input.operation_id,&hash).await?{storage::audit(tx,audit,202).await?;return Ok(value);}
            if matches!(input.schedule.trigger,Trigger::Registration|Trigger::CheckIn{..}) {
                let tenant=tx.tenant_id().to_string();let devices=input.devices.clone();
                let full=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT device FROM mdm_commands.action_plans CROSS JOIN LATERAL jsonb_array_elements_text(document->'input'->'devices') device WHERE tenant_id=$1::uuid AND active AND (document->'input'->'schedule'->>'until')::bigint>$3 AND document->'input'->'schedule'->'trigger'->>'kind' IN ('check_in','registration') AND device=ANY($2) GROUP BY device HAVING count(*)>=128)").bind(tenant).bind(devices).bind(now).fetch_one(c).await})).await?;
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
            let frozen=Frozen{input:input.clone(),definition:definition.clone(),resource_digest:version.digest().bytes(),artifact_reference:artifact.reference().as_str().into(),content:rss_mdm_agent_wire::TaskContent{length:artifact.length(),sha256:artifact.digest().bytes()}};
            let tenant=tx.tenant_id().to_string();let document=invalid(serde_json::to_value(frozen))?;let author=invalid(serde_json::to_value(proof.user()))?;let approvals=invalid(serde_json::to_value(approvals))?;let digest=hash.clone();let id=input.operation_id.to_string();let resource=input.resource.clone();let version=input.version.clone();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_plans(tenant_id,id,resource,version,document,fingerprint,author,author_approvals,scan_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9)").bind(tenant).bind(id).bind(resource).bind(version).bind(document).bind(digest).bind(author).bind(approvals).bind(now-1).execute(c).await?;Ok(())})).await?;
            let response=json!({"planId":input.operation_id,"revision":1,"authorization":"pending_review"});
            db::receipt(tx,&actor,input.operation_id,hash,&response).await?;storage::audit(tx,audit,202).await?;proof.check_live()?;Ok(response)
        })).await
    }
    pub(super) async fn approve_action_plan(
        &self,
        proof: &Principal,
        id: Uuid,
        change: &Change,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        let failure = Mutex::new(None);
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let attempt=rss_reconcile_postgres::messaging::wake_with(&self.runtime,&target(self.tenant,id),&control,(self,proof,id,change,audit,&failure),|ctx,tx|Box::pin(async move{
            let (service,proof,id,change,audit,failure)=*ctx;
            let result:Result<Value>=async{
                storage::admit(tx).await?;storage::lock(tx,"action-owner").await?;let mut plan=db::load_plan(tx,id).await?;
                if plan.author==proof.user(){return Err(Error::Forbidden.into());}
                let now=storage::now(tx).await?;
                if !plan.active || now>=plan.frozen.input.schedule.until{return Err(Error::Conflict.into());}
                let mut approvals=Vec::new();
                for device in &plan.frozen.input.devices {let snapshot=storage::authorized(tx,proof,device,Permission::ScriptApprove).await?;approvals.push(Approval::from_proof(&snapshot,proof,device,Permission::ScriptApprove)?);}
                let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&("approve",id,proof.user()))?;
                if let Some(value)=db::replay(tx,&actor,change.operation_id,&hash).await?{storage::audit(tx,audit,200).await?;return Ok(value);}
                if plan.reviewer.is_some(){return Err(Error::Conflict.into());}
                let tenant=tx.tenant_id().to_string();let reviewer=invalid(serde_json::to_value(proof.user()))?;let approvals_value=invalid(serde_json::to_value(&approvals))?;
                tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_plans SET reviewer=$3,reviewer_approvals=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(reviewer).bind(approvals_value).execute(c).await?;Ok(())})).await?;
                plan.reviewer=Some(proof.user());plan.reviewer_approvals=approvals;
                if matches!(plan.frozen.input.schedule.trigger,Trigger::Manual){super::production::produce(service,tx,&plan,now,"manual",now,None).await?;}
                let response=json!({"planId":id,"revision":1,"authorization":"approved"});db::receipt(tx,&actor,change.operation_id,hash,&response).await?;storage::audit(tx,audit,200).await?;proof.check_live()?;Ok(response)
            }.await;
            match result{Ok(value)=>{audit.mark_commit_started();Ok(value)},Err(error)=>Err(rejection(error,failure))}
        })).await;
        settle(attempt, audit, failure)
    }
    pub(super) async fn read_action_plan(
        &self,
        proof: &Principal,
        id: Uuid,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        self.transact((proof,id,audit),audit,|ctx,tx|Box::pin(async move{
            let (proof,id,audit)=*ctx;storage::lock(tx,"action-owner").await?;let plan=db::load_plan(tx,id).await?;
            for device in &plan.frozen.input.devices{storage::authorized(tx,proof,device,Permission::OperationRead).await?;}
            let tenant=tx.tenant_id().to_string();
            let runs=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('taskId',id,'device',device,'registrationId',registration,'generation',generation,'occurrence',occurrence,'availableAt',available_at,'deadline',deadline,'state',state,'effect','unverified','result',result) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND plan=$2::uuid ORDER BY available_at DESC,id LIMIT 256").bind(tenant).bind(id.to_string()).fetch_all(c).await})).await?;
            storage::audit(tx,audit,200).await?;Ok(json!({"planId":id,"revision":1,"active":plan.active,"approved":plan.reviewer.is_some(),"definition":plan.frozen,"runs":runs}))
        })).await
    }
    pub(super) async fn cancel_action_plan(
        &self,
        proof: &Principal,
        id: Uuid,
        change: &Change,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        if change.operation_id.is_nil() {
            return Err(Error::Malformed);
        }
        self.transact((proof,id,change,audit),audit,|ctx,tx|Box::pin(async move{
            let (proof,id,change,audit)=*ctx;storage::lock(tx,"action-owner").await?;let plan=db::load_plan(tx,id).await?;
            for device in &plan.frozen.input.devices{storage::authorized(tx,proof,device,Permission::OperationCancel).await?;}
            let actor=format!("user:{}",proof.principal_id());let hash=fingerprint(&("cancel",id,proof.user()))?;
            if let Some(value)=db::replay(tx,&actor,change.operation_id,&hash).await?{storage::audit(tx,audit,200).await?;return Ok(value);}
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_plans SET active=false WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())})).await?;
            let response=json!({"planId":id,"cancelRequested":true});db::receipt(tx,&actor,change.operation_id,hash,&response).await?;storage::audit(tx,audit,200).await?;proof.check_live()?;Ok(response)
        })).await
    }
}
