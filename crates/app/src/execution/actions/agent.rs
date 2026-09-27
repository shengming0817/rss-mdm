use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::execution::{ExecutionService, Result, checked_input, storage, stored};
use crate::transaction::fingerprint;
use crate::{Error, device::DevicePrincipal};
use rss_mdm_agent_wire as wire;
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use uuid::Uuid;

async fn principal(tx: &mut PgTransaction<'_>, principal: &DevicePrincipal) -> Result<()> {
    if tx.tenant_id() != principal.tenant() {
        return Err(Error::Unauthorized.into());
    }
    let principal = principal.clone();
    let checked = principal.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::device::store::revalidate_source(
                c,
                &checked,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await)
        })
    })
    .await??;
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    let enabled = tx
        .with_connection(move |c| {
            Box::pin(
                async move { crate::device::store::task_capable(c, &tenant, &registration).await },
            )
        })
        .await?;
    if !enabled {
        return Err(Error::Forbidden.into());
    }
    Ok(())
}
fn belongs(run: &db::Run, p: &DevicePrincipal) -> Result<()> {
    if run.target.device != p.device()
        || run.target.registration != p.registration()
        || run.target.generation != p.generation()
    {
        return Err(Error::Unauthorized.into());
    }
    Ok(())
}
impl ExecutionService {
    pub(super) async fn claim_action(
        &self,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,input,audit),|ctx,tx|Box::pin(async move{
            let (service,p,input,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(tx,p).await?;
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(input)?;let now=storage::now(tx).await?;
            let event_key = format!("agent:{}:offer:{}",p.registration(),input.operation_id());
            // Old successful polls are replayable only while their exact offer remains authorized.
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if let Some(task)=response.get("task").filter(|v|!v.is_null()) {
                    let signed:wire::SignedTask=stored(serde_json::from_value(task.clone()))?;
                    let run=db::load_run(tx,signed.payload.task_id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&run.id.to_string());let plan=db::load_source(tx,run.source).await?;
                    if run.state.cancellation!=Cancellation::None || run.state.execution!=Execution::NotStarted || signed.payload.expires_at<=now || run.state.attempt()!=Some(signed.payload.attempt_id) || !plan.definition.authorized_in(tx,p.device(),now).await?{return Err(Error::Conflict.into());}
                }
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);
            }
            let _tenant=tx.tenant_id().to_string();let _device=p.device().to_owned();
            let versions=crate::planning::policies::admission::agent_versions_in(tx,p.registration()).await?;
            for id in versions {
                let policy=db::load_policy_version(tx,id).await?;
                let target=super::model::Target {device:p.device().into(),registration:p.registration(),generation:p.generation()};
                super::production::accept_for_device(service,tx,&policy,&target,input.operation_id(),now).await?;
            }
            let ids=super::poll::offer_candidates(tx,p.registration(),now).await?;
            let mut offer=None;
            for id in ids {
                let mut run=db::load_run(tx,stored(Uuid::parse_str(&id))?).await?;belongs(&run,p)?;let plan=db::load_source(tx,run.source).await?;
                let previous=run.state.clone();
                run.state.expire(now,plan.definition.frozen.definition.spec().timeout_seconds);
                let allowed=plan.definition.authorized_in(tx,p.device(),now).await?;
                if plan.definition.withdrawn_in(tx,p.device()).await?{run.state.cancel();}
                super::recovery::audit_recovery(service,tx,&run,&previous).await?;
                if run.state.cancellation==Cancellation::None && run.available_at<=now && allowed {
                    let attempt=Uuid::new_v4();
                    if run.state.claim(attempt,now).is_ok(){
                        let signer=service.signer.as_ref().ok_or(Error::Unsupported)?;
                        let signed=signer.sign(plan.definition.frozen.task(checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,&run.target,run.id,attempt,wire::TaskPermit::Offer,(now+60).min(run.deadline))?)?;
                        let tenant=tx.tenant_id().to_string();let run_id=run.id.to_string();let reg=p.registration().to_string();let value=checked_input(serde_json::to_value(&signed))?;
                        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_attempts(tenant_id,id,run,registration,claimed_at,offer) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6)").bind(tenant).bind(attempt.to_string()).bind(run_id).bind(reg).bind(now).bind(value).execute(c).await?;Ok(())})).await?;
                        run.source.audit(audit);audit.target(&run.id.to_string());offer=Some(signed);
                    }
                }
                db::save_run(tx,&run).await?;
                if offer.is_some(){break;}
            }
            let cancellations=super::poll::cancellations(tx,p.registration()).await?;
            let has_offer=offer.is_some();
            let response=checked_input(serde_json::to_value(checked_input(wire::TaskClaimResponse::new(offer,cancellations))?))?;
            if has_offer{
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                db::receipt(tx,&actor,input.operation_id(),hash,&response).await?;
                service.audit_store.append_in(tx,&fact,false).await?;
            }else{service.audit_store.append_request_in(tx,audit,200,"success").await?;}
            Ok(response)
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub(super) async fn action_event(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,id,input,audit),|ctx,tx|Box::pin(async move{
            let (service,p,id,input,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(tx,p).await?;
            let mut run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(tx,run.source).await?;let now=storage::now(tx).await?;
            let allowed=plan.definition.authorized_in(tx,p.device(),now).await?;
            if matches!(input.event(),wire::TaskEvent::Start|wire::TaskEvent::Received) && !allowed{return Err(Error::Forbidden.into());}
            if run.state.attempt()!=Some(input.attempt_id()){return Err(Error::Conflict.into());}
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(&(id,input))?;
            let event_key = format!("agent:{}:task:{id}:event:{}",p.registration(),input.operation_id());
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if response.get("permit").filter(|p|!p.is_null()).and_then(|p|p["payload"]["expiresAt"].as_i64()).is_some_and(|expiry|expiry<=now){return Err(Error::Conflict.into());}
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);}
            let mut permit=None;
            match input.event() {
                wire::TaskEvent::Received=>run.state.received(input.attempt_id(),now)?,
                wire::TaskEvent::Start=>{
                    if run.state.execution!=Execution::NotStarted{return Err(Error::Conflict.into());}
                    run.state.start(input.attempt_id(),now)?;
                    let signed=service.signer.as_ref().ok_or(Error::Unsupported)?.sign(plan.definition.frozen.task(checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?,&run.target,id,input.attempt_id(),wire::TaskPermit::Start,(now+15).min(run.deadline))?)?;
                    let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let value=checked_input(serde_json::to_value(&signed))?;
                    let changed=tx.with_connection(move|c|Box::pin(async move{Ok(sqlx::query("UPDATE mdm_commands.action_attempts SET permit=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND permit IS NULL").bind(tenant).bind(attempt).bind(value).execute(c).await?.rows_affected())})).await?;
                    if changed!=1{return Err(Error::Conflict.into());}
                    permit=Some(signed);
                },
                wire::TaskEvent::Cancelled=>{run.state.cancel();run.state.cancelled(input.attempt_id())?;},
                wire::TaskEvent::Result(result)=>{
                    let output=result.output();
                    let schema_valid=plan.definition.frozen.definition.validate_output(output).is_ok();
                    let success=result.exit_code()==Some(0) && result.quality()==wire::OutputQuality::Complete && schema_valid;
                    let trusted=success && allowed && run.state.trusts_result(now,plan.definition.frozen.definition.spec().timeout_seconds);
                    run.state.result(input.attempt_id(),success)?;
                    super::collection::accept(tx,&plan.definition.frozen,&run,output,trusted,now).await?;
                    run.result=Some(json!({"exitCode":result.exit_code(),"quality":result.quality(),"schemaValid":schema_valid,"output":output,"diagnostics":result.diagnostics(),"trusted":trusted}));
                },
            }
            db::save_run(tx,&run).await?;let response=checked_input(serde_json::to_value(wire::TaskEventAck::new(permit,!allowed || run.state.cancellation!=Cancellation::None)))?;
            let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
            db::receipt(tx,&actor,input.operation_id(),hash,&response).await?;
            service.audit_store.append_in(tx,&fact,false).await?;Ok(response)
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub(super) async fn action_content(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<crate::content::Verified, Error> {
        let artifact = self.authorize_content(p, id, attempt, audit).await?;
        let verified = self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify(&artifact)
            .await?;
        let current = self.authorize_content(p, id, attempt, audit).await?;
        if !verified.matches(&current) {
            return Err(Error::Conflict);
        }
        Ok(verified)
    }
    async fn authorize_content(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_resource::Artifact, Error> {
        audit.require_request_settlement();
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p,id,attempt,audit),|ctx,tx|Box::pin(async move{
            let (_service,p,id,attempt,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(tx,p).await?;
            let run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(tx,run.source).await?;let now=storage::now(tx).await?;
            if run.state.attempt()!=Some(attempt) || run.deadline<=now || run.state.cancellation!=Cancellation::None || !plan.definition.authorized_in(tx,p.device(),now).await?{return Err(Error::Forbidden.into());}
            let tenant=tx.tenant_id().to_string();let expiry=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,i64>("SELECT (offer->'payload'->>'expiresAt')::bigint FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt.to_string()).bind(id.to_string()).fetch_one(c).await})).await?;
            if now>=expiry{return Err(Error::Forbidden.into());}
            plan.definition.frozen.artifact().map_err(Into::into)
        }),crate::transaction::TransactionOwner::Execution).await
    }
}

use rss_mdm_audit_integration::RequestAudit;
