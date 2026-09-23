use super::{
    schedule::Trigger,
    service::fingerprint,
    state::{Cancellation, Execution},
    storage as db,
};
use crate::commands::{Commands, Result, corrupt, invalid, storage};
use crate::{Error, audit::Audit, device::DevicePrincipal};
use rss_mdm_agent_wire as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use uuid::Uuid;

async fn principal(tx: &mut PgTransaction<'_>, principal: &DevicePrincipal) -> Result<()> {
    if tx.tenant_id() != principal.tenant() {
        return Err(Error::Unauthorized.into());
    }
    let principal = principal.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::collection::revalidate_source(
                c,
                &principal,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await)
        })
    })
    .await??;
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
impl Commands {
    pub(super) async fn claim_action(
        &self,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        self.transact((self,p,input,audit),audit,|ctx,tx|Box::pin(async move{
            let (service,p,input,audit)=*ctx;storage::lock(tx,"action-owner").await?;principal(tx,p).await?;
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(input)?;let now=storage::now(tx).await?;
            // Old successful polls are replayable only while their exact offer remains authorized.
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if let Some(task)=response.get("task").filter(|v|!v.is_null()) {
                    let signed:wire::SignedTask=corrupt(serde_json::from_value(task.clone()))?;
                    let run=db::load_run(tx,signed.payload.task_id).await?;belongs(&run,p)?;audit.plan(run.plan);audit.target(&run.id.to_string());let plan=db::load_plan(tx,run.plan).await?;
                    if run.state.cancellation!=Cancellation::None || run.state.execution!=Execution::NotStarted || signed.payload.expires_at<=now || run.state.attempt()!=Some(signed.payload.attempt_id) || !db::valid(tx,&plan,p.device(),now).await?{return Err(Error::Conflict.into());}
                }
                storage::audit(tx,audit,200).await?;return Ok(response);
            }
            let tenant=tx.tenant_id().to_string();let device=p.device().to_owned();
            let plans=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_commands.action_plans WHERE tenant_id=$1::uuid AND active AND reviewer IS NOT NULL AND (document->'input'->'schedule'->>'until')::bigint>$3 AND document->'input'->'devices' ? $2 AND document->'input'->'schedule'->'trigger'->>'kind' IN ('check_in','registration') ORDER BY id LIMIT 128").bind(tenant).bind(device).bind(now).fetch_all(c).await})).await?;
            for id in plans {
                let plan=db::load_plan(tx,corrupt(Uuid::parse_str(&id))?).await?;
                let target=super::model::Target{device:p.device().into(),registration:p.registration(),generation:p.generation()};
                let kind=if matches!(plan.frozen.input.schedule.trigger,Trigger::Registration){"registration"}else{"checkin"};
                super::production::event(service,tx,&plan,&target,kind,now).await?;
            }
            let ids=super::poll::offer_candidates(tx,p.registration(),now).await?;
            let mut offer=None;
            for id in ids {
                let mut run=db::load_run(tx,corrupt(Uuid::parse_str(&id))?).await?;belongs(&run,p)?;let plan=db::load_plan(tx,run.plan).await?;
                run.state.expire(now,plan.frozen.definition.spec().timeout_seconds);
                if !db::valid(tx,&plan,p.device(),now).await?{run.state.cancel();}
                if run.state.cancellation==Cancellation::None && run.available_at<=now {
                    let attempt=Uuid::new_v4();
                    if run.state.claim(attempt,now).is_ok(){
                        let content=service.content.as_ref().ok_or(Error::Unsupported)?;
                        let signed=content.sign(plan.frozen.task(invalid(Uuid::parse_str(&tx.tenant_id().to_string()))?,&run.target,run.id,attempt,wire::TaskPermit::Offer,(now+60).min(run.deadline))?)?;
                        let tenant=tx.tenant_id().to_string();let run_id=run.id.to_string();let reg=p.registration().to_string();let value=invalid(serde_json::to_value(&signed))?;
                        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_attempts(tenant_id,id,run,registration,claimed_at,offer) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6)").bind(tenant).bind(attempt.to_string()).bind(run_id).bind(reg).bind(now).bind(value).execute(c).await?;Ok(())})).await?;
                        audit.plan(run.plan);audit.target(&run.id.to_string());offer=Some(signed);
                    }
                }
                db::save_run(tx,&run).await?;
                if offer.is_some(){break;}
            }
            let cancellations=super::poll::cancellations(tx,p.registration()).await?;
            let has_offer=offer.is_some();
            let response=invalid(serde_json::to_value(wire::TaskClaimResponse {wire_version:2,task:offer,cancellations}))?;
            if has_offer{db::receipt(tx,&actor,input.operation_id(),hash,&response).await?;}storage::audit(tx,audit,200).await?;Ok(response)
        })).await
    }
    pub(super) async fn action_event(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &Audit,
    ) -> std::result::Result<Value, Error> {
        self.transact((self,p,id,input,audit),audit,|ctx,tx|Box::pin(async move{
            let (service,p,id,input,audit)=*ctx;storage::lock(tx,"action-owner").await?;principal(tx,p).await?;
            let mut run=db::load_run(tx,id).await?;belongs(&run,p)?;audit.plan(run.plan);audit.target(&id.to_string());let plan=db::load_plan(tx,run.plan).await?;let now=storage::now(tx).await?;
            let allowed=db::valid(tx,&plan,p.device(),now).await?;
            if matches!(input.event(),wire::TaskEvent::Start|wire::TaskEvent::Received) && !allowed{return Err(Error::Forbidden.into());}
            if run.state.attempt()!=Some(input.attempt_id()){return Err(Error::Conflict.into());}
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(&(id,input))?;
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if response.get("permit").filter(|p|!p.is_null()).and_then(|p|p["payload"]["expiresAt"].as_i64()).is_some_and(|expiry|expiry<=now){return Err(Error::Conflict.into());}
                storage::audit(tx,audit,200).await?;return Ok(response);}
            let mut permit=None;
            match input.event() {
                wire::TaskEvent::Received=>run.state.received(input.attempt_id(),now)?,
                wire::TaskEvent::Start=>{
                    if run.state.execution!=Execution::NotStarted{return Err(Error::Conflict.into());}
                    run.state.start(input.attempt_id(),now)?;
                    let signed=service.content.as_ref().ok_or(Error::Unsupported)?.sign(plan.frozen.task(invalid(Uuid::parse_str(&tx.tenant_id().to_string()))?,&run.target,id,input.attempt_id(),wire::TaskPermit::Start,(now+15).min(run.deadline))?)?;
                    let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let value=invalid(serde_json::to_value(&signed))?;
                    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.action_attempts SET permit=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND permit IS NULL").bind(tenant).bind(attempt).bind(value).execute(c).await?;Ok(())})).await?;
                    permit=Some(signed);
                },
                wire::TaskEvent::Cancelled=>{run.state.cancel();run.state.cancelled(input.attempt_id())?;},
                wire::TaskEvent::Result{exit_code,quality,output}=>{
                    let schema_valid=plan.frozen.definition.validate_output(output).is_ok();
                    let success=*exit_code==Some(0) && *quality==wire::OutputQuality::Complete && schema_valid;
                    let trusted=success && allowed && run.state.trusts_result(now,plan.frozen.definition.spec().timeout_seconds);
                    run.state.result(input.attempt_id(),success)?;
                    super::collection::accept(tx,&plan.frozen,&run,output,trusted,now).await?;
                    run.result=Some(json!({"exitCode":exit_code,"quality":quality,"schemaValid":schema_valid,"output":output,"trusted":trusted}));
                },
            }
            db::save_run(tx,&run).await?;let response=invalid(serde_json::to_value(wire::TaskEventAck{wire_version:2,accepted:true,permit,cancel_requested:!allowed || run.state.cancellation!=Cancellation::None}))?;
            db::receipt(tx,&actor,input.operation_id(),hash,&response).await?;storage::audit(tx,audit,200).await?;Ok(response)
        })).await
    }
    pub(super) async fn action_content(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        audit: &Audit,
    ) -> std::result::Result<(Vec<u8>, String), Error> {
        self.transact((self,p,id,attempt,audit),audit,|ctx,tx|Box::pin(async move{
            let (service,p,id,attempt,audit)=*ctx;storage::lock(tx,"action-owner").await?;principal(tx,p).await?;
            let run=db::load_run(tx,id).await?;belongs(&run,p)?;audit.plan(run.plan);audit.target(&id.to_string());let plan=db::load_plan(tx,run.plan).await?;let now=storage::now(tx).await?;
            if run.state.attempt()!=Some(attempt) || run.deadline<=now || run.state.cancellation!=Cancellation::None || !db::valid(tx,&plan,p.device(),now).await?{return Err(Error::Forbidden.into());}
            let tenant=tx.tenant_id().to_string();let expiry=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,i64>("SELECT (offer->'payload'->>'expiresAt')::bigint FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt.to_string()).bind(id.to_string()).fetch_one(c).await})).await?;
            if now>=expiry{return Err(Error::Forbidden.into());}
            let artifact=plan.frozen.artifact()?;let etag=format!("\"{}\"",artifact.digest().bytes().iter().map(|v|format!("{v:02x}")).collect::<String>());let content=service.content.clone().ok_or(Error::Unsupported)?;
            let bytes=tokio::task::spawn_blocking(move||content.read(&artifact)).await.map_err(|_|Error::Unavailable(crate::Failure::CommandStorage))??;
            storage::audit(tx,audit,200).await?;Ok((bytes,etag))
        })).await
    }
}
