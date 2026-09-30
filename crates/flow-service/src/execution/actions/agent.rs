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

async fn principal(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    principal: &DevicePrincipal,
) -> Result<()> {
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
    let enabled = crate::execution::channels::agent_binding_in(
        tx,
        service.agent_store.clone(),
        principal.registration(),
    )
    .await?
    .is_some_and(|b| b.inventory() && b.task());
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
    pub async fn claim_action(
        &self,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,input,audit),|ctx,tx|Box::pin(async move{
            let (service,p,input,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(service,tx,p).await?;
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(input)?;let now=storage::now(tx).await?;
            let event_key = format!("agent:{}:offer:{}",p.registration(),input.operation_id());
            // Old successful polls are replayable only while their exact offer remains authorized.
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if let Some(task)=response.get("task").filter(|v|!v.is_null()) {
                    let signed:wire::SignedTask=stored(serde_json::from_value(task.clone()))?;
                    let run=db::load_run(tx,signed.payload.task_id()).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&run.id.to_string());let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
                    if run.state.cancellation!=Cancellation::None || run.state.execution!=Execution::NotStarted || signed.payload.expires_at()<=now || run.state.attempt()!=Some(signed.payload.attempt_id()) || !plan.authorized_in(service,tx,&run.target,now).await?{return Err(Error::Conflict.into());}
                }
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);
            }
            let binding=crate::execution::channels::agent_binding_in(tx,service.agent_store.clone(),p.registration()).await?.ok_or(Error::Forbidden)?;
            let (script_capable,software_capable,enrollment_capable)=(binding.script(),binding.software(),binding.enrollment());
            let versions=crate::planning::policies::admission::agent_versions_in(tx,p.registration()).await?;
            for id in versions {
                let policy=db::load_policy_version(&service.policy_reader,tx,id).await?;
                let target=super::model::Target {device:p.device().into(),registration:p.registration(),generation:p.generation()};
                match &policy {
                    db::ScheduledPolicy::Enrollment(_) if enrollment_capable => super::production::accept_for_device(service,tx,&policy,&target,input.operation_id(),now).await?,
                    db::ScheduledPolicy::Script(_) if script_capable => super::production::accept_for_device(service,tx,&policy,&target,input.operation_id(),now).await?,
                    db::ScheduledPolicy::Software(software) if software_capable => super::software::accept_for_device(service,tx,software,&target,now).await?,
                    _ => (),
                }
            }
            let ids=super::poll::offer_candidates(tx,p.registration(),now).await?;
            let mut offer=None;
            for id in ids {
                let mut run=db::load_run(tx,stored(Uuid::parse_str(&id))?).await?;belongs(&run,p)?;let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
                let previous=run.state.clone();
                run.state.expire(now,plan.timeout_seconds());
                let capable=match &plan { db::ScheduledPolicy::Script(_) => script_capable, db::ScheduledPolicy::Software(_) => software_capable, db::ScheduledPolicy::Enrollment(_) => enrollment_capable };
                let allowed=capable && plan.authorized_in(service,tx,&run.target,now).await?;
                if plan.withdrawn_in(service,tx,&run.target,now).await?{run.state.cancel();}
                super::recovery::audit_recovery(service,tx,&run,&previous).await?;
                if run.state.cancellation==Cancellation::None && run.available_at<=now && allowed {
                    let attempt=Uuid::new_v4();
                    if run.state.claim(attempt,now).is_ok(){
                        let signer=service.signer.as_ref().ok_or(Error::Unsupported)?;
                        let signed=signer.sign(plan.task(service,tx,&run.target,db::TaskIssue { run:run.id,attempt,permit:wire::TaskPermit::Offer,expiry:(now+60).min(run.deadline) }).await?)?;
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
                db::receipt(tx,&actor,input.operation_id(),hash,&response,None).await?;
                service.audit_store.append_in(tx,&fact,false).await?;
            }else{service.audit_store.append_request_in(tx,audit,200,"success").await?;}
            Ok(response)
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub async fn action_event(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,id,input,audit),|ctx,tx|Box::pin(async move{
            let (service,p,id,input,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(service,tx,p).await?;
            let mut run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(&service.policy_reader,tx,run.source).await?;let now=storage::now(tx).await?;
            let allowed=plan.authorized_in(service,tx,&run.target,now).await?;
            if matches!(input.event(),wire::TaskEvent::Start|wire::TaskEvent::Received) && !allowed{return Err(Error::Forbidden.into());}
            if run.state.attempt()!=Some(input.attempt_id()){return Err(Error::Conflict.into());}
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(&(id,input))?;
            let event_key = format!("agent:{}:task:{id}:event:{}",p.registration(),input.operation_id());
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if response.get("permit").filter(|p|!p.is_null()).and_then(|p|p["payload"]["expiresAt"].as_i64()).is_some_and(|expiry|expiry<=now){return Err(Error::Conflict.into());}
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                let fact=if let Some(details)=db::audit_details(tx,&actor,input.operation_id()).await? {fact.with_details(details)?}else{fact};
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);}
            let mut permit=None;
            let mut software_audit=None;
            match input.event() {
                wire::TaskEvent::EnrollmentResult { outcome } => {
                    if !matches!(plan,db::ScheduledPolicy::Enrollment(_)) { return Err(Error::Malformed.into()); }
                    if *outcome==wire::EnrollmentEntryOutcome::Unknown {
                        run.state.uncertain_result(input.attempt_id())?;
                    } else {
                        run.state.result(input.attempt_id(),*outcome==wire::EnrollmentEntryOutcome::Opened)?;
                    }
                    run.result=Some(json!({"entryOutcome":outcome}));
                },
                wire::TaskEvent::Received=>run.state.received(input.attempt_id(),now)?,
                wire::TaskEvent::Start=>{
                    if run.state.execution!=Execution::NotStarted{return Err(Error::Conflict.into());}
                    if matches!(&plan,db::ScheduledPolicy::Software(_)) {
                        let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let run_id=id.to_string();
                        let offer:Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt).bind(run_id).fetch_one(c).await})).await?;
                        let signed:wire::SignedTask=stored(serde_json::from_value(offer))?;
                        let wire::TaskPayload::Software(offered)=signed.payload else {return Err(Error::Malformed.into());};
                        let current=plan.task(service,tx,&run.target,db::TaskIssue {run:id,attempt:input.attempt_id(),permit:wire::TaskPermit::Offer,expiry:offered.expires_at}).await?;
                        let wire::TaskPayload::Software(current)=current else {return Err(Error::Malformed.into());};
                        if current.steps!=offered.steps || current.definition_digest!=offered.definition_digest {return Err(Error::Forbidden.into());}
                    }
                    run.state.start(input.attempt_id(),now)?;
                    let signed=service.signer.as_ref().ok_or(Error::Unsupported)?.sign(plan.task(service,tx,&run.target,db::TaskIssue { run:id,attempt:input.attempt_id(),permit:wire::TaskPermit::Start,expiry:(now+15).min(run.deadline) }).await?)?;
                    let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let value=checked_input(serde_json::to_value(&signed))?;
                    let changed=tx.with_connection(move|c|Box::pin(async move{Ok(sqlx::query("UPDATE mdm_commands.action_attempts SET permit=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND permit IS NULL").bind(tenant).bind(attempt).bind(value).execute(c).await?.rows_affected())})).await?;
                    if changed!=1{return Err(Error::Conflict.into());}
                    permit=Some(signed);
                },
                wire::TaskEvent::Cancelled=>{run.state.cancel();run.state.cancelled(input.attempt_id())?;},
                wire::TaskEvent::Result(result)=>{
                    let db::ScheduledPolicy::Script(script)=&plan else { return Err(Error::Malformed.into()); };
                    let output=result.output();
                    let schema_valid=script.frozen.definition.validate_output(output).is_ok();
                    let success=result.exit_code()==Some(0) && result.quality()==wire::OutputQuality::Complete && schema_valid;
                    let trusted=success && allowed && run.state.trusts_result(now,plan.timeout_seconds());
                    run.state.result(input.attempt_id(),success)?;
                    super::collection::accept(tx,&script.frozen,&run,output,trusted,now).await?;
                    run.result=Some(json!({"exitCode":result.exit_code(),"quality":result.quality(),"schemaValid":schema_valid,"output":output,"diagnostics":result.diagnostics(),"trusted":trusted}));
                },
                wire::TaskEvent::SoftwareResult(result) => {
                    let db::ScheduledPolicy::Software(software)=&plan else { return Err(Error::Malformed.into()); };
                    let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let run_id=id.to_string();
                    let offer:Value=tx.with_connection(move|c|Box::pin(async move{
                        sqlx::query_scalar("SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid")
                            .bind(tenant).bind(attempt).bind(run_id).fetch_one(c).await
                    })).await?;
                    let signed:wire::SignedTask=stored(serde_json::from_value(offer))?;
                    let wire::TaskPayload::Software(spec)=signed.payload else { return Err(Error::Malformed.into()); };
                    let expected_version=spec.steps.last().map(|s|s.action.version.as_str()).ok_or(Error::Malformed)?;
                    let intended=match software.intent() {
                        rss_mdm_policy::SoftwareIntent::RequiredInstall | rss_mdm_policy::SoftwareIntent::AvailableInstall => wire::SoftwareTaskIntent::Install,
                        rss_mdm_policy::SoftwareIntent::ExplicitUninstall => wire::SoftwareTaskIntent::Uninstall,
                    };
                    if result.intent!=intended || spec.intent!=intended
                        || spec.definition_digest!=result.definition_digest { return Err(Error::Malformed.into()); }
                    let late_detection=matches!(run.state.execution,Execution::Unknown | Execution::WaitingReboot)
                        && run.state.attempt()==Some(input.attempt_id())
                        && run.state.cancellation==Cancellation::None;
                    let trusted=allowed && (run.state.trusts_result(now,plan.timeout_seconds()) || late_detection);
                    let matches_intent=match (result.intent,result.detection) {
                        (wire::SoftwareTaskIntent::Install,wire::SoftwareDetectionState::Present)
                        | (wire::SoftwareTaskIntent::Detect,wire::SoftwareDetectionState::Present) =>
                            result.observed_version.as_deref()==Some(expected_version),
                        (wire::SoftwareTaskIntent::Uninstall,wire::SoftwareDetectionState::Absent) => true,
                        _ => false,
                    };
                    let effect=if !trusted || result.detection==wire::SoftwareDetectionState::Unknown {
                        run.state.uncertain_result(input.attempt_id())?;"unknown"
                    } else if result.reboot_required {
                        run.state.waiting_reboot(input.attempt_id())?;"waiting_reboot"
                    } else if matches_intent {
                        run.state.result(input.attempt_id(),true)?;"verified"
                    } else {
                        run.state.result(input.attempt_id(),false)?;"failed"
                    };
                    let previous_effect=run.result.as_ref().and_then(|v|v["effect"].as_str()).map(str::to_owned);
                    software_audit=Some(json!({"taskId":id,"attemptId":input.attempt_id(),"previousEffect":previous_effect,
                        "effect":effect,"detection":result.detection,"definitionDigest":result.definition_digest,
                        "evidenceDigest":result.evidence_digest,"rebootRequired":result.reboot_required}));
                    run.result=Some(json!({"intent":result.intent,"installerExitCode":result.installer_exit_code,
                        "detection":result.detection,"definitionDigest":result.definition_digest,
                        "observedVersion":result.observed_version,"evidenceDigest":result.evidence_digest,
                        "rebootRequired":result.reboot_required,
                        "diagnostics":result.diagnostics,"effect":effect}));
                },
            }
            db::save_run(tx,&run).await?;let response=checked_input(serde_json::to_value(wire::TaskEventAck::new(permit,!allowed || run.state.cancellation!=Cancellation::None)))?;
            let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
            let fact=if let Some(details)=software_audit.clone() {fact.with_details(details)?}else{fact};
            db::receipt(tx,&actor,input.operation_id(),hash,&response,software_audit).await?;
            service.audit_store.append_in(tx,&fact,false).await?;Ok(response)
        }),crate::transaction::TransactionOwner::Execution).await
    }
    pub async fn action_content(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        attempt: Uuid,
        key: Option<&str>,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_content_service::Verified, Error> {
        let artifact = self.authorize_content(p, id, attempt, key, audit).await?;
        let verified = self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify(&artifact)
            .await?;
        let current = self.authorize_content(p, id, attempt, key, audit).await?;
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
        key: Option<&str>,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_resource::Artifact, Error> {
        audit.require_request_settlement();
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p,id,attempt,key,audit),|ctx,tx|Box::pin(async move{
            let (service,p,id,attempt,key,audit)=*ctx;storage::lock(tx,p.device()).await?;principal(service,tx,p).await?;
            let run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(&service.policy_reader,tx,run.source).await?;let now=storage::now(tx).await?;
            if run.state.attempt()!=Some(attempt) || run.deadline<=now || run.state.cancellation!=Cancellation::None
                || !matches!(run.state.execution, Execution::NotStarted | Execution::Running)
                || !plan.authorized_in(service,tx,&run.target,now).await? {return Err(Error::Forbidden.into());}
            let tenant=tx.tenant_id().to_string();let expiry=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,i64>("SELECT (offer->'payload'->>'expiresAt')::bigint FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt.to_string()).bind(id.to_string()).fetch_one(c).await})).await?;
            if now>=expiry { return Err(Error::Forbidden.into()); }
            match plan {
                db::ScheduledPolicy::Enrollment(_) => Err(Error::NotFound.into()),
                db::ScheduledPolicy::Script(script) => {
                    if key.is_some() { return Err(Error::Malformed.into()); }
                    script.frozen.artifact().map_err(Into::into)
                }
                db::ScheduledPolicy::Software(software) => {
                    let key = key.ok_or(Error::Malformed)?;
                    let (index,local_key)=key.split_once('/').ok_or(Error::Malformed)?;
                    let index:usize=index.parse().map_err(|_|Error::Malformed)?;
                    let (platform, architecture) = db::agent_profile_in(service,tx, run.target.registration).await?.ok_or(Error::Forbidden)?;
                    let steps=software.execution_steps_in(service,tx,platform,architecture).await?;
                    let selected=steps.get(index).ok_or(Error::NotFound)?;
                    let variant = selected.version().resolve(selected.platform(),selected.architecture(),selected.variant()).map_err(|_| Error::Malformed)?;
                    let rss_mdm_resource::Declaration::Software { definition } = variant.declaration() else { return Err(Error::Malformed.into()); };
                    let artifact=definition.spec().artifacts.get(local_key).ok_or(Error::NotFound)?;
                    let tenant=tx.tenant_id().to_string();let attempt_id=attempt.to_string();let run_id=id.to_string();
                    let offer:Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt_id).bind(run_id).fetch_one(c).await})).await?;
                    let signed:wire::SignedTask=stored(serde_json::from_value(offer))?;
                    let wire::TaskPayload::Software(spec)=signed.payload else {return Err(Error::Malformed.into());};
                    let offered=spec.steps.get(index).and_then(|s|s.artifacts.iter().find(|a|a.key==key)).ok_or(Error::Forbidden)?;
                    if offered.length!=artifact.length || offered.sha256!=artifact.sha256 {return Err(Error::Forbidden.into());}
                    artifact.artifact().map_err(|_| Error::Malformed.into())
                }
            }
        }),crate::transaction::TransactionOwner::Execution).await
    }
}

use rss_mdm_audit_integration::RequestAudit;
