use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::transaction::fingerprint;
use crate::{Error, device::DevicePrincipal};
use crate::{ExecutionService, Result, checked_input, storage, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::Fact;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) async fn principal(
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
    let enabled = crate::channels::agent_binding_in(
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
pub(crate) fn belongs(run: &db::Run, p: &DevicePrincipal) -> Result<()> {
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
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,
            (self,p,input,audit),|ctx,tx|Box::pin(async move{
            let (service,p,input,audit)=*ctx;crate::transaction::lock_authority(service,tx).await?;super::native_recovery::lock_device(tx,p.device()).await?;principal(service,tx,p).await?;crate::script_eligibility::announce_in(tx,p.registration(),input).await?;crate::channels::agent_context_in(tx,service.agent_store.clone(),p.registration(),input.execution_context()).await?;
            let communication = p.clone();
            tx.with_connection(move |c| Box::pin(async move {
                Ok(crate::device::store::record_communication_in(c, &communication).await)
            })).await??;
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(input)?;let now=storage::now(tx).await?;
            let event_key = format!("agent:{}:offer:{}",p.registration(),input.operation_id());
            // Old successful polls are replayable only while their exact offer remains authorized.
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if let Some(task)=response.get("task").filter(|v|!v.is_null()) {
                    let id=stored(Uuid::parse_str(task["payload"]["task"]["taskId"].as_str().ok_or(Error::Conflict)?))?;
                    let run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&run.id.to_string());
                    let replay_attempt=task["payload"]["task"]["attemptId"].as_str().and_then(|v|Uuid::parse_str(v).ok());
                    if run.state.cancellation!=Cancellation::None || run.state.execution!=Execution::NotStarted || run.state.attempt()!=replay_attempt || replay_attempt.is_none(){return Err(Error::Conflict.into());}
                    let signed:wire::SignedTask=stored(serde_json::from_value(task.clone()))?;
                    let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
                    if signed.payload.expires_at()<=now || run.state.attempt()!=Some(signed.payload.attempt_id()) || !plan.authorized_run_in(service,tx,&run,now).await?{return Err(Error::Conflict.into());}
                }
                crate::transaction::prepare_audit_in(&service.audit_store,tx,audit,&[]).await?;
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);
            }
            let binding=crate::channels::agent_binding_in(tx,service.agent_store.clone(),p.registration()).await?.ok_or(Error::Forbidden)?;
            let (software_capable,enrollment_capable)=(binding.software(),binding.enrollment());
            let versions = crate::sources::admission::agent_versions_in(tx,p.registration()).await?
                .into_iter().map(|version| (version, Uuid::new_v4())).collect::<Vec<_>>();
            let existing = super::poll::offer_candidates(tx,p.registration(),now).await?;
            let mut partitions = vec![
                rss_mdm_audit_integration::source_partition(tx.tenant_id(), "device", p.device())?,
                rss_mdm_audit_integration::source_partition(tx.tenant_id(), "mdm", "request")?,
            ];
            for id in existing.iter().cloned().chain(versions.iter().map(|(_, id)| id.to_string())) {
                partitions.push(rss_mdm_audit_integration::source_partition(tx.tenant_id(), "mdm", &id)?);
            }
            let access = if binding.capabilities.contains(&wire::Capability::DeviceAccessV1) {
                let prepared=crate::device_access::prepare_reconciliation_in(service,tx,p).await?;
                partitions.extend(prepared.partitions.iter().cloned());
                Some(prepared)
            } else { None };
            crate::transaction::prepare_audit_in(&service.audit_store,tx,audit,&partitions).await?;
            for (id, run_id) in versions {
                let policy=db::load_policy_version(&service.policy_reader,tx,id).await?;
                let target=crate::Target {device:p.device().into(),registration:p.registration(),generation:p.generation()};
                match &policy {
                    db::ScheduledPolicy::Credential(v) if crate::credential_tasks::capable(&binding,v.frozen.input.architecture) => super::production::accept_for_device(service,tx,&policy,&target,super::production::AdmissionTrigger::Agent(input.operation_id()),now,run_id).await?,
                    db::ScheduledPolicy::AgentCollection(v) if crate::agent_collection_eligibility::matches(&binding,v.frozen.input.platform,v.frozen.input.architecture,&v.frozen.definition,input.environment()) => super::production::accept_for_device(service,tx,&policy,&target,super::production::AdmissionTrigger::Agent(input.operation_id()),now,run_id).await?,
                    db::ScheduledPolicy::Enrollment(_) if enrollment_capable => super::production::accept_for_device(service,tx,&policy,&target,super::production::AdmissionTrigger::Agent(input.operation_id()),now,run_id).await?,
                    db::ScheduledPolicy::Script(script) if crate::script_eligibility::matches(&binding,script.frozen.input.platform,script.frozen.input.architecture,script.frozen.executor_profile(),input.profiles()) => super::production::accept_for_device(service,tx,&policy,&target,super::production::AdmissionTrigger::Agent(input.operation_id()),now,run_id).await?,
                    db::ScheduledPolicy::Software(software) if software_capable => super::software::accept_for_device(service,tx,software,&target,now,run_id).await?,
                    _ => (),
                }
            }
            if let Some(prepared)=access { crate::device_access::reconcile_in(service,tx,prepared,now,audit).await?; }
            let ids=super::poll::offer_candidates(tx,p.registration(),now).await?;
            let mut offer=None;
            for id in ids {
                let mut run=db::load_run(tx,stored(Uuid::parse_str(&id))?).await?;belongs(&run,p)?;let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
                let previous=run.state.clone();
                run.state.expire(now,plan.timeout_seconds());
                let capable=match &plan { db::ScheduledPolicy::DeviceAccess(_) => binding.capabilities.contains(&wire::Capability::DeviceAccessV1), db::ScheduledPolicy::Retirement(_) => binding.capabilities.contains(&wire::Capability::DeviceUnmanageV1), db::ScheduledPolicy::Credential(v) => crate::credential_tasks::capable(&binding,v.frozen.input.architecture), db::ScheduledPolicy::Native(_) => false, db::ScheduledPolicy::AgentCollection(v) => crate::agent_collection_eligibility::matches(&binding,v.frozen.input.platform,v.frozen.input.architecture,&v.frozen.definition,input.environment()), db::ScheduledPolicy::Script(script) => crate::script_eligibility::matches(&binding,script.frozen.input.platform,script.frozen.input.architecture,script.frozen.executor_profile(),input.profiles()), db::ScheduledPolicy::Software(software) => software.assignment.supported_in(&service.admission(),tx,&binding).await?, db::ScheduledPolicy::Enrollment(_) => enrollment_capable };
                let allowed=capable && plan.authorized_run_in(service,tx,&run,now).await?;
                if (!allowed && run.invocation.is_some()) || plan.withdrawn_in(service,tx,&run.target,now).await?{run.state.cancel();}
                super::recovery::audit_recovery(service,tx,&run,&previous).await?;
                if run.state.cancellation==Cancellation::None && run.available_at<=now && allowed {
                    let attempt=Uuid::new_v4();
                    let previous_attempt=run.state.attempt();
                    if run.state.claim(attempt,now).is_ok(){
                        if let Some(old)=previous_attempt {super::collection::abandon(service,tx,old,"superseded").await?;}
                        if let db::ScheduledPolicy::Script(script)=&plan {super::collection::reserve(tx,&script.frozen,&run,now).await?;}
                        let payload=plan.task(service,tx,&run.target,db::TaskIssue { run:run.id,attempt,permit:wire::TaskPermit::Offer,expiry:(now+60).min(run.deadline) }).await?;
                        if let (db::ScheduledPolicy::AgentCollection(v), wire::TaskPayload::Collection(spec))=(&plan,&payload) {super::agent_collection::reserve(tx,&v.frozen,&run,spec,now).await?;}
                        let signer=service.signer.as_ref().ok_or(Error::Unsupported)?;
                        require_signing_trust(tx,p,signer).await?;
                        let signed=signer.sign(payload)?;
                        let tenant=tx.tenant_id().to_string();let run_id=run.id.to_string();let reg=p.registration().to_string();let value=checked_input(serde_json::to_value(&signed))?;
                        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_commands.action_attempts(tenant_id,id,run,registration,claimed_at,offer) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6)").bind(tenant).bind(attempt.to_string()).bind(run_id).bind(reg).bind(now).bind(value).execute(c).await?;Ok(())})).await?;
                        super::evidence::persist_in(tx, run.id, attempt, &signed.payload).await?;
                        run.source.audit(audit);audit.target(&run.id.to_string());offer=Some(signed);
                    }
                }
                db::save_run(tx,&run).await?;crate::unmanage::wake_device_in(&service.reconcile_messaging, tx,&run.target.device).await?;
                if offer.is_some(){break;}
            }
            let cancellations=super::poll::cancellations(tx,p.registration()).await?;
            let has_offer=offer.is_some();
            let response=checked_input(serde_json::to_value(checked_input(wire::TaskClaimResponse::new(offer,cancellations))?))?;
            if has_offer{
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                db::receipt(tx,&actor,input.operation_id(),hash,&response,None).await?;
                service.audit_store.append_in(tx,&fact,false).await?;
            }
            Ok(response)
        })).await
    }
    pub async fn action_event(
        &self,
        p: &DevicePrincipal,
        id: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        audit.target(&id.to_string());
        let partitions = [
            rss_mdm_audit_integration::source_partition(self.tenant, "mdm", "request")
                .map_err(Error::from)?,
            rss_mdm_audit_integration::source_partition(self.tenant, "device", p.device())
                .map_err(Error::from)?,
        ];
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,id,input,audit,&partitions),|ctx,tx|Box::pin(async move{
            let (service,p,id,input,audit,partitions)=*ctx;crate::transaction::lock_authority(service,tx).await?;super::native_recovery::lock_device(tx,p.device()).await?;principal(service,tx,p).await?;crate::channels::agent_context_in(tx,service.agent_store.clone(),p.registration(),input.execution_context()).await?;
            let mut run=db::load_run(tx,id).await?;belongs(&run,p)?;crate::transaction::prepare_audit_in(&service.audit_store,tx,audit,partitions).await?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
            if matches!(&plan, db::ScheduledPolicy::Script(_)) { audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(rss_mdm_audit_integration::SensitiveAction::ScriptContentRead)); }
            let now=storage::now(tx).await?;
            let requires_start_authority = matches!(input.event(), wire::TaskEvent::Start | wire::TaskEvent::Received) || run.state.started_at.is_none();
            let allowed = if requires_start_authority { plan.authorized_run_in(service,tx,&run,now).await? } else { plan.completion_authorized_in(service,tx,&run.target,now).await? };
            let effect_allowed = allowed && run.state.cancellation == Cancellation::None;
            if matches!(input.event(),wire::TaskEvent::Start|wire::TaskEvent::Received) && !allowed{return Err(Error::Forbidden.into());}
            if run.state.attempt()!=Some(input.attempt_id()){return Err(Error::Conflict.into());}
            let actor=format!("agent:{}",p.registration());let hash=fingerprint(&(id,input))?;
            let event_key = format!("agent:{}:task:{id}:event:{}",p.registration(),input.operation_id());
            if let Some(response)=db::replay(tx,&actor,input.operation_id(),&hash).await?{
                if response.get("permit").filter(|p|!p.is_null()).and_then(|p|p["payload"]["task"]["expiresAt"].as_i64()).is_some_and(|expiry|expiry<=now){return Err(Error::Conflict.into());}
                audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
                let fact=if let Some(details)=db::audit_details(tx,&actor,input.operation_id()).await? {fact.with_details(details)?}else{fact};
                service.audit_store.append_in(tx,&fact,true).await?;return Ok(response);}
            let mut permit=None;
            let mut credentials=Vec::new();
            let mut software_audit=None;
            match input.event() {
                wire::TaskEvent::DeviceAccessPrepared(value) => {
                    if !matches!(plan,db::ScheduledPolicy::DeviceAccess(_)) || !matches!(run.state.execution,Execution::Running|Execution::Unknown) || run.state.started_at.is_none() { return Err(Error::Forbidden.into()); }
                    crate::device_access::provisioning::prepared(tx,&run,input,value).await?;
                }
                wire::TaskEvent::DeviceAccessResult(value) => {
                    let db::ScheduledPolicy::DeviceAccess(access_plan) = &plan else { return Err(Error::Forbidden.into()); };
                    let access_complete = value.effect.complete(&access_plan.binding.configuration);
                    if !matches!(plan,db::ScheduledPolicy::DeviceAccess(_)) || !matches!(run.state.execution,Execution::Running|Execution::Unknown) || run.state.started_at.is_none() { return Err(Error::Forbidden.into()); }
                    crate::device_access::finish_in(tx,&run,input,value,effect_allowed).await?;
                    if crate::device_access::provisioning::unresolved(tx,&run,input.attempt_id(),!matches!(value.effect,wire::AccessEffect::Unknown) && (!matches!(value.effect,wire::AccessEffect::Applied { .. }) || access_complete)).await? || matches!(value.effect,wire::AccessEffect::Unknown) || matches!(value.effect,wire::AccessEffect::Applied{..}) && !access_complete {run.state.uncertain_result(input.attempt_id())?;}
                    else {run.state.result(input.attempt_id(),access_complete)?;}
                    run.result=Some(checked_input(serde_json::to_value(value))?);
                }
                wire::TaskEvent::CredentialEscrow(value) => {
                    if !matches!(plan,db::ScheduledPolicy::Credential(_) | db::ScheduledPolicy::DeviceAccess(_)) || !effect_allowed || !matches!(run.state.execution,Execution::Running|Execution::Unknown) || run.state.started_at.is_none() { return Err(Error::Forbidden.into()); }
                    credentials = if matches!(plan,db::ScheduledPolicy::DeviceAccess(_)) {
                        crate::device_access::provisioning::escrow(service,tx,&run,input.attempt_id(),value).await?
                    } else { crate::credential_tasks::escrow(service,tx,&run,input.attempt_id(),value).await? };
                    if !run.state.trusts_result(now,plan.timeout_seconds()) {
                        run.state.uncertain_result(input.attempt_id())?;
                        let tenant=checked_input(Uuid::parse_str(&service.tenant.to_string()))?;
                        tx.with_connection(move|c|Box::pin(async move{Ok(rss_mdm_recovery_credentials::storage::unknown_in(c,tenant,id).await)})).await?.map_err(crate::recovery_credentials::error)?;
                    }
                },
                wire::TaskEvent::CredentialResult(value) => {
                    if !matches!(plan,db::ScheduledPolicy::Credential(_)) || !effect_allowed || !matches!(run.state.execution,Execution::Running|Execution::Unknown) || run.state.started_at.is_none() || !run.state.trusts_result(now,plan.timeout_seconds()) { return Err(Error::Forbidden.into()); }
                    match crate::credential_tasks::finish(service,tx,&run,input.attempt_id(),value).await? {
                        Execution::Unknown=>run.state.uncertain_result(input.attempt_id())?,
                        Execution::Succeeded=>run.state.result(input.attempt_id(),true)?,
                        Execution::Failed=>run.state.result(input.attempt_id(),false)?,
                        _=>return Err(Error::Conflict.into()),
                    }
                    run.result=Some(checked_input(serde_json::to_value(value))?);
                },
                wire::TaskEvent::UnmanageResult { outcome } => {
                    if !matches!(plan,db::ScheduledPolicy::Retirement(_)) {return Err(Error::Malformed.into());}
                    if *outcome==wire::UnmanageOutcome::Unknown {run.state.uncertain_result(input.attempt_id())?;}
                    else {run.state.result(input.attempt_id(),*outcome==wire::UnmanageOutcome::Completed)?;}
                    run.result=Some(json!({"unmanageOutcome":outcome}));
                },
                wire::TaskEvent::EnrollmentResult { outcome } => {
                    if !matches!(plan,db::ScheduledPolicy::Enrollment(_)) { return Err(Error::Malformed.into()); }
                    if *outcome==wire::EnrollmentEntryOutcome::Unknown {
                        run.state.uncertain_result(input.attempt_id())?;
                    } else {
                        run.state.result(input.attempt_id(),*outcome==wire::EnrollmentEntryOutcome::Opened)?;
                    }
                    run.result=Some(json!({"entryOutcome":outcome}));
                },
                wire::TaskEvent::Received=>{run.state.received(input.attempt_id(),now)?;if matches!(plan,db::ScheduledPolicy::DeviceAccess(_)){crate::device_access::received_in(tx,&run).await?;}},
                wire::TaskEvent::Start=>{
                    if run.state.execution!=Execution::NotStarted{return Err(Error::Conflict.into());}
                    if matches!(&plan,db::ScheduledPolicy::DeviceAccess(_) | db::ScheduledPolicy::Credential(_) | db::ScheduledPolicy::Script(_) | db::ScheduledPolicy::AgentCollection(_)) {
                        let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id();let run_id=id;
                        let offer:Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2 AND run=$3").bind(tenant).bind(attempt).bind(run_id).fetch_one(c).await})).await?;
                        let offered:wire::SignedTask=stored(serde_json::from_value(offer))?;
                        let current=plan.task(service,tx,&run.target,db::TaskIssue{run:id,attempt:input.attempt_id(),permit:wire::TaskPermit::Offer,expiry:offered.payload.expires_at()}).await?;
                        if current!=offered.payload {return Err(Error::Forbidden.into());}
                    }
                    if matches!(&plan,db::ScheduledPolicy::Software(_)) {
                        let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let run_id=id.to_string();
                        let offer:Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt).bind(run_id).fetch_one(c).await})).await?;
                        let signed:wire::SignedTask=stored(serde_json::from_value(offer))?;
                        let wire::TaskPayload::Software(offered)=signed.payload else {return Err(Error::Malformed.into());};
                        let current=plan.task(service,tx,&run.target,db::TaskIssue {run:id,attempt:input.attempt_id(),permit:wire::TaskPermit::Offer,expiry:offered.expires_at}).await?;
                        let wire::TaskPayload::Software(current)=current else {return Err(Error::Malformed.into());};
                        if current.steps!=offered.steps || current.definition_digest!=offered.definition_digest || current.execution_context!=offered.execution_context {return Err(Error::Forbidden.into());}
                    }
                    if matches!(plan,db::ScheduledPolicy::Credential(_)) {crate::credential_tasks::start(service,tx,&run,input.attempt_id()).await?;}
                    run.state.start(input.attempt_id(),now)?;
                    require_signing_trust(tx,p,service.signer.as_ref().ok_or(Error::Unsupported)?).await?;
                    let signed=service.signer.as_ref().ok_or(Error::Unsupported)?.sign(plan.task(service,tx,&run.target,db::TaskIssue { run:id,attempt:input.attempt_id(),permit:wire::TaskPermit::Start,expiry:(now+15).min(run.deadline) }).await?)?;
                    let tenant=tx.tenant_id().to_string();let attempt=input.attempt_id().to_string();let value=checked_input(serde_json::to_value(&signed))?;
                    let changed=tx.with_connection(move|c|Box::pin(async move{Ok(sqlx::query("UPDATE mdm_commands.action_attempts SET permit=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND permit IS NULL").bind(tenant).bind(attempt).bind(value).execute(c).await?.rows_affected())})).await?;
                    if changed!=1{return Err(Error::Conflict.into());}
                    super::evidence::persist_in(tx, id, input.attempt_id(), &signed.payload).await?;
                    permit=Some(signed);
                },
                wire::TaskEvent::Cancelled=>{run.state.cancel();
                    if matches!(plan,db::ScheduledPolicy::DeviceAccess(_)) && run.state.started_at.is_some()
                        && crate::device_access::provisioning::unresolved(tx,&run,input.attempt_id(),true).await? {
                        run.state.uncertain_result(input.attempt_id())?;
                    } else { run.state.cancelled(input.attempt_id())?; }super::collection::abandon(service,tx,input.attempt_id(),"revoked").await?;},
                wire::TaskEvent::Result(result)=>{
                    let db::ScheduledPolicy::Script(script)=&plan else {return Err(Error::Malformed.into());};
                    super::collection::finish(tx,&script.frozen,&mut run,result,allowed,effect_allowed,now).await?;
                },
                wire::TaskEvent::CollectionResult(result)=>{
                    let db::ScheduledPolicy::AgentCollection(v)=&plan else{return Err(Error::Malformed.into());};
                    super::agent_collection::finish(tx,&v.frozen,&mut run,result,effect_allowed,now).await?;
                },
                wire::TaskEvent::ChunkedCollectionResult{manifest}=>{
                    let db::ScheduledPolicy::AgentCollection(v)=&plan else{return Err(Error::Malformed.into());};
                    if v.frozen.definition.spec().plan.requires_inline() {return Err(Error::Malformed.into());}
                    let result=super::output::assemble_native(tx,&plan,&run,manifest).await?;
                    super::agent_collection::finish(tx,&v.frozen,&mut run,&result,effect_allowed,now).await?;
                },
                wire::TaskEvent::OutputChunk(chunk)=>super::output::append(tx,&plan,&run,chunk).await?,
                wire::TaskEvent::ChunkedResult(reference)=>{
                    let result=super::output::assemble(tx,&plan,&run,reference).await?;
                    let db::ScheduledPolicy::Script(script)=&plan else {return Err(Error::Malformed.into());};
                    super::collection::finish(tx,&script.frozen,&mut run,&result,allowed,effect_allowed,now).await?;
                },
                wire::TaskEvent::SoftwareResult(result) => {
                    let db::ScheduledPolicy::Software(software)=&plan else { return Err(Error::Malformed.into()); };
                    let super::evidence::Material::Software { platform: _, intent, definition_digest, steps } = super::evidence::load_in(tx,id,input.attempt_id()).await? else { return Err(Error::Malformed.into()); };
                    let assessment=rss_mdm_software_service::preparation::evidence::assess_execution(result,intent,definition_digest,&steps).map_err(|_|Error::Malformed)?;
                    let intended=match software.assignment.intent() {
                        rss_mdm_policy::SoftwareIntent::RequiredInstall | rss_mdm_policy::SoftwareIntent::AvailableInstall => wire::SoftwareTaskIntent::Install,
                        rss_mdm_policy::SoftwareIntent::ExplicitUninstall => wire::SoftwareTaskIntent::Uninstall,
                    };
                    if intent!=intended { return Err(Error::Malformed.into()); }
                    let late_detection=matches!(run.state.execution,Execution::Unknown | Execution::WaitingReboot)
                        && run.state.attempt()==Some(input.attempt_id())
                        && run.state.cancellation==Cancellation::None;
                    let trusted=effect_allowed && (run.state.trusts_result(now,plan.timeout_seconds()) || late_detection);
                    use rss_mdm_software_service::preparation::evidence::SoftwareEvidenceAssessment as Assessment;
                    let effect=match (trusted,assessment) {
                        (false,_) | (_,Assessment::Unknown) => {
                            run.state.uncertain_result(input.attempt_id())?;"unknown"
                        }
                        (true,Assessment::RebootPending) => {
                            run.state.waiting_reboot(input.attempt_id())?;"waiting_reboot"
                        }
                        (true,Assessment::Satisfied) => {
                            run.state.result(input.attempt_id(),true)?;"verified"
                        }
                        (true,Assessment::Unsatisfied) => {
                            run.state.result(input.attempt_id(),false)?;"failed"
                        }
                    };
                    let previous_effect=run.result.as_ref().and_then(|v|v["effect"].as_str()).map(str::to_owned);
                    let evidence=checked_input(serde_json::to_value(result))?;
                    software_audit=Some(json!({"taskId":id,"attemptId":input.attempt_id(),"previousEffect":previous_effect,
                        "effect":effect,"definitionDigest":result.definition_digest,"steps":result.steps}));
                    let observed_at:i64=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint").fetch_one(c).await})).await?;
                    run.result=Some(json!({"intent":result.intent,"definitionDigest":result.definition_digest,"evidence":evidence,"effect":effect,"effectObservedAt":observed_at}));
                },
            }
            db::save_run(tx,&run).await?;crate::unmanage::wake_device_in(&service.reconcile_messaging, tx,&run.target.device).await?;let response=checked_input(serde_json::to_value(wire::TaskEventAck::new(permit,!allowed || run.state.cancellation!=Cancellation::None).with_credentials(credentials)))?;
            let fact=Fact::business(audit,&event_key,&hash,200,"success",None)?;
            let fact=if let Some(details)=software_audit.clone() {fact.with_details(details)?}else{fact};
            db::receipt(tx,&actor,input.operation_id(),hash,&response,software_audit).await?;
            service.audit_store.append_in(tx,&fact,false).await?;Ok(response)
        })).await
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
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p,id,attempt,key,audit),|ctx,tx|Box::pin(async move{
            let (service,p,id,attempt,key,audit)=*ctx;crate::transaction::lock_authority(service,tx).await?;super::native_recovery::lock_device(tx,p.device()).await?;principal(service,tx,p).await?;
            let run=db::load_run(tx,id).await?;belongs(&run,p)?;run.source.audit(audit);audit.target(&id.to_string());let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
            if matches!(&plan, db::ScheduledPolicy::Script(_)) { audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(rss_mdm_audit_integration::SensitiveAction::ScriptContentRead)); }
            let now=storage::now(tx).await?;
            let allowed=if run.state.started_at.is_some() {plan.completion_authorized_in(service,tx,&run.target,now).await?} else {plan.authorized_run_in(service,tx,&run,now).await?};
            if run.state.attempt()!=Some(attempt) || run.deadline<=now || run.state.cancellation!=Cancellation::None
                || !matches!(run.state.execution, Execution::NotStarted | Execution::Running)
                || !allowed {return Err(Error::Forbidden.into());}
            let tenant=tx.tenant_id().to_string();let expiry=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar::<_,i64>("SELECT (offer->'payload'->'task'->>'expiresAt')::bigint FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2::uuid AND run=$3::uuid").bind(tenant).bind(attempt.to_string()).bind(id.to_string()).fetch_one(c).await})).await?;
            if now>=expiry { return Err(Error::Forbidden.into()); }
            match plan {
                db::ScheduledPolicy::Retirement(_) => Err(Error::Unsupported.into()),
                db::ScheduledPolicy::Enrollment(_) => Err(Error::NotFound.into()),
                db::ScheduledPolicy::DeviceAccess(_) | db::ScheduledPolicy::Credential(_) | db::ScheduledPolicy::Native(_) | db::ScheduledPolicy::AgentCollection(_) => Err(Error::Forbidden.into()),
                db::ScheduledPolicy::Script(script) => {
                    if key.is_some() { return Err(Error::Malformed.into()); }
                    script.frozen.artifact().map_err(Into::into)
                }
                db::ScheduledPolicy::Software(software) => {
                    let key = key.ok_or(Error::Malformed)?;
                    let (index,local_key)=key.split_once('/').ok_or(Error::Malformed)?;
                    let index:usize=index.parse().map_err(|_|Error::Malformed)?;
                    let (platform, architecture) = db::agent_profile_in(service,tx, run.target.registration).await?.ok_or(Error::Forbidden)?;
                    let artifact=software.assignment.artifact_in(&service.admission(),tx,platform,architecture,index,local_key).await?;
                    let super::evidence::Material::Software { steps, .. }=super::evidence::load_in(tx,id,attempt).await? else {return Err(Error::Malformed.into());};
                    let offered=steps.get(index).and_then(|s|s.artifacts.iter().find(|a|a.key==key)).ok_or(Error::Forbidden)?;
                    if offered.length!=artifact.length() || offered.sha256!=artifact.digest().bytes() {return Err(Error::Forbidden.into());}
                    Ok(artifact)
                }
            }
        })).await
    }
}

use rss_mdm_audit_integration::RequestAudit;

async fn require_signing_trust(
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    signer: &crate::task_signing::Signer,
) -> Result<()> {
    let p = p.clone();
    let key = signer.key_id().to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(crate::task_signing::trust::require_issue(c, &p, &key).await) })
    })
    .await??;
    Ok(())
}
