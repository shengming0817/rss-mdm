//! Targeted self-service calls use the existing Policy version, Run reducer and frequency.
use crate::{
    Error, ExecutionService, Result, Target,
    actions::{production, storage as db},
    authorization::{Permission, UserGrant, context::AuthorizedPrincipal},
    storage,
    transaction::*,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub authorization: wire::ScriptAuthorization,
    pub parameters: std::collections::BTreeMap<String, Value>,
    pub grant: UserGrant,
}
impl Invocation {
    pub async fn valid_in(
        &self,
        tx: &mut PgTransaction<'_>,
        script: &crate::sources::admission::ExecutionPolicy,
        now: i64,
    ) -> Result<bool> {
        let wire::ScriptAuthorization::SelfService {
            actor,
            source,
            policy_id,
            policy_revision,
            policy_version,
            allow_ai,
            risk_level,
            confirmed,
            ..
        } = &self.authorization
        else {
            return Ok(false);
        };
        let Some(policy) = script.policy() else {
            return Ok(false);
        };
        let Some(config) = &policy.definition.self_service else {
            return Ok(false);
        };
        let user = self.grant.user();
        if policy.id != *policy_id
            || policy.revision as u64 != *policy_revision
            || policy.version != *policy_version
            || !policy.enabled
            || !config.published
            || config.allow_ai != Some(*allow_ai)
            || config.risk_level.map(|r| r.value()) != Some(*risk_level)
            || (*source == wire::ScriptCaller::Ai
                && (!*allow_ai || (*risk_level == 2 && !*confirmed)))
            || user.tenant_id != actor.tenant_id.to_string()
            || user.instance_id != actor.instance_id.to_string()
            || user.principal_id != actor.principal_id.to_string()
        {
            return Ok(false);
        }
        let grant = self.grant.clone();
        let valid = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(grant.valid(c, Permission::ScriptExecute, now).await) })
            })
            .await?
            .map_err(Error::from)?;
        Ok(valid)
    }
}
impl ExecutionService {
    pub async fn self_service_directory(
        &self,
        p: &DevicePrincipal,
        proof: &AuthorizedPrincipal,
        input: &wire::SelfServiceDirectory,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if proof.tenant_id() != p.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        proof.require(Permission::ScriptExecute, Some(p.device()))?;
        proof.bind_audit(audit)?;
        if input.after.is_some_and(|id| id.is_nil()) {
            return Err(Error::Malformed);
        }
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,proof,input,audit),|ctx,tx|Box::pin(async move {
            let (service,p,proof,input,audit)=*ctx;
            storage::lock(tx,p.device()).await?;
            crate::actions::agent::principal(service,tx,p).await?;
            crate::action_admission::authorized(tx,proof,p.device(),Permission::ScriptExecute).await?;
            let tenant=tx.tenant_id().to_string();let after=input.after;
            let mut ids=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND enabled AND definition->'action'->>'kind'='execution' AND definition->'selfService'->>'published'='true' AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 65").bind(tenant).bind(after).fetch_all(c).await})).await?;
            let more=ids.len()>64;ids.truncate(64);let next=if more {ids.last().copied()} else {None};
            let target=Target{device:p.device().into(),registration:p.registration(),generation:p.generation()};
            let now=storage::now(tx).await?;let mut items=Vec::new();
            for id in ids {
                let Some(policy)=crate::sources::storage::read_in(&service.policy_reader,tx,id).await? else {continue};
                let script=crate::sources::admission::read_in(&service.policy_reader,tx,policy.version).await?;
                let Some(config)=policy.definition.self_service.as_ref() else {continue};
                if !policy.enabled || !config.published || (input.source==wire::ScriptCaller::Ai && config.allow_ai!=Some(true)) || !script.authorized_in(&service.source,tx,p.device(),now).await? || !crate::script_eligibility::require_in(tx,service.agent_store.clone(),&target,&script.frozen).await? {continue}
                items.push(wire::SelfServiceDirectoryItem{policy_id:id,policy_revision:policy.revision as u64,policy_version:policy.version,self_service:metadata(config)?,resource:script.frozen.resource.clone(),parameter_sources:parameter_sources(&script.frozen.parameters),parameter_schema:script.frozen.definition.spec().parameters.clone()});
            }
            proof.check_live()?;service.audit_store.append_request_in(tx,audit,200,"success").await?;
            json(&wire::SelfServiceDirectoryResponse{items,next_cursor:next,as_of:now})
        })).await
    }
    pub async fn invoke_self_service(
        &self,
        p: &DevicePrincipal,
        proof: &AuthorizedPrincipal,
        input: &wire::SelfServiceInvoke,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if proof.tenant_id() != p.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        proof.require(Permission::ScriptExecute, Some(p.device()))?;
        proof.bind_audit(audit)?;
        if input.operation_id.is_nil()
            || input.policy_id.is_nil()
            || input.policy_version.is_nil()
            || input.policy_revision == 0
            || input.policy_revision > i64::MAX as u64
            || input.parameters.len() > 32
            || serde_json::to_vec(input)
                .map_err(|_| Error::Malformed)?
                .len()
                > 131072
        {
            return Err(Error::Malformed);
        }
        audit.operation(input.operation_id, "command_accept");
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,proof,input,audit),|ctx,tx|Box::pin(async move {
            let (service,p,proof,input,audit)=*ctx;
            storage::lock(tx,p.device()).await?;
            crate::actions::agent::principal(service,tx,p).await?;
            let auth=crate::action_admission::authorized(tx,proof,p.device(),Permission::ScriptExecute).await?;
            let actor=format!("self-service:{}:{}:{}",proof.instance_id(),proof.principal_id(),p.registration());
            let hash=fingerprint(input)?;
            let event_key=format!("self-service:{}:{}",p.registration(),input.operation_id);
            if let Some(response)=db::replay(tx,&actor,input.operation_id,&hash).await? {
                proof.check_live()?;
                let fact=Fact::business(audit,&event_key,&hash,202,"success",None)?;service.audit_store.append_in(tx,&fact,true).await?;
                return Ok(response);
            }
            let policy=crate::sources::storage::read_in(&service.policy_reader,tx,input.policy_id).await?.ok_or(Error::NotFound)?;
            if policy.version!=input.policy_version || policy.revision as u64!=input.policy_revision {return Err(Error::Conflict.into())}
            let config=policy.definition.self_service.as_ref().ok_or(Error::Forbidden)?;
            let allow_ai=config.allow_ai.ok_or(Error::Forbidden)?;let risk=config.risk_level.ok_or(Error::Forbidden)?.value();
            if !policy.enabled || !config.published || (input.source==wire::ScriptCaller::Ai && (!allow_ai || (risk==2 && !input.confirmed))) {return Err(Error::Forbidden.into())}
            let script=crate::sources::admission::read_in(&service.policy_reader,tx,policy.version).await?;
            let now=storage::now(tx).await?;
            let target=Target{device:p.device().into(),registration:p.registration(),generation:p.generation()};
            let Some(entry)=script.entry_in(&service.source,tx,p.device(),now).await? else {return Err(Error::Forbidden.into())};
            if !crate::script_eligibility::require_in(tx,service.agent_store.clone(),&target,&script.frozen).await? {return Err(Error::Forbidden.into())}
            let parameters=script.frozen.parameters.resolve(&json!(input.parameters))?;
            script.frozen.definition.validate_parameters(&parameters).map_err(|_|Error::Malformed)?;
            let (pending,last)=production::policy_pending_in(tx,policy.id,policy.version,&target,now,false).await?;
            if pending || !production::check_in_interval_elapsed(&script.frozen.input.schedule.trigger,last,now) {return Err(Error::Conflict.into())}
            let occurrence=production::policy_occurrence(script.frequency,&target,&script.entry_source(),entry,&format!("self-service:{}",input.operation_id));
            if !production::occurrence_available_in(tx,policy.version,&target,&occurrence,now).await? {return Err(Error::Conflict.into())}
            let schedule=&script.frozen.input.schedule;
            let Some(slot)=schedule.occurrence(now,p.device().as_bytes())? else {return Err(Error::Conflict.into())};
            let available=slot.available_at.max(now);
            let deadline=available.checked_add(i64::from(script.frozen.input.run_lifetime_seconds)).ok_or(Error::Malformed)?.min(schedule.ends_at()).min(slot.window_end.unwrap_or(i64::MAX));
            if deadline<=available {return Err(Error::Conflict.into())}
            let decision=wire::ScriptAuthorization::SelfService {request_id:input.operation_id,actor:wire::ScriptActor{tenant_id:checked_input(Uuid::parse_str(proof.tenant_id()))?,instance_id:checked_input(Uuid::parse_str(proof.instance_id()))?,principal_id:checked_input(Uuid::parse_str(proof.principal_id()))?},source:input.source,policy_id:policy.id,policy_revision:input.policy_revision,policy_version:policy.version,allow_ai,risk_level:risk,confirmed:input.confirmed};
            checked_input(decision.validate(checked_input(Uuid::parse_str(proof.tenant_id()))?))?;
            let invocation=Invocation{authorization:decision,parameters:checked_input(serde_json::from_value(parameters))?,grant:UserGrant::from_proof(&auth,proof,p.device(),Permission::ScriptExecute)?};
            let id=Uuid::new_v4();
            production::queue_run_in(service,tx,production::RunInput{source:db::Source::Policy{version:policy.version},target:&target,id,occurrence,available,deadline,now}).await?;
            let tenant=tx.tenant_id().to_string();let document=json(&invocation)?;
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.action_runs SET invocation=$3 WHERE tenant_id=$1::uuid AND id=$2 AND invocation IS NULL").bind(tenant).bind(id).bind(document).execute(c).await?;Ok(())})).await?;
            let response=json(&wire::SelfServiceAccepted{request_id:input.operation_id,run_id:id,policy_id:policy.id,policy_revision:policy.revision as u64,policy_version:policy.version})?;
            db::receipt(tx,&actor,input.operation_id,hash.clone(),&response,None).await?;
            proof.check_live()?;
            let fact=Fact::business(audit,&event_key,&hash,202,"success",None)?;service.audit_store.append_in(tx,&fact,false).await?;
            crate::sources::storage::wake_execution_in(tx,policy.id).await?;
            Ok(response)
        })).await
    }
    pub async fn self_service_status(
        &self,
        p: &DevicePrincipal,
        proof: &AuthorizedPrincipal,
        request: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if proof.tenant_id() != p.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        proof.require(Permission::ScriptExecute, Some(p.device()))?;
        proof.bind_audit(audit)?;
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,p,proof,request,audit),|ctx,tx|Box::pin(async move {
            let (service,p,proof,request,audit)=*ctx;
            storage::lock(tx,p.device()).await?;crate::actions::agent::principal(service,tx,p).await?;
            let auth=crate::action_admission::authorized(tx,proof,p.device(),Permission::ScriptExecute).await?;
            let actor=format!("self-service:{}:{}:{}",proof.instance_id(),proof.principal_id(),p.registration());let tenant=tx.tenant_id().to_string();
            let response:Value=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT response FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3").bind(tenant).bind(actor).bind(request).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
            let id=checked_input(Uuid::parse_str(response["runId"].as_str().ok_or(Error::Malformed)?))?;
            let run=db::load_run(tx,id).await?;crate::actions::agent::belongs(&run,p)?;
            let plan=db::load_source(&service.policy_reader,tx,run.source).await?;
            if let db::ScheduledPolicy::Script(script)=&plan && let Some(collection)=&script.frozen.collection {
                auth.require(proof,Permission::InventoryRead,Some(p.device()))?;
                if collection.fields().iter().any(|f|f.sensitivity==rss_mdm_inventory::Sensitivity::Sensitive) {auth.require(proof,Permission::InventorySensitiveRead,None)?;}
            }
            proof.check_live()?;service.audit_store.append_request_in(tx,audit,200,"success").await?;
            json(&wire::SelfServiceStatus{request_id:request,run_id:id,attempt_id:run.state.attempt(),state:public_state(&run.state),available_at:run.available_at,deadline:run.deadline,result:run.result})
        })).await
    }
}

fn metadata(config: &rss_mdm_policy::SelfService) -> Result<wire::SelfServiceMetadata> {
    Ok(wire::SelfServiceMetadata {
        published: config.published,
        display_name: config.display_name.clone(),
        description: config.description.clone(),
        prerequisites: config.prerequisites.clone(),
        side_effects: config.side_effects.clone(),
        category: config.category.clone(),
        keywords: config.keywords.clone(),
        allow_ai: config.allow_ai.ok_or(Error::Malformed)?,
        risk_level: config.risk_level.ok_or(Error::Malformed)?.value(),
    })
}
fn parameter_sources(
    sources: &rss_mdm_policy::ParameterSources,
) -> std::collections::BTreeMap<String, wire::ScriptParameterSource> {
    sources
        .0
        .iter()
        .map(|(name, source)| {
            (
                name.clone(),
                match source {
                    rss_mdm_policy::ParameterSource::Fixed { value } => {
                        wire::ScriptParameterSource::Fixed {
                            value: value.clone(),
                        }
                    }
                    rss_mdm_policy::ParameterSource::Input {} => {
                        wire::ScriptParameterSource::Input {}
                    }
                },
            )
        })
        .collect()
}
fn public_state(state: &crate::actions::state::RunState) -> wire::ScriptRunState {
    use crate::actions::state::{Cancellation, Delivery, Execution};
    wire::ScriptRunState {
        delivery: match state.delivery {
            Delivery::Queued => wire::ScriptDelivery::Queued,
            Delivery::Claimed {
                attempt,
                lease_until,
            } => wire::ScriptDelivery::Claimed {
                attempt,
                lease_until,
            },
            Delivery::Received {
                attempt,
                lease_until,
            } => wire::ScriptDelivery::Received {
                attempt,
                lease_until,
            },
        },
        execution: match state.execution {
            Execution::NotStarted => wire::ScriptExecution::NotStarted,
            Execution::Running => wire::ScriptExecution::Running,
            Execution::Succeeded => wire::ScriptExecution::Succeeded,
            Execution::Failed => wire::ScriptExecution::Failed,
            Execution::WaitingReboot => wire::ScriptExecution::WaitingReboot,
            Execution::Unknown => wire::ScriptExecution::Unknown,
        },
        cancellation: match state.cancellation {
            Cancellation::None => wire::ScriptCancellation::None,
            Cancellation::Requested => wire::ScriptCancellation::Requested,
            Cancellation::Confirmed => wire::ScriptCancellation::Confirmed,
        },
        deadline: state.deadline,
        started_at: state.started_at,
    }
}
