//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::sources::{onboarding, software};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
    transaction::*,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;

use crate::authorize_policy_snapshot;
use crate::input_preparation::{PublicationInput, preview::PreviewInputs};
use rss_mdm_policy::Definition;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub definition: Definition,
    pub after: Option<String>,
    pub scope_result: Option<Uuid>,
}
pub async fn preview(
    s: &Queries,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
) -> std::result::Result<super::records::Preview, crate::queries::QueryError> {
    audit.set_action("management_read");
    input.definition.validate()?;
    proof.manage(Permission::PolicyRead)?;
    if input.definition.action.resource().is_some() {
        proof.manage(Permission::ResourceRead)?;
    }
    authorize_policy_snapshot(proof.authorization()?, proof, &input.definition)?;
    let request = PublicationInput::from(&input.definition.action);
    let verified = s.inputs.prepare_resource(request.resource()).await?;
    run(&s.audit_store,&s.runtime,s.tenant,audit,(s,proof,audit,input,verified.as_ref()),|ctx,tx|Box::pin(async move {
        let (s,proof,audit,input,verified)=*ctx;
        let authorization=crate::action_admission::current(tx,proof).await?;
        authorization.require(proof,Permission::PolicyRead,None)?;
        if input.definition.action.resource().is_some() { authorization.require(proof,Permission::ResourceRead,None)?; }
        authorize_policy_snapshot(&authorization,proof,&input.definition)?;
        let prepared = s.inputs.preview_in(tx, &PublicationInput::from(&input.definition.action), verified, proof, &authorization).await?;
        let software = if let PreviewInputs::Software(action) = &prepared {
            let Action::Software { rollout, .. } = &input.definition.action else { return Err(Error::Malformed.into()); };
            Some(software::SoftwareAssignment::draft(input.definition.scope, rollout.clone(), (**action).clone()))
        } else { None };
        let onboarding = if let PreviewInputs::Onboarding(frozen) = &prepared { Some(frozen) } else { None };
        authorization.require_all_devices(proof,Permission::InventoryRead)?;
        let source=s.source.clone();let tenant=tx.tenant_id();let scope=input.definition.scope;let after=input.after.clone();let channel=crate::source_authority::action_channel(input.definition.action.kind());
        let mut objects=tx.with_connection(move|c|Box::pin(async move {Ok(source.assignment_objects_on(c,tenant,scope,channel,after.as_deref()).await)})).await??;
        let source=s.source.clone();let tenant=tx.tenant_id();
        let result=tx.with_connection(move|c|Box::pin(async move {Ok(source.preview_scope_on(c,tenant,scope,channel,None).await)})).await??.result;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let more=objects.len()>64;objects.truncate(64);let next=if more{objects.last().map(|o|o.object.key())}else{None};let mut items=Vec::new();
        for mut object in objects {
            let task_admission=if let Some(target)=&object.target {
                let device=&target.device;
                if let Some(software)=&software {let now=crate::storage::now(tx).await?;Some(software.management_state_in(&s.admission,tx,device,now).await?)}
                else if let Some(frozen)=onboarding {Some(onboarding::state_in(&s.admission,tx,device,frozen).await?)}
                else if let PreviewInputs::Script {platform,architecture,profile,applicability}=&prepared {
                    let agents=crate::channels::agent_targets_in(tx,s.agent_store.clone(),vec![device.clone()]).await?;
                    let mut state=if let Some(agent)=agents.first() {crate::script_eligibility::check_in(tx,s.agent_store.clone(),&crate::Target{device:device.clone(),registration:agent.registration,generation:agent.generation},*platform,*architecture,*profile).await?}else{crate::script_eligibility::Eligibility::Unknown};
                    if state == crate::script_eligibility::Eligibility::Eligible
                        && let (Some(requirements), Some(agent)) = (applicability, agents.first())
                        && !crate::script_eligibility::collection_requirements_in(tx, &crate::Target{device:device.clone(),registration:agent.registration,generation:agent.generation}, requirements).await?
                    { state = crate::script_eligibility::Eligibility::Ineligible; }
                    Some(software::TaskAdmission::new(match state {crate::script_eligibility::Eligibility::Eligible=>software::TaskAdmissionState::Eligible,crate::script_eligibility::Eligibility::Ineligible=>software::TaskAdmissionState::UnsupportedCapability,crate::script_eligibility::Eligibility::Unknown=>software::TaskAdmissionState::ChannelUnknown},None))
                } else if let PreviewInputs::Native(template) = &prepared {
                    let template = template.clone(); let candidate = crate::Target { device: target.device.clone(), registration: target.registration_id, generation: target.generation }; let tenant = tx.tenant_id();
                    let allowed = tx.with_connection(move |c| Box::pin(async move { Ok(crate::collection_eligibility::native_on(c, tenant, &candidate, &template).await) })).await??;
                    Some(software::TaskAdmission::new(if allowed { software::TaskAdmissionState::Eligible } else { software::TaskAdmissionState::UnsupportedCapability }, None))
                }else{None}
            }else{None};
            if task_admission.as_ref().is_some_and(|a|!software::TaskAdmission::is_eligible(a)) {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"eligibility":object.admission,"taskAdmission":task_admission}));
        }
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        super::records::decode(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":next}))
    })).await.map_err(Into::into)
}
