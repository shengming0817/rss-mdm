//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::sources::{onboarding, software};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;

use crate::authorize_policy_snapshot;
use crate::input_preparation::{PublicationInput, preview::PreviewInputs};
use rss_mdm_policy::Definition;
use serde::Deserialize;
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    #[serde(deserialize_with = "rss_mdm_policy::definition_input")]
    pub definition: Box<Definition>,
    pub scope_result: Option<Uuid>,
}
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_previews",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
pub async fn preview(
    s: &Queries,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<super::records::Preview, crate::queries::QueryError> {
    query
        .require_schema(&SCHEMA)
        .map_err(|_| Error::Malformed)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    input.definition.validate()?;
    proof.manage(Permission::PolicyRead)?;
    if input.definition.action.resource().is_some() {
        proof.manage(Permission::ResourceRead)?;
    }
    authorize_policy_snapshot(proof.authorization()?, proof, &input.definition)?;
    let request = PublicationInput::try_from(&input.definition.action)?;
    let verified = s.inputs.prepare_resource(request.resource()).await?;
    crate::transaction::inspect(&s.runtime, s.tenant,(s,proof,audit,input,verified.as_ref(),query,codec),|ctx,tx|Box::pin(async move {
        let (s,proof,_audit,input,verified,query,codec)=*ctx;
        let authorization=crate::action_admission::current(tx,proof).await?;
        authorization.require(proof,Permission::PolicyRead,None)?;
        if input.definition.action.resource().is_some() { authorization.require(proof,Permission::ResourceRead,None)?; }
        authorize_policy_snapshot(&authorization,proof,&input.definition)?;
        let authority=authorization.query_binding(proof)?;let scope=input.definition.scope;let definition=json!([input.definition,input.scope_result]);let limit=query.limit();
        let binding=super::window::binding_in(s,tx,proof,&authority,SCHEMA.id,scope,&definition).await?;
        let page=async {
        let after=super::window::after(codec,query,&binding)?;
        if matches!(input.definition.action, Action::UnmanageDevice {..}) {
            let preview=super::lifecycle::preview_in(s,tx,input,after.as_deref(),limit,codec,&binding).await?;

            return Ok(preview);
        }
        let prepared = s.inputs.preview_in(tx, &PublicationInput::try_from(&input.definition.action)?, verified, proof, &authorization).await?;
        let software = if let PreviewInputs::Software(action) = &prepared {
            let Action::Software { rollout, .. } = &input.definition.action else { return Err(Error::Malformed.into()); };
            Some(software::SoftwareAssignment::draft(input.definition.scope, rollout.clone(), (**action).clone()))
        } else { None };
        let onboarding = if let PreviewInputs::Onboarding(frozen) = &prepared { Some(frozen) } else { None };
        authorization.require_all_devices(proof,Permission::InventoryRead)?;
        let source=s.source.clone();let tenant=tx.tenant_id();let scope=input.definition.scope;let after=after.clone();let channel=crate::source_authority::action_channel(&input.definition.action)?;
        let mut objects=tx.with_connection(move|c|Box::pin(async move {Ok(source.assignment_objects_on(c,tenant,scope,channel,after.as_deref(),limit).await)})).await??;
        let source=s.source.clone();let tenant=tx.tenant_id();
        let result=tx.with_connection(move|c|Box::pin(async move {Ok(source.preview_scope_on(c,tenant,scope,channel,None).await)})).await??.result;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let more=objects.len()>limit;objects.truncate(limit);let next=if more{objects.last().map(|o|o.object.key())}else{None};let mut items=Vec::new();
        for mut object in objects {
            let task_admission=if let Some(target)=&object.target {
                let device=&target.device;
                if let Some(software)=&software {let now=crate::storage::now(tx).await?;Some(software.management_state_in(&s.admission,tx,device,now).await?)}
                else if let Some(frozen)=onboarding {Some(onboarding::state_in(&s.admission,tx,device,frozen,Uuid::nil()).await?)}
                else if let PreviewInputs::Script {platform,architecture,profile,applicability}=&prepared {
                    let agents=crate::channels::agent_targets_in(tx,s.agent_store.clone(),vec![device.clone()]).await?;
                    let mut state=if let Some(agent)=agents.first() {crate::script_eligibility::check_in(tx,s.agent_store.clone(),&crate::Target{device:device.clone(),registration:agent.registration,generation:agent.generation},*platform,*architecture,*profile).await?}else{crate::script_eligibility::Eligibility::Unknown};
                    if state == crate::script_eligibility::Eligibility::Eligible
                        && let (Some(requirements), Some(agent)) = (applicability, agents.first())
                        && !crate::script_eligibility::collection_requirements_in(tx, &crate::Target{device:device.clone(),registration:agent.registration,generation:agent.generation}, requirements).await?
                    { state = crate::script_eligibility::Eligibility::Ineligible; }
                    Some(software::TaskAdmission::new(match state {crate::script_eligibility::Eligibility::Eligible=>software::TaskAdmissionState::Eligible,crate::script_eligibility::Eligibility::Ineligible=>software::TaskAdmissionState::UnsupportedCapability,crate::script_eligibility::Eligibility::Unknown=>software::TaskAdmissionState::ChannelUnknown},None))
                } else if let PreviewInputs::DeviceAccess { windows } = &prepared {
                    let binding=crate::channels::agent_binding_in(tx,s.agent_store.clone(),target.registration_id).await?;
                    let allowed=binding.is_some_and(|b|crate::device_access::capable(&b, windows));
                    Some(software::TaskAdmission::new(if allowed{software::TaskAdmissionState::Eligible}else{software::TaskAdmissionState::UnsupportedCapability},None))
                } else if let PreviewInputs::Credential { architecture } = &prepared {
                    let binding=crate::channels::agent_binding_in(tx,s.agent_store.clone(),target.registration_id).await?;
                    let allowed=binding.is_some_and(|b|crate::credential_tasks::capable(&b,*architecture));
                    Some(software::TaskAdmission::new(if allowed { software::TaskAdmissionState::Eligible } else { software::TaskAdmissionState::UnsupportedCapability },None))
                } else if let PreviewInputs::AgentCollection{definition,platform,architecture}=&prepared {
                    let candidate=crate::Target{device:target.device.clone(),registration:target.registration_id,generation:target.generation};
                    let allowed=crate::agent_collection_eligibility::check_in(tx,s.agent_store.clone(),&candidate,*platform,*architecture,definition).await?;
                    Some(software::TaskAdmission::new(if allowed{software::TaskAdmissionState::Eligible}else{software::TaskAdmissionState::UnsupportedCapability},None))
                } else if let PreviewInputs::Native(template) = &prepared {
                    let needs_context = template.spec().adapter != rss_mdm_resource::NativeAdapter::WindowsRead;
                    let template = template.clone(); let candidate = crate::Target { device: target.device.clone(), registration: target.registration_id, generation: target.generation }; let tenant = tx.tenant_id();
                    let allowed = tx.with_connection(move |c| Box::pin(async move { Ok(crate::collection_eligibility::native_on(c, tenant, &candidate, &template).await) })).await??;
                    Some(software::TaskAdmission::new(if !allowed { software::TaskAdmissionState::UnsupportedCapability } else if needs_context { software::TaskAdmissionState::ChannelUnknown } else { software::TaskAdmissionState::Eligible }, None))
                }else{None}
            }else{None};
            if task_admission.as_ref().is_some_and(|a|!software::TaskAdmission::is_eligible(a)) {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"eligibility":object.admission,"taskAdmission":task_admission}));
        }

        super::records::decode(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":super::window::next(codec,&binding,next)?}))
        }.await?;
        if binding != super::window::binding_in(s,tx,proof,&authority,SCHEMA.id,scope,&definition).await? { return Err(Error::Conflict.into()); }
        Ok(page)
    })).await.map_err(Into::into)
}
