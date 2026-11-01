//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use rss_mdm_policy::pages::{TaskAdmission, TaskAdmissionState};
use serde_json::json;

use crate::authorize_action;
use crate::input_preparation::{PublicationInput, preview::PreviewInputs};
use rss_mdm_policy::Definition;
use rss_mdm_policy::pages::Preview;
pub async fn preview(
    s: &Queries,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<super::records::Preview, crate::queries::QueryError> {
    query
        .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
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
    authorize_preview(proof.authorization()?, proof, &input.definition)?;
    let prepared =
        crate::transaction::inspect(&s.runtime, s.tenant, (s, proof, input), |ctx, tx| {
            Box::pin(async move {
                let (s, proof, input) = *ctx;
                let authorization = crate::action_admission::current(tx, proof).await?;
                authorization.require(proof, Permission::PolicyRead, None)?;
                if input.definition.action.resource().is_some() {
                    authorization.require(proof, Permission::ResourceRead, None)?;
                }
                authorize_preview(&authorization, proof, &input.definition)?;
                s.inputs
                    .prepare_preview_in(
                        tx,
                        &PublicationInput::try_from(&input.definition.action)?,
                        proof,
                        &authorization,
                    )
                    .await
            })
        })
        .await?;
    s.snapshot(proof,(s,proof,input,&prepared,query,codec),|ctx,c,basis|Box::pin(async move {
        let (s,proof,input,prepared,query,codec)=*ctx;
        let authorization=&basis.grant;
        authorization.require(proof,Permission::PolicyRead,None)?;
        if input.definition.action.resource().is_some(){authorization.require(proof,Permission::ResourceRead,None)?;}
        authorize_preview(authorization,proof,&input.definition)?;
        s.inputs.recheck_preview_on(c,&PublicationInput::try_from(&input.definition.action)?,prepared).await?;
        let authority=authorization.query_binding(proof)?;let scope=input.definition.scope;let definition=json!([input.definition,input.scope_result]);let limit=query.limit();
        let binding=rss_mdm_scope_service::window::binding_on(&s.source,c,proof,&authority,rss_mdm_policy::pages::PREVIEW_SCHEMA.id,scope,&definition).await?;
        let after=rss_mdm_scope_service::window::after(codec,query,&binding)?;
        if matches!(input.definition.action,Action::UnmanageDevice{..}) {
            return super::lifecycle::preview_on(s,c,input,after.as_deref(),limit,codec,&binding).await;
        }
        let prepared = &prepared.inputs;
        authorization.require_all_devices(proof,Permission::InventoryRead)?;
        let source=s.source.clone();let tenant=s.tenant;let scope=input.definition.scope;let after=after.clone();let channel=crate::sources::candidates::action_channel(&input.definition.action)?;
        let mut objects=source.assignment_objects_on(c,tenant,scope,channel,after.as_deref(),limit).await?;
        let source=s.source.clone();let tenant=s.tenant;
        let result=source.preview_scope_on(c,tenant,scope,channel,None).await?.result;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let more=objects.len()>limit;objects.truncate(limit);let next=if more{objects.last().map(|o|o.object.key())}else{None};let mut items=Vec::new();
        for mut object in objects {
            let task_admission=if let Some(target)=&object.target {
                let _device=&target.device;
                if let PreviewInputs::DeviceAccess { windows } = prepared {
                    let binding=crate::agent_facts::agent_binding_on(c,tenant,s.agent_store.clone(),target.registration_id).await?;
                    let allowed=binding.is_some_and(|b|crate::device_access::capable(&b, windows));
                    Some(TaskAdmission::new(if allowed{TaskAdmissionState::Eligible}else{TaskAdmissionState::UnsupportedCapability},None))
                } else if let PreviewInputs::Credential { architecture } = prepared {
                    let binding=crate::agent_facts::agent_binding_on(c,tenant,s.agent_store.clone(),target.registration_id).await?;
                    let allowed=binding.is_some_and(|b|crate::credential_tasks::capable(&b,*architecture));
                    Some(TaskAdmission::new(if allowed { TaskAdmissionState::Eligible } else { TaskAdmissionState::UnsupportedCapability },None))
                }else{None}
            }else{None};
            if task_admission.as_ref().is_some_and(|a|!TaskAdmission::is_eligible(a)) {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"eligibility":object.admission,"taskAdmission":task_admission}));
        }

        super::records::decode(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":rss_mdm_scope_service::window::next(codec,&binding,next)?}))
    })).await.map_err(Into::into)
}

fn authorize_preview(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> Result<(), crate::Error> {
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    authorize_action(snapshot, proof, &definition.action)
}
