//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::deployment::sources::{onboarding, software};
use crate::deployment::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;

use crate::deployment::authorize_action;
use crate::deployment::input_preparation::{PublicationInput, preview::PreviewInputs};
use rss_mdm_policy::Definition;
use rss_mdm_policy::pages::Preview;
pub async fn preview(
    s: &Queries,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<super::records::Preview, crate::deployment::queries::QueryError> {
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
    let prepared = crate::deployment::transaction::inspect(
        &s.runtime,
        s.tenant,
        (s, proof, input),
        |ctx, tx| {
            Box::pin(async move {
                let (s, proof, input) = *ctx;
                let authorization = crate::deployment::action_admission::current(tx, proof).await?;
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
        },
    )
    .await?;
    s.snapshot(proof,(s,proof,input,&prepared,query,codec),|ctx,c,basis|Box::pin(async move {
        let (s,proof,input,prepared,query,codec)=*ctx;
        let authorization=&basis.grant;
        authorization.require(proof,Permission::PolicyRead,None)?;
        if input.definition.action.resource().is_some(){authorization.require(proof,Permission::ResourceRead,None)?;}
        authorize_preview(authorization,proof,&input.definition)?;
        s.inputs.recheck_preview_on(c,&PublicationInput::try_from(&input.definition.action)?,prepared).await?;
        let authority=authorization.query_binding(proof)?;let scope=input.definition.scope;let definition=json!([input.definition,input.scope_result]);let limit=query.limit();
        let coordinate=s.source.query_coordinate_on(c,s.tenant,scope).await?;
        let binding=rss_mdm_query::cursor::fingerprint(&(rss_mdm_policy::pages::PREVIEW_SCHEMA.id,proof.tenant_id(),proof.instance_id(),proof.principal_id(),authority,scope,definition,coordinate)).map_err(|_|Error::Malformed)?;
        let after: Option<rss_mdm_agent_wire::ObjectRef>=query.cursor().as_ref().map(|v|codec.decode(&rss_contract::PageCursor::parse(v).map_err(|_|Error::Malformed)?,&binding).map_err(|_|Error::Conflict)).transpose()?;
        let prepared = &prepared.inputs;
        let software = if let PreviewInputs::Software(action) = prepared {
            let Action::Software { rollout, .. } = &input.definition.action else { return Err(Error::Malformed.into()); };
            Some(software::SoftwareAssignment::draft(input.definition.scope, rollout.clone(), (**action).clone()))
        } else { None };
        let onboarding = if let PreviewInputs::Onboarding(frozen) = prepared { Some(frozen) } else { None };
        authorization.require_all_devices(proof,Permission::InventoryRead)?;
        let source=s.source.clone();let tenant=s.tenant;let scope=input.definition.scope;let channel=crate::deployment::sources::candidates::action_channel(&input.definition.action)?;
        let mut objects=source.assignment_objects_on(c,tenant,scope,channel,after,limit).await?;
        let source=s.source.clone();let tenant=s.tenant;
        let result=source.preview_scope_on(c,tenant,scope,channel,None).await?.result;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let more=objects.len()>limit;objects.truncate(limit);let next=if more{objects.last().map(|o|o.object)}else{None};let mut items=Vec::new();
        for mut object in objects {
            let task_admission=if let Some(target)=&object.target {
                let device=&target.device;
                if let Some(software)=&software {let now=basis.now;Some(software.management_state_on(&s.admission,c,tenant,device,now).await?)}
                else if let Some(frozen)=onboarding {Some(onboarding::state_on(&s.admission,c,tenant,device,frozen,Uuid::nil(),basis.now).await?)}
                else {None}
            }else{None};
            if task_admission.as_ref().is_some_and(|a|!rss_mdm_policy::pages::TaskAdmission::is_eligible(a)) {object.availability=crate::deployment::scope::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"eligibility":object.admission,"taskAdmission":task_admission}));
        }

        super::records::decode(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":next.map(|v|codec.encode(&binding,&v).map(|v|v.as_str().to_owned()).map_err(|_|Error::Malformed)).transpose()?}))
    })).await.map_err(Into::into)
}

fn authorize_preview(
    snapshot: &crate::deployment::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> Result<(), crate::deployment::Error> {
    snapshot.require(proof, Permission::PolicyRead, None)?;
    snapshot.require_all_devices(proof, Permission::InventoryRead)?;
    authorize_action(snapshot, proof, &definition.action)
}
