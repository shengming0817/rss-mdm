//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
    transaction::*,
};
use crate::{
    frozen::Frozen,
    sources::{onboarding, software},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;

use crate::authorize_policy_snapshot;
use crate::enrollment_preparation as enrollment;
use crate::input_preparation::variant;
use rss_mdm_policy::Definition;
use rss_mdm_resource as resource;
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
    let verified = if let Action::Execution {
        resource,
        parameters,
        ..
    } = &input.definition.action
    {
        Some(
            s.inputs
                .verify_script(resource, parameters, s.inputs.content.as_ref())
                .await?,
        )
    } else {
        None
    };
    run(&s.audit_store,&s.runtime,s.tenant,audit,(s,proof,audit,input,verified.as_ref()),|ctx,tx|Box::pin(async move {
        let (s,proof,audit,input,verified)=*ctx;
        let authorization=crate::action_admission::current(tx,proof).await?;
        authorize_policy_snapshot(&authorization,proof,&input.definition)?;
        let enrollment=if matches!(input.definition.action,Action::RequestMdmEnrollment{..}) {Some(Frozen::MdmEnrollment{action:Box::new(enrollment::freeze(proof,&authorization,&input.definition.action,&s.inputs.enrollment_entries)?)})}else{None};
        let agent=if matches!(input.definition.action,Action::EnsureAgentInstalled{..}){Some(s.inputs.freeze_agent_in(tx,proof,&authorization,&input.definition.action).await?)}else{None};
        let binding=input.definition.action.resource();
        let version=if let Some(binding)=binding {Some(s.inputs.active_version_in(tx,binding.id(),binding.version()).await?)}else{None};
        let software=if matches!(input.definition.action, Action::Software { .. }) {
            let Frozen::Software { action }=s.inputs.freeze_in(tx, &input.definition.action, None, None).await? else {return Err(Error::Malformed.into());};
            Some(software::SoftwareExecutionPolicy::draft(input.definition.clone(),*action))
        } else if agent.is_some() {None} else if let Some(version)=version {
            if let Action::Execution {parameters,..}=&input.definition.action {
                crate::input_preparation::script(&version,binding.ok_or(Error::Malformed)?,parameters,verified.ok_or(Error::Conflict)?)?;
            } else {
                let selected=variant(&version,binding.ok_or(Error::Malformed)?)?;
                match (&input.definition.action,selected.declaration()) {
                    (Action::NativeCollection{..},resource::Declaration::NativeCollection{..})=>(),
                    (Action::Configuration {..},resource::Declaration::Configuration {..})=>(),
                    _=>return Err(Error::Malformed.into()),
                }
            }
            None
        } else {None};
        let onboarding=agent.map(|action|Frozen::AgentInstall{action:Box::new(action)}).or(enrollment);
        authorization.require_all_devices(proof,Permission::InventoryRead)?;
        let source=s.source.clone();let tenant=tx.tenant_id();let scope=input.definition.scope;let after=input.after.clone();
        let page=tx.with_connection(move|c|Box::pin(async move {Ok(source.preview_scope_on(c,tenant,scope,after.as_deref()).await)})).await??;
        let result=page.result;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let mut devices=page.devices;
        let more=devices.len()>64;devices.truncate(64);let next=if more{devices.last().cloned()}else{None};let mut items=Vec::new();
        for device in devices {
            let eligibility=crate::sources::storage::admission_in(&s.source,tx,input.definition.scope,&device).await?;
            let task_admission=if let Some(software)=&software {
                let now=crate::storage::now(tx).await?;
                Some(software.management_state_in(&s.admission,tx,&device,now).await?)
            }else if let Some(frozen)=&onboarding{Some(onboarding::state_in(&s.admission,tx,&device,frozen).await?)}else{None};
            items.push(json!({"device":device,"eligibility":eligibility,"taskAdmission":task_admission}));
        }
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        super::records::decode(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":next}))
    }),TransactionOwner::Execution).await.map_err(Into::into)
}
