//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use super::*;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub definition: Definition,
    pub after: Option<String>,
    pub scope_result: Option<Uuid>,
}
pub async fn preview(
    s: &Policies,
    proof: &AuthorizedPrincipal,
    audit: &RequestAudit,
    input: &Preview,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
    input.definition.validate()?;
    proof.manage(Permission::PolicyRead)?;
    if input.definition.action.resource().is_some() {
        proof.manage(Permission::ResourceRead)?;
    }
    authorize(proof, &input.definition)?;
    let verified = if let Action::Execution {
        resource,
        parameters,
        ..
    } = &input.definition.action
    {
        Some(
            s.planning
                .catalog
                .verify_script(resource, parameters, s.execution.content.as_ref())
                .await?,
        )
    } else {
        None
    };
    run(&s.planning.audit_store,&s.planning.runtime,s.planning.tenant,audit,(s,proof,audit,input,verified.as_ref()),|ctx,tx|Box::pin(async move {
        let (s,proof,audit,input,verified)=*ctx;
        let authorization=crate::action_admission::current(tx,proof).await?;
        authorize_snapshot(&authorization,proof,&input.definition)?;
        let enrollment=if matches!(input.definition.action,Action::RequestMdmEnrollment{..}) {Some(Frozen::MdmEnrollment{action:Box::new(enrollment::freeze(proof,&authorization,&input.definition.action,&s.execution.enrollment_entries)?)})}else{None};
        let agent=if matches!(input.definition.action,Action::EnsureAgentInstalled{..}){Some(s.freeze_agent_in(tx,proof,&authorization,&input.definition.action).await?)}else{None};
        let binding=input.definition.action.resource();
        let version=if let Some(binding)=binding {Some(s.planning.catalog.active_version_in(tx,binding.id(),binding.version()).await?)}else{None};
        let software=if matches!(input.definition.action, Action::Software { .. }) {
            let Frozen::Software { action }=s.freeze_in(tx, &input.definition.action, None, None).await? else {return Err(Error::Malformed.into());};
            Some(software::SoftwareExecutionPolicy::draft(input.definition.clone(),*action))
        } else if agent.is_some() {None} else if let Some(version)=version {
            if let Action::Execution {parameters,..}=&input.definition.action {
                crate::resource_catalog::scripts::prepare(&version,binding.ok_or(Error::Malformed)?,parameters,verified.ok_or(Error::Conflict)?)?;
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
        proof.require_all_devices(Permission::InventoryRead)?;
        let tenant=tx.tenant_id().to_string();let id=input.definition.scope;
        let result=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<Uuid>>("SELECT resolution FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted FOR SHARE").bind(tenant).bind(id).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?.ok_or(Error::Conflict)?;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let tenant=tx.tenant_id().to_string();let after=input.after.clone();
        let mut devices=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT device FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65").bind(tenant).bind(result).bind(after).fetch_all(c).await})).await?;
        let more=devices.len()>64;devices.truncate(64);let next=if more{devices.last().cloned()}else{None};let mut items=Vec::new();
        for device in devices {
            let name=device.clone();let id=input.definition.scope;
            let eligibility=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Value>("SELECT mdm_planning.scope_admission($1,$2)").bind(id).bind(name).fetch_one(c).await})).await?;
            let task_admission=if let Some(software)=&software {
                let now=crate::execution::storage::now(tx).await?;
                Some(software.management_state_in(&s.execution,tx,&device,now).await?)
            }else if let Some(frozen)=&onboarding{Some(onboarding::state_in(&s.execution,tx,&device,frozen).await?)}else{None};
            items.push(json!({"device":device,"eligibility":eligibility,"taskAdmission":task_admission}));
        }
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":next}))
    }),TransactionOwner::Planning).await
}
