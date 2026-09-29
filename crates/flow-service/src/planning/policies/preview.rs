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
    proof.manage(Permission::ResourceRead)?;
    authorize(proof, &input.definition)?;
    run(&s.planning.audit_store,&s.planning.runtime,s.planning.tenant,audit,(s,proof,audit,input),|ctx,tx|Box::pin(async move {
        let (s,proof,audit,input)=*ctx;
        let version=s.resource_in(tx,&input.definition.resource).await?;
        let software=if matches!(input.definition.behavior, Behavior::Software { .. }) {
            let Frozen::Software { action }=s.freeze_in(tx, &input.definition.resource, &input.definition.behavior, None).await? else {return Err(Error::Malformed.into());};
            Some(software::SoftwareExecutionPolicy::draft(input.definition.clone(),*action))
        } else {
            let selected=variant(&version,&input.definition.resource)?;
            match (&input.definition.behavior,selected.declaration()) {
                (Behavior::Execution {parameters,..},resource::Declaration::Script {definition,..})=>checked_input(definition.validate_parameters(parameters))?,
                (Behavior::Configuration {exit},resource::Declaration::Configuration {remove,..})=>{
                    if matches!(exit,Exit::Remove) && remove.is_none(){return Err(Error::Unsupported.into());}
                },
                _=>return Err(Error::Malformed.into()),
            }
            None
        };
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
            }else{None};
            items.push(json!({"device":device,"eligibility":eligibility,"taskAdmission":task_admission}));
        }
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"resource":input.definition.resource,"scopeResult":result,"items":items,"nextCursor":next}))
    }),TransactionOwner::Planning).await
}
