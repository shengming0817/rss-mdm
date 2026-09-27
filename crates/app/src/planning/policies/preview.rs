//! A draft preview reads an immutable Scope result and never publishes or creates execution work.
use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Preview {
    definition: Definition,
    after: Option<String>,
    scope_result: Option<Uuid>,
}
pub(crate) async fn preview(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Json(input) = body.map_err(|_| Error::Malformed)?;
    input.definition.validate()?;
    a.proof.manage(Permission::PolicyRead)?;
    a.proof.manage(Permission::ResourceRead)?;
    authorize(&a.proof, &input.definition)?;
    run(&s.planning.audit_store,&s.planning.runtime,s.planning.tenant,&audit,(&s,&a,&audit,&input),|ctx,tx|Box::pin(async move {
        let (s,a,audit,input)=*ctx;
        let version=s.resource_in(tx,&input.definition.resource).await?;
        if matches!(input.definition.behavior, Behavior::Software { .. }) {
            s.freeze_in(tx, &input.definition.resource, &input.definition.behavior, None).await?;
        } else {
            let selected=variant(&version,&input.definition.resource)?;
            match (&input.definition.behavior,selected.declaration()) {
                (Behavior::Execution {parameters,..},resource::Declaration::Script {definition,..})=>checked_input(definition.validate_parameters(parameters))?,
                (Behavior::Configuration {exit},resource::Declaration::Configuration {remove,..})=>{
                    if matches!(exit,Exit::Remove) && remove.is_none(){return Err(Error::Unsupported.into());}
                },
                _=>return Err(Error::Malformed.into()),
            }
        }
        a.proof.require_all_devices(Permission::InventoryRead)?;
        let tenant=tx.tenant_id().to_string();let id=input.definition.scope;
        let result=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<Uuid>>("SELECT resolution FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted FOR SHARE").bind(tenant).bind(id).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?.ok_or(Error::Conflict)?;
        if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict.into());}
        let tenant=tx.tenant_id().to_string();let after=input.after.clone();
        let mut devices=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT device FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65").bind(tenant).bind(result).bind(after).fetch_all(c).await})).await?;
        let more=devices.len()>64;devices.truncate(64);let next=if more{devices.last().cloned()}else{None};let mut items=Vec::new();
        for device in devices {
            let name=device.clone();let id=input.definition.scope;
            let eligibility=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Value>("SELECT mdm_planning.scope_admission($1,$2)").bind(id).bind(name).fetch_one(c).await})).await?;
            items.push(json!({"device":device,"eligibility":eligibility}));
        }
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(Json(json!({"resource":input.definition.resource,"scopeResult":result,"items":items,"nextCursor":next})))
    }),TransactionOwner::Planning).await
}
