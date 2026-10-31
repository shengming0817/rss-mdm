use super::*;
use rss_mdm_inventory::Channel;
use rss_mdm_management_http::execution::task_reads::{Pending, Reads as Port};
use rss_mdm_policy::Action;
use serde_json::json;
impl Port for Reads {
    fn assignments<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        page: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_execution_service::queries::records::AssignmentPage> {
        Box::pin(super::assignments::assignments(
            self, proof, audit, policy, page, codec,
        ))
    }

    fn runs<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        page: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::RunPage> {
        Box::pin(Reads::runs(self, proof, audit, policy, page, codec))
    }
    fn run<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::RunDetail> {
        Box::pin(Reads::run(self, proof, audit, policy, id))
    }

    fn preview<'a>(
        &'a self,
        proof: &'a AuthorizedPrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        input: &'a rss_mdm_policy::pages::Preview,
        query: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_execution_service::queries::records::Preview> {
        Box::pin(async move {
            if !matches!(
                input.definition.action,
                Action::Execution { .. }
                    | Action::AgentCollection { .. }
                    | Action::NativeCollection { .. }
            ) {
                return rss_mdm_execution_service::queries::preview::preview(
                    &self.execution,
                    proof,
                    audit,
                    input,
                    query,
                    codec,
                )
                .await
                .map_err(Into::into);
            }
            input.definition.validate().map_err(|_| Error::Malformed)?;
            query
                .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
                .map_err(|_| Error::Malformed)?;
            proof.manage(Permission::PolicyRead)?;
            proof.manage(Permission::ResourceRead)?;
            let grant = proof.authorization()?;
            grant.require(proof, Permission::ScopeRead, None)?;
            grant.require_all_devices(proof, Permission::InventoryRead)?;
            audit.set_action(
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            let channel = if matches!(input.definition.action, Action::NativeCollection { .. }) {
                Channel::Mdm
            } else {
                Channel::Agent
            };
            match &input.definition.action {
                Action::Execution { .. } => {
                    grant.require_all_devices(proof, Permission::ScriptExecute)?
                }
                Action::AgentCollection { .. } => {
                    grant.require_all_devices(proof, Permission::InventoryCollect)?;
                    grant.require(proof, Permission::InventorySensitiveRead, None)?;
                    if !self.signing_enabled {
                        return Err(Error::Conflict);
                    }
                }
                Action::NativeCollection { .. } => {
                    grant.require_all_devices(proof, Permission::InventoryCollect)?
                }
                _ => unreachable!(),
            }
            let verified = match &input.definition.action {
                Action::Execution {
                    resource,
                    parameters,
                    ..
                } => self
                    .scripts
                    .prepare_resource(
                        resource,
                        rss_mdm_script_service::Parameters::Sources(parameters),
                    )
                    .await
                    .map_err(script)?,
                Action::AgentCollection { resource, .. }
                | Action::NativeCollection { resource, .. } => {
                    self.collections.prepare_resource(resource, channel).await?
                }
                _ => unreachable!(),
            };
            self.snapshot(proof,(proof,input,query,codec,&verified,self),|ctx,c,grant,_now|Box::pin(async move {
                let (proof,input,query,codec,verified,s)=*ctx;
                grant.require(proof,Permission::PolicyRead,None)?;
                grant.require(proof,Permission::ResourceRead,None)?;
                grant.require(proof,Permission::ScopeRead,None)?;
                grant.require_all_devices(proof,Permission::InventoryRead)?;
                let script_preview=if let Action::Execution{resource,parameters,..}=&input.definition.action {Some(s.scripts.preview_on(c,resource,rss_mdm_script_service::Parameters::Sources(parameters),verified,proof,grant).await.map_err(script_fault)?)}else{None};
                let collection_preview=match &input.definition.action {Action::AgentCollection{resource,..}|Action::NativeCollection{resource,..}=>Some(s.collections.preview_on(c,resource,channel,verified,proof,grant).await?),_=>None};
                let scope=input.definition.scope;
                let authority=grant.query_binding(proof)?;
                let binding=rss_mdm_scope_service::window::binding_on(&s.source,c,proof,&authority,rss_mdm_policy::pages::PREVIEW_SCHEMA.id,scope,&json!([input.definition,input.scope_result])).await.map_err(window)?;
                let after=rss_mdm_scope_service::window::after(codec,query,&binding).map_err(window)?;
                let limit=query.limit();
                let mut objects=s.source.assignment_objects_on(c,s.tenant,scope,channel,after.as_deref(),limit).await.map_err(source)?;
                let result=s.source.preview_scope_on(c,s.tenant,scope,channel,None).await.map_err(source)?.result;
                if input.scope_result.is_some_and(|r|r!=result) {return Err(Error::Conflict);}
                let more=objects.len()>limit;objects.truncate(limit);
                let next=if more{objects.last().map(|o|o.object.key())}else{None};
                let mut items=Vec::with_capacity(objects.len());
                for mut object in objects {
                    let admission=if let Some(target)=&object.target {
                        let state=if let Some(preview)=&script_preview {
                            let target=rss_mdm_script_service::Target{device:target.device.clone(),registration:target.registration_id,generation:target.generation};
                            match preview.eligibility_on(c,s.tenant,Arc::new(super::super::agent_facts::AgentFacts),&target).await.map_err(script_fault)? {
                                rss_mdm_script_service::eligibility::Eligibility::Eligible=>"eligible",
                                rss_mdm_script_service::eligibility::Eligibility::Ineligible=>"unsupported_capability",
                                rss_mdm_script_service::eligibility::Eligibility::Unknown=>"channel_unknown",
                            }
                        }else if let Some(preview)=&collection_preview {
                            let target=rss_mdm_inventory_service::collection::execution::model::Target{device:target.device.clone(),registration:target.registration_id,generation:target.generation};
                            if s.collections.eligible_on(c,preview,Arc::new(super::super::agent_facts::AgentFacts),&target).await? {"eligible"}else{"unsupported_capability"}
                        }else{unreachable!()};
                        if state!="eligible" {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
                        Some(json!({"state":state,"stage":null}))
                    }else{None};
                    items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"eligibility":object.admission,"taskAdmission":admission}));
                }
                serde_json::from_value(json!({"action":input.definition.action,"scopeResult":result,"items":items,"nextCursor":rss_mdm_scope_service::window::next(codec,&binding,next).map_err(window)?})).map_err(|_|Error::Unavailable(Failure::CommandInvariant))
            })).await
        })
    }
}
