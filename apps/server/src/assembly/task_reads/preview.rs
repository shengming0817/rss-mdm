use super::*;
use rss_mdm_inventory::Channel;
use rss_mdm_management_http::execution::task_reads::{Pending, Reads as Port};
use rss_mdm_policy::Action;
use serde_json::json;
impl Port for Reads {
    fn assignments<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        page: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::AssignmentPage> {
        Box::pin(super::assignments::assignments(
            self, request, audit, policy, page, codec,
        ))
    }

    fn runs<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        page: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::RunPage> {
        Box::pin(Reads::runs(self, request, audit, policy, page, codec))
    }
    fn run<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        policy: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::RunDetail> {
        Box::pin(Reads::run(self, request, audit, policy, id))
    }

    fn preview<'a>(
        &'a self,
        request: &'a rss_mdm_authorization_service::context::RequestAuth,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        input: &'a rss_mdm_policy::pages::Preview,
        query: &'a rss_mdm_query::window::Query,
        codec: &'a rss_mdm_query::cursor::CursorCodec,
    ) -> Pending<'a, rss_mdm_management_http::execution::task_reads::Preview> {
        let proof = request.proof.as_ref();
        Box::pin(async move {
            if matches!(
                input.definition.action,
                Action::Software { .. } | Action::EnsureAgentInstalled { .. }
            ) {
                return rss_mdm_software_service::deployment::queries::preview::preview(
                    &self.software,
                    proof,
                    audit,
                    input,
                    query,
                    codec,
                )
                .await
                .map(super::projections::software_preview)
                .map_err(Into::into);
            }
            if matches!(
                input.definition.action,
                Action::DeviceAccess { .. } | Action::Credential { .. }
            ) {
                return access_credentials(self, request, audit, input, query, codec).await;
            }
            if matches!(input.definition.action, Action::RequestMdmEnrollment { .. }) {
                return enrollment(self, request, audit, input, query, codec).await;
            }
            if matches!(input.definition.action, Action::UnmanageDevice { .. }) {
                return retirement(self, request, audit, input, query, codec).await;
            }
            if matches!(input.definition.action, Action::Configuration { .. }) {
                return Err(Error::Unsupported);
            }
            input.definition.validate().map_err(|_| Error::Malformed)?;
            query
                .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
                .map_err(|_| Error::Malformed)?;
            proof.manage(Permission::PolicyRead)?;
            proof.manage(Permission::ResourceRead)?;
            let grant = proof.authorization()?;
            grant.require(proof, Permission::PolicyRead, None)?;
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
            self.snapshot(request,(proof,input,query,codec,&verified,self),|ctx,c,grant,_now|Box::pin(async move {
                let (proof,input,query,codec,verified,s)=*ctx;
                grant.require(proof,Permission::PolicyRead,None)?;
                grant.require(proof,Permission::ResourceRead,None)?;
                grant.require(proof,Permission::PolicyRead,None)?;
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

async fn enrollment(
    s: &Reads,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    audit: &rss_mdm_audit_integration::RequestAudit,
    input: &rss_mdm_policy::pages::Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> Result<rss_mdm_management_http::execution::task_reads::Preview, Error> {
    let proof = request.proof.as_ref();
    use rss_mdm_management_http::execution::task_reads::{Preview, PreviewTarget};
    input.definition.validate().map_err(|_| Error::Malformed)?;
    query
        .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    proof.manage(Permission::PolicyRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    s.snapshot(
        request,
        (s, proof, input, query, codec),
        |ctx, c, grant, now| {
            Box::pin(async move {
                let (s, proof, input, query, codec) = *ctx;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require_all_devices(proof, Permission::InventoryRead)?;
                let Action::RequestMdmEnrollment {
                    organization,
                    schedule,
                    run_lifetime_seconds,
                } = &input.definition.action
                else {
                    return Err(Error::Malformed);
                };
                let frozen = rss_mdm_registration_service::enrollment::task::prepare(
                    &s.entries,
                    s.signing_enabled,
                    proof,
                    grant,
                    *organization,
                    schedule,
                    *run_lifetime_seconds,
                )?;
                let authority = grant.query_binding(proof)?;
                let scope = input.definition.scope;
                let channel = Channel::Agent;
                let binding = rss_mdm_scope_service::window::binding_on(
                    &s.source,
                    c,
                    proof,
                    &authority,
                    rss_mdm_policy::pages::PREVIEW_SCHEMA.id,
                    scope,
                    &json!([input.definition, input.scope_result]),
                )
                .await
                .map_err(window)?;
                let after =
                    rss_mdm_scope_service::window::after(codec, query, &binding).map_err(window)?;
                let limit = query.limit();
                let mut objects = s
                    .source
                    .assignment_objects_on(c, s.tenant, scope, channel, after.as_deref(), limit)
                    .await
                    .map_err(source)?;
                let result = s
                    .source
                    .preview_scope_on(c, s.tenant, scope, channel, None)
                    .await
                    .map_err(source)?
                    .result;
                if input.scope_result.is_some_and(|r| r != result) {
                    return Err(Error::Conflict);
                }
                let more = objects.len() > limit;
                objects.truncate(limit);
                let next = if more {
                    objects.last().map(|o| o.object.key())
                } else {
                    None
                };
                let mut items = Vec::new();
                for mut object in objects {
                    let admission = if let Some(target) = &object.target {
                        Some(
                            rss_mdm_registration_service::enrollment::tasks::queries::state_on(
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                s.tenant,
                                &s.enrollment,
                                &target.device,
                                &frozen,
                                now,
                            )
                            .await
                            .map_err(enrollment_fault)?,
                        )
                    } else {
                        None
                    };
                    if admission.as_ref().is_some_and(|a| !a.is_eligible()) {
                        object.availability =
                            rss_mdm_scope_service::channels::Availability::Unavailable;
                        object.reason = Some("target_unavailable".into());
                    }
                    items.push(PreviewTarget {
                        object: object.object,
                        channel: Some(object.channel),
                        availability: object.availability,
                        reason: object.reason,
                        target: object.target,
                        eligibility: object.admission,
                        task_admission: admission,
                    });
                }
                Ok(Preview {
                    action: input.definition.action.clone(),
                    scope_result: result,
                    items,
                    next_cursor: rss_mdm_scope_service::window::next(codec, &binding, next)
                        .map_err(window)?,
                })
            })
        },
    )
    .await
    .inspect(|_| audit.require_final_request())
}

async fn access_credentials(
    s: &Reads,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    audit: &rss_mdm_audit_integration::RequestAudit,
    input: &rss_mdm_policy::pages::Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> Result<rss_mdm_management_http::execution::task_reads::Preview, Error> {
    let proof = request.proof.as_ref();
    use rss_mdm_management_http::execution::task_reads::{Preview, PreviewTarget};
    input.definition.validate().map_err(|_| Error::Malformed)?;
    query
        .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    proof.manage(Permission::PolicyRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    s.snapshot(
        request,
        (s, proof, input, query, codec),
        |ctx, c, grant, _now| {
            Box::pin(async move {
                let (s, proof, input, query, codec) = *ctx;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require_all_devices(proof, Permission::InventoryRead)?;
                if !s.signing_enabled{return Err(Error::Unsupported)}
                let permission=match &input.definition.action {Action::DeviceAccess{..}=>Permission::AccountWrite,Action::Credential{operation,..}=>{if !s.recovery_enabled{return Err(Error::Unsupported)}rss_mdm_recovery_credentials::tasks::credential_tasks::permission(operation)},_=>return Err(Error::Malformed)};
                grant.require_all_devices(proof,permission)?;
                let authority = grant.query_binding(proof)?;
                let scope = input.definition.scope;
                let channel = Channel::Agent;
                let binding = rss_mdm_scope_service::window::binding_on(
                    &s.source,
                    c,
                    proof,
                    &authority,
                    rss_mdm_policy::pages::PREVIEW_SCHEMA.id,
                    scope,
                    &json!([input.definition, input.scope_result]),
                )
                .await
                .map_err(window)?;
                let after =
                    rss_mdm_scope_service::window::after(codec, query, &binding).map_err(window)?;
                let limit = query.limit();
                let mut objects = s
                    .source
                    .assignment_objects_on(c, s.tenant, scope, channel, after.as_deref(), limit)
                    .await
                    .map_err(source)?;
                let result = s
                    .source
                    .preview_scope_on(c, s.tenant, scope, channel, None)
                    .await
                    .map_err(source)?
                    .result;
                if input.scope_result.is_some_and(|r| r != result) {
                    return Err(Error::Conflict);
                }
                let more = objects.len() > limit;
                objects.truncate(limit);
                let next = if more {
                    objects.last().map(|o| o.object.key())
                } else {
                    None
                };
                let mut items = Vec::new();
                for mut object in objects {
                    let admission = if let Some(target) = &object.target {
                        let binding=s.enrollment.agent_store.binding(c,s.tenant.to_string(),target.registration_id).await.map_err(|_|Error::Unavailable(Failure::Database))?;
                        let allowed=binding.is_some_and(|b|match &input.definition.action {
                            Action::DeviceAccess{windows,..}=>rss_mdm_device_access_postgres::device_access::execution::admission::capable(&b,windows),
                            Action::Credential{architecture,..}=>rss_mdm_recovery_credentials::tasks::credential_tasks::capable(&b,*architecture),_=>false
                        });
                        use rss_mdm_policy::pages::{TaskAdmission,TaskAdmissionState};
                        Some(TaskAdmission::new(if allowed{TaskAdmissionState::Eligible}else{TaskAdmissionState::UnsupportedCapability},None))

                    } else {
                        None
                    };
                    if admission.as_ref().is_some_and(|a| !a.is_eligible()) {
                        object.availability =
                            rss_mdm_scope_service::channels::Availability::Unavailable;
                        object.reason = Some("target_unavailable".into());
                    }
                    items.push(PreviewTarget {
                        object: object.object,
                        channel: Some(object.channel),
                        availability: object.availability,
                        reason: object.reason,
                        target: object.target,
                        eligibility: object.admission,
                        task_admission: admission,
                    });
                }
                Ok(Preview {
                    action: input.definition.action.clone(),
                    scope_result: result,
                    items,
                    next_cursor: rss_mdm_scope_service::window::next(codec, &binding, next)
                        .map_err(window)?,
                })
            })
        },
    )
    .await
    .inspect(|_| audit.require_final_request())
}

async fn retirement(
    s: &Reads,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    audit: &rss_mdm_audit_integration::RequestAudit,
    input: &rss_mdm_policy::pages::Preview,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> Result<rss_mdm_management_http::execution::task_reads::Preview, Error> {
    let proof = request.proof.as_ref();
    query
        .require_schema(&rss_mdm_policy::pages::PREVIEW_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    input.definition.validate().map_err(|_| Error::Malformed)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    s.snapshot(
        request,
        (s, proof, input, query, codec),
        |ctx, c, grant, _| {
            Box::pin(async move {
                let (s, proof, input, query, codec) = *ctx;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require(proof, Permission::PolicyRead, None)?;
                grant.require_all_devices(proof, Permission::InventoryRead)?;
                rss_mdm_device_service::control::authorize_action(
                    grant,
                    proof,
                    &input.definition.action,
                )?;
                let authority = grant.query_binding(proof)?;
                let binding = rss_mdm_scope_service::window::binding_on(
                    &s.source,
                    c,
                    proof,
                    &authority,
                    rss_mdm_policy::pages::PREVIEW_SCHEMA.id,
                    input.definition.scope,
                    &json!([input.definition, input.scope_result]),
                )
                .await
                .map_err(window)?;
                let after =
                    rss_mdm_scope_service::window::after(codec, query, &binding).map_err(window)?;
                super::retirement::preview_on(
                    s,
                    c,
                    input,
                    after.as_deref(),
                    query.limit(),
                    codec,
                    &binding,
                )
                .await
            })
        },
    )
    .await
}
