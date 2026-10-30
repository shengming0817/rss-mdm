//! Draft target preview shares publication preparation and runtime capability checks.
use crate::{Error, Service};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_execution_service::queries::preview::Preview;
use serde_json::json;
use std::sync::{Arc, Mutex};
impl Service {
    /// Preview does not create collection definitions, policies, batches or execution tasks.
    pub async fn preview(
        self: &Arc<Self>,
        proof: &Arc<AuthorizedPrincipal>,
        input: Preview,
        audit: &RequestAudit,
        query: rss_mdm_query::window::Query,
        codec: rss_mdm_query::cursor::CursorCodec,
    ) -> Result<PreviewResponse, Error> {
        query
            .require_schema(&rss_mdm_execution_service::queries::preview::SCHEMA)
            .map_err(|_| Error::Invalid)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Denied);
        }
        input.definition.validate().map_err(|_| Error::Invalid)?;
        let rss_mdm_policy::Action::TelemetryProfile { resource } = &input.definition.action else {
            return Err(Error::Invalid);
        };
        let binding = resource.clone();
        let input = Arc::new(input);
        let prepared_input = input.clone();
        let prepared_actor = proof.clone();
        let service = self.clone();
        let _audit = audit.clone();
        let rejection = Arc::new(Mutex::new(None));
        let rejected = rejection.clone();
        let (frozen, profile_digest) = self
            .runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    let input = prepared_input;
                    let proof = prepared_actor;
                    service
                        .audit_store
                        .bind_in(tx)
                        .await
                        .map_err(crate::storage_error)?;
                    let prepared_failure = rejected.clone();
                    let actor = proof.clone();
                    let snapshot = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                let result = async {
                                    actor.check_live().map_err(|_| Error::Denied)?;
                                    rss_mdm_authorization_service::lock_shared_on(
                                        c,
                                        actor.tenant_id(),
                                        actor.instance_id(),
                                    )
                                    .await
                                    .map_err(|_| Error::Denied)?;
                                    let snapshot = rss_mdm_authorization_service::snapshot_on(
                                        c,
                                        actor.tenant_id(),
                                        actor.instance_id(),
                                    )
                                    .await
                                    .map_err(|_| Error::Denied)?;
                                    for permission in
                                        [Permission::PolicyRead, Permission::ResourceRead]
                                    {
                                        snapshot
                                            .require(&actor, permission, None)
                                            .map_err(|_| Error::Denied)?;
                                    }
                                    snapshot
                                        .require_all_devices(&actor, Permission::InventoryRead)
                                        .map_err(|_| Error::Denied)?;
                                    Ok(snapshot)
                                }
                                .await;
                                result.map_err(|e| {
                                    *rejected.lock().expect("preview rejection") = Some(e);
                                    sqlx::Error::Protocol("telemetry preview denied".into())
                                })
                            })
                        })
                        .await?;
                    rss_mdm_policy_service::management::authorize_policy_snapshot(
                        &snapshot,
                        &proof,
                        &input.definition,
                    )
                    .map_err(|_| {
                        *prepared_failure.lock().expect("preview scope authority") =
                            Some(Error::Denied);
                        crate::storage_error(Error::Denied)
                    })?;
                    let frozen = service
                        .policies
                        .prepare_in(
                            tx,
                            &binding,
                            &proof,
                            &snapshot,
                            &crate::profile_validation::ProfileValidator,
                        )
                        .await
                        .map_err(|e| {
                            let error = match e {
                                rss_mdm_policy_service::transaction::Fault::Request(
                                    rss_mdm_policy_service::Error::Forbidden
                                    | rss_mdm_policy_service::Error::Unauthorized
                                    | rss_mdm_policy_service::Error::NotFound,
                                ) => Error::Denied,
                                rss_mdm_policy_service::transaction::Fault::Request(
                                    rss_mdm_policy_service::Error::Malformed,
                                ) => Error::Invalid,
                                rss_mdm_policy_service::transaction::Fault::Request(
                                    rss_mdm_policy_service::Error::Conflict,
                                ) => Error::Conflict,
                                _ => Error::Storage,
                            };
                            *prepared_failure.lock().expect("preview preparation") = Some(error);
                            crate::storage_error(error)
                        })?;
                    let (profile, _) = rss_mdm_resource_postgres::lock_reference_in(
                        tx,
                        &rss_mdm_resource::Id::new(&binding.id).map_err(crate::storage_error)?,
                        &rss_mdm_resource::Id::new(&binding.version)
                            .map_err(crate::storage_error)?,
                    )
                    .await?
                    .map_err(crate::storage_error)?;
                    Ok((frozen, profile.digest().bytes()))
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| {
                    Err(rejection
                        .lock()
                        .expect("preview rejection")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )?;
        self.query_reads.snapshot(proof.as_ref(),(self,proof,input,&frozen,&query,&codec),|context,c,basis|Box::pin(async move {
            let (service,proof,input,frozen,query,codec)=context;
            let result=async {
                let grant=&basis.grant;
                for permission in [Permission::PolicyRead,Permission::ResourceRead] {grant.require(proof,permission,None).map_err(|_|Error::Denied)?;}
                grant.require_all_devices(proof,Permission::InventoryRead).map_err(|_|Error::Denied)?;
                rss_mdm_policy_service::management::authorize_policy_snapshot(grant,proof,&input.definition).map_err(|_|Error::Denied)?;
                for permission in [Permission::InventoryCollect,Permission::InventoryRead] {grant.require_all_devices(proof,permission).map_err(|_|Error::Denied)?;}
                if matches!(frozen.source,rss_mdm_inventory::Source::AgentScript|rss_mdm_inventory::Source::AgentOsquery) {grant.require_all_devices(proof,Permission::ScriptExecute).map_err(|_|Error::Denied)?;}
                let rss_mdm_policy::Action::TelemetryProfile{resource}= &input.definition.action else {return Err(Error::Invalid);};
                let template=&frozen.profile.spec().template;
                let facts=rss_mdm_resource_postgres::version_facts_on(c,service.tenant,&[(resource.id.clone(),resource.version.clone()),(template.resource.clone(),template.version.clone())]).await.map_err(|_|Error::Storage)?;
                let mut versions=facts.versions.into_iter();
                let (profile,profile_state)=versions.next().flatten().ok_or(Error::Conflict)?;
                let (template,template_state)=versions.next().flatten().ok_or(Error::Conflict)?;
                if profile_state!=rss_mdm_resource::State::Active || template_state!=rss_mdm_resource::State::Active || profile.digest().bytes()!=profile_digest || template.digest().bytes()!=frozen.resource_digest {return Err(Error::Conflict);}
                let fields=crate::profile_validation::validate_on(c,service.tenant,&template,&frozen.profile).await?;
                if serde_json::to_value(fields).map_err(|_|Error::Storage)?!=serde_json::to_value(&frozen.fields).map_err(|_|Error::Storage)? {return Err(Error::Conflict);}
                let authority=grant.query_binding(proof).map_err(|_|Error::Denied)?;
                let coordinate=rss_mdm_execution_service::scope::source::query_coordinate_on(c,service.tenant,input.definition.scope).await.map_err(|_|Error::Conflict)?;
                let binding=rss_mdm_execution_service::queries::window::binding(proof,&authority,rss_mdm_execution_service::queries::preview::SCHEMA.id,input.definition.scope,&json!([input.definition,input.scope_result]),&coordinate).map_err(|_|Error::Invalid)?;
                let after=rss_mdm_execution_service::queries::window::after(codec,query,&binding).map_err(|_|Error::Conflict)?;let limit=query.limit();
                let mut targets=rss_mdm_execution_service::scope::targets::objects_on(service.objects.as_ref(),c,service.tenant,input.definition.scope,rss_mdm_inventory::Channel::Agent,after.as_deref(),limit).await.map_err(|_|Error::Conflict)?;
                let result=rss_mdm_execution_service::scope::targets::devices_on(c,service.tenant,input.definition.scope,rss_mdm_inventory::Channel::Agent,None).await.map_err(|_|Error::Conflict)?.result;
                if input.scope_result.is_some_and(|v|v!=result){return Err(Error::Conflict);}
                let more=targets.len()>limit;targets.truncate(limit);
                let next=if more{targets.last().map(|v|v.object.key())}else{None};
                let mut items=Vec::new();
                for mut target in targets {
                    let supported=if let Some(device)=&target.target {
                        match crate::admission::capable_on(c,service.tenant,device.registration_id,frozen).await {Ok(())=>Some(true),Err(Error::Unsupported)=>Some(false),Err(e)=>return Err(e)}
                    }else{None};
                    if supported==Some(false){target.availability=rss_mdm_execution_service::source_authority::Availability::Unavailable;target.reason=Some("unsupported_collection".into());}
                    items.push(PreviewTarget{object:target.object,channel:target.channel,availability:target.availability,reason:target.reason,target:target.target,eligibility:target.admission,collection_supported:supported});
                }
                Ok(PreviewResponse{action:input.definition.action.clone(),scope_result:result,items,next_cursor:rss_mdm_execution_service::queries::window::next(codec,&binding,next).map_err(|_|Error::Invalid)?})
            }.await;
            Ok(result)
        })).await.map_err(|e|match e {
            rss_mdm_execution_service::Error::ReadConflict|rss_mdm_execution_service::Error::Conflict=>Error::Conflict,
            rss_mdm_execution_service::Error::Forbidden|rss_mdm_execution_service::Error::Unauthorized=>Error::Denied,
            _=>Error::Storage,
        })?
    }
}

#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewResponse {
    pub action: rss_mdm_policy::Action,
    pub scope_result: uuid::Uuid,
    pub items: Vec<PreviewTarget>,
    pub next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewTarget {
    pub object: rss_mdm_execution_service::source_authority::ObjectRef,
    pub channel: rss_mdm_inventory::Channel,
    pub availability: rss_mdm_execution_service::source_authority::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub eligibility: rss_mdm_execution_service::source_authority::ScopeAdmission,
    pub collection_supported: Option<bool>,
}
