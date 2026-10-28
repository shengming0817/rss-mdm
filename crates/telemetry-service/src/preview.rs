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
        let service = self.clone();
        let proof = proof.clone();
        let _audit = audit.clone();
        let rejection = Arc::new(Mutex::new(None));
        let rejected = rejection.clone();
        self.runtime.local_tx(self.tenant,crate::deadline(),move|tx|Box::pin(async move {
            service.planning.audit_store.bind_in(tx).await.map_err(crate::storage_error)?;
            let prepared_failure=rejected.clone();
            let actor=proof.clone();
            let snapshot=tx.with_connection(move|c|Box::pin(async move {
                let result=async {
                    actor.check_live().map_err(|_|Error::Denied)?;
                    rss_mdm_authorization_service::lock_on(c,actor.tenant_id(),actor.instance_id()).await.map_err(|_|Error::Denied)?;
                    let snapshot=rss_mdm_authorization_service::snapshot_on(c,actor.tenant_id(),actor.instance_id()).await.map_err(|_|Error::Denied)?;
                    for permission in [Permission::PolicyRead,Permission::ResourceRead] {snapshot.require(&actor,permission,None).map_err(|_|Error::Denied)?;}
                    snapshot.require_all_devices(&actor,Permission::InventoryRead).map_err(|_|Error::Denied)?;
                    Ok(snapshot)
                }.await;
                result.map_err(|e|{*rejected.lock().expect("preview rejection")=Some(e);sqlx::Error::Protocol("telemetry preview denied".into())})
            })).await?;
            rss_mdm_execution_service::authorize_policy_snapshot(&snapshot,&proof,&input.definition).map_err(|_|{*prepared_failure.lock().expect("preview scope authority")=Some(Error::Denied);crate::storage_error(Error::Denied)})?;
            let frozen=rss_mdm_flow_service::planning::policies::telemetry::prepare_in(tx,&binding,&proof,&snapshot).await.map_err(|e| {
                let error=match e {
                    rss_mdm_flow_service::transaction::Fault::Request(rss_mdm_flow_service::Error::Forbidden|rss_mdm_flow_service::Error::Unauthorized|rss_mdm_flow_service::Error::NotFound)=>Error::Denied,
                    rss_mdm_flow_service::transaction::Fault::Request(rss_mdm_flow_service::Error::Malformed)=>Error::Invalid,
                    rss_mdm_flow_service::transaction::Fault::Request(rss_mdm_flow_service::Error::Conflict)=>Error::Conflict,
                    _=>Error::Storage,
                };
                *prepared_failure.lock().expect("preview preparation")=Some(error);crate::storage_error(error)
            })?;
            let preview_service=service.clone();
            let value=tx.with_connection(move|c|Box::pin(async move {
                let result=async {
                    let authority=snapshot.query_binding(&proof).map_err(|_|Error::Denied)?;
                    let coordinate=rss_mdm_execution_service::scope::source::query_coordinate_on(c,preview_service.tenant,input.definition.scope).await.map_err(|_|Error::Conflict)?;
                    let binding=rss_mdm_execution_service::queries::window::binding(&proof,&authority,rss_mdm_execution_service::queries::preview::SCHEMA.id,input.definition.scope,&json!([input.definition,input.scope_result]),&coordinate).map_err(|_|Error::Invalid)?;
                    let after=rss_mdm_execution_service::queries::window::after(&codec,&query,&binding).map_err(|_|Error::Conflict)?;let limit=query.limit();
                    let (mut targets,result)=rss_mdm_flow_service::planning::policies::telemetry::preview_targets_on(&preview_service.planning,c,input.definition.scope,after.as_deref(),limit).await.map_err(|_|Error::Conflict)?;
                    if input.scope_result.is_some_and(|v|v!=result) {return Err(Error::Conflict);}
                    let more=targets.len()>limit;targets.truncate(limit);
                    let next=if more {targets.last().map(|v|v.object.key())}else{None};
                    let mut items=Vec::new();
                    for mut target in targets {
                        let supported=if let Some(device)=&target.target {
                            match crate::admission::capable_on(c,preview_service.tenant,device.registration_id,&frozen).await {Ok(())=>Some(true),Err(Error::Unsupported)=>Some(false),Err(e)=>return Err(e)}
                        } else {None};
                        if supported==Some(false) {target.availability=rss_mdm_execution_service::source_authority::Availability::Unavailable;target.reason=Some("unsupported_collection".into());}
                        items.push(PreviewTarget { object:target.object,channel:target.channel,availability:target.availability,reason:target.reason,target:target.target,eligibility:target.admission,collection_supported:supported });
                    }
                    if coordinate != rss_mdm_execution_service::scope::source::query_coordinate_on(c,preview_service.tenant,input.definition.scope).await.map_err(|_|Error::Conflict)? { return Err(Error::Conflict); }
                    proof.check_live().map_err(|_|Error::Denied)?;
                    Ok(PreviewResponse {action:input.definition.action,scope_result:result,items,next_cursor:rss_mdm_execution_service::queries::window::next(&codec,&binding,next).map_err(|_|Error::Invalid)?})
                }.await;
                Ok(result)
            })).await?;
            let value=value.map_err(|e|{*prepared_failure.lock().expect("preview target page")=Some(e);crate::storage_error(e)})?;

            Ok(value)
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(rejection.lock().expect("preview rejection").unwrap_or(Error::Storage)),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
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
