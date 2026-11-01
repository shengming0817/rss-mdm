use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;
pub(super) async fn assignments(
    service: &Reads,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<rss_mdm_management_http::execution::task_reads::AssignmentPage, Error> {
    query
        .require_schema(&rss_mdm_policy::pages::ASSIGNMENTS_SCHEMA)
        .map_err(|_| Error::Malformed)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    auth.manage(Permission::PolicyRead)?;
    auth.require_all_devices(Permission::InventoryRead)?;
    service.snapshot(auth,(service,auth,audit,query,codec),|ctx,c,current,now|Box::pin(async move {
        let (s,a,_audit,query,codec)=*ctx;let limit=query.limit();current.require(a,Permission::PolicyRead,None)?;current.require_all_devices(a,Permission::InventoryRead)?;
        let p=s.policy_reader.read_on(c,id).await.map_err(|_|Error::Unavailable(Failure::PlanningStorage))?.map_err(|_|Error::Conflict)?.ok_or(Error::PolicyMissing)?;
        let authority=current.query_binding(a)?;let scope=p.definition.scope;let input=json!([id,p.revision,p.version]);
        let binding=rss_mdm_scope_service::window::binding_on(&s.source,c,a,&authority,rss_mdm_policy::pages::ASSIGNMENTS_SCHEMA.id,scope,&input).await.map_err(window)?;
        let page=async {
        let after=rss_mdm_scope_service::window::after(codec,query,&binding).map_err(window)?;
        if matches!(p.definition.action,Action::UnmanageDevice {..}) {
            let page=s.execution.lifecycle_assignments_on(c,&p,after.as_deref(),limit,codec,&binding).await.map_err(super::history::execution_fault)?;

            return Ok(super::projections::execution_assignments(page));
        }
        let source=s.source.clone();let tenant=s.tenant;let scope=p.definition.scope;let cursor=after.clone();let channel=match p.definition.action.target_channel() {Some(rss_mdm_policy::SoftwareChannel::Agent)=>rss_mdm_inventory::Channel::Agent,Some(rss_mdm_policy::SoftwareChannel::Mdm)=>rss_mdm_inventory::Channel::Mdm,None=>return Err(Error::Malformed)};
        let mut objects=source.assignment_objects_on(c,tenant,scope,channel,cursor.as_deref(),limit).await.map_err(super::source)?;
        let t=tenant.to_string();let version=p.version;let channel_name=channel.as_str();let cursor=after.clone();
        let retired=sqlx::query_scalar::<_,serde_json::Value>("SELECT input FROM mdm_policy.assignments WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND channel=$4 AND reason='source_removed' AND object>coalesce($5,'') COLLATE \"C\" ORDER BY object LIMIT $6").bind(t).bind(id).bind(version).bind(channel_name).bind(cursor).bind((limit+1) as i64).fetch_all(&mut *c).await.map_err(sql)?;
        for value in retired {let row:rss_mdm_scope_service::channels::AssignmentObject=serde_json::from_value(value).map_err(|_|Error::Malformed)?;if !objects.iter().any(|o|o.object==row.object){objects.push(row);}}
        objects.sort_by_key(|o|o.object.key());
        let more=objects.len()>limit;objects.truncate(limit);let next=if more {objects.last().map(|o|o.object.key())}else{None};
        let mut items=Vec::new();
        for mut object in objects {
            let mut operations=Vec::new();let mut task_admission=None;
            if !p.state.is_enabled() {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some("policy_disabled".into());}
            if let Some(target)=&object.target {
                let device=&target.device;
                let eligible=rss_mdm_registration_service::lifecycle::work_allowed_on(c,&tenant.to_string(),device).await?;
                if !eligible && object.availability==rss_mdm_scope_service::channels::Availability::Ready {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some("source_pending".into());}
                let diagnosis=match &p.definition.action {
                    Action::Software{..}|Action::EnsureAgentInstalled{..}=>{
                        let state=s.software.assignment_state_on(c,&p,target,channel,now).await.map_err(software_fault)?;
                        task_admission=state.task_admission;operations=state.operations;state.diagnosis
                    },
                    Action::DeviceAccess{..}=>{operations=rss_mdm_registration_service::device_access::execution::queries::assignment_ids_on(c,tenant,id,target,channel).await.map_err(access_fault)?;None},
                    Action::Credential{..}=>{operations=rss_mdm_recovery_credentials::tasks::queries::assignment_ids_on(c,tenant,id,target,channel).await.map_err(credential_fault)?;None},
                    Action::RequestMdmEnrollment{..}=>{
                        task_admission=Some(rss_mdm_registration_service::enrollment::tasks::queries::assignment_state_on(c,tenant,&s.enrollment,&p,device,now).await.map_err(enrollment_fault)?);
                        operations=rss_mdm_registration_service::enrollment::tasks::queries::assignment_ids_on(c,tenant,id,target,channel).await.map_err(enrollment_fault)?;None
                    },
                    _=>{let state=s.execution.assignment_state_on(c,&p,target,channel,now).await.map_err(super::history::execution_fault)?;task_admission=state.task_admission;operations=state.operations;state.diagnosis}
                };
                if object.availability==rss_mdm_scope_service::channels::Availability::Ready && task_admission.as_ref().is_some_and(|a|!a.is_eligible()) {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
                if (object.availability==rss_mdm_scope_service::channels::Availability::Ready||object.reason.as_deref()==Some("policy_disabled")) && let Some(reason)=diagnosis {object.availability=rss_mdm_scope_service::channels::Availability::Unavailable;object.reason=Some(reason);}
                operations.extend(rss_mdm_script_service::queries::assignment_ids_on(c,tenant,id,target,channel).await.map_err(script_fault)?);
                operations.extend(rss_mdm_inventory_service::collection::execution::queries::assignment_ids_on(c,tenant,id,target,channel).await?);
                operations.sort();
                if operations.windows(2).any(|ids|ids[0]==ids[1]) {return Err(Error::Unavailable(Failure::CommandInvariant));}

            }
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"qualification":object.admission,"sources":object.sources,"scopeResult":object.scope_result,"taskAdmission":task_admission,"operationIds":operations}));
        }

        serde_json::from_value(json!({"items":items,"nextCursor":rss_mdm_scope_service::window::next(codec,&binding,next).map_err(window)?})).map_err(|_|Error::Unavailable(Failure::CommandInvariant))
        }.await?;
        Ok(page)
    })).await
}
