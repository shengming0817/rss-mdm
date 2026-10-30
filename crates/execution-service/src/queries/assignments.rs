use crate::sources::{onboarding, software, storage};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_assignments",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
pub async fn assignments(
    service: &Queries,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    query: &rss_mdm_query::window::Query,
    codec: &rss_mdm_query::cursor::CursorCodec,
) -> std::result::Result<super::records::AssignmentPage, crate::queries::QueryError> {
    query
        .require_schema(&SCHEMA)
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
    service.snapshot(auth,(service,auth,audit,query,codec),|ctx,c,basis|Box::pin(async move {
        let (s,a,_audit,query,codec)=*ctx;let limit=query.limit();let current=&basis.grant;current.require(a,Permission::PolicyRead,None)?;current.require_all_devices(a,Permission::InventoryRead)?;
        let p=storage::read_on(&s.policy_reader,c,id).await?.ok_or(Error::NotFound)?;
        let authority=current.query_binding(a)?;let scope=p.definition.scope;let input=json!([id,p.revision,p.version]);
        let binding=super::window::binding_on(s,c,a,&authority,SCHEMA.id,scope,&input).await?;
        let page=async {
        let after=super::window::after(codec,query,&binding)?;
        if matches!(p.definition.action,Action::UnmanageDevice {..}) {
            let page=super::lifecycle::assignments_on(s,c,&p,after.as_deref(),limit,codec,&binding).await?;

            return Ok(page);
        }
        let onboarding=if matches!(p.definition.action,Action::EnsureAgentInstalled{..}|Action::RequestMdmEnrollment{..}){Some(crate::sources::storage::version_on(&s.policy_reader,c,p.version).await?.1)}else{None};
        let software=if matches!(p.definition.action,Action::Software {..}) {Some(software::read_on(&s.policy_reader,c,p.version).await?)}else{None};
        let source=s.source.clone();let tenant=s.tenant;let scope=p.definition.scope;let cursor=after.clone();let channel=crate::source_authority::action_channel(&p.definition.action)?;
        let mut objects=source.assignment_objects_on(c,tenant,scope,channel,cursor.as_deref(),limit).await?;
        let t=tenant.to_string();let version=p.version;let channel_name=channel.as_str();let cursor=after.clone();
        let retired=sqlx::query_scalar::<_,serde_json::Value>("SELECT input FROM mdm_policy.assignments WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND channel=$4 AND reason='source_removed' AND object>coalesce($5,'') COLLATE \"C\" ORDER BY object LIMIT $6").bind(t).bind(id).bind(version).bind(channel_name).bind(cursor).bind((limit+1) as i64).fetch_all(&mut *c).await?;
        for value in retired {let row:crate::source_authority::AssignmentObject=serde_json::from_value(value).map_err(|_|Error::Malformed)?;if !objects.iter().any(|o|o.object==row.object){objects.push(row);}}
        objects.sort_by_key(|o|o.object.key());
        let more=objects.len()>limit;objects.truncate(limit);let next=if more {objects.last().map(|o|o.object.key())}else{None};
        let mut items=Vec::new();
        for mut object in objects {
            let mut operations=Vec::new();let mut task_admission=None;
            if !p.state.is_enabled() {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("policy_disabled".into());}
            if let Some(target)=&object.target {
                let device=&target.device;
                let eligible=rss_mdm_registration_service::lifecycle::work_allowed_on(c,&tenant.to_string(),device).await?;
                if !eligible && object.availability==crate::source_authority::Availability::Ready {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("source_pending".into());}
                task_admission=if let Some(software)=&software {let now=basis.now;Some(software.assignment.management_state_on(&s.admission,c,tenant,device,now).await?)}else if let Some(frozen)=&onboarding {Some(onboarding::state_on(&s.admission,c,tenant,device,frozen,p.version,basis.now).await?)}else{None};
                if object.availability==crate::source_authority::Availability::Ready && task_admission.as_ref().is_some_and(|a|!software::TaskAdmission::is_eligible(a)) {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
                if matches!(p.definition.action,Action::Configuration {..}) && (object.availability==crate::source_authority::Availability::Ready || object.reason.as_deref()==Some("policy_disabled")) {
                    let tenant=tenant.to_string();let device=device.clone();
                    let diagnosis=sqlx::query_scalar::<_,String>("SELECT d.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=$3 AND d.diagnosis IS NOT NULL ORDER BY d.diagnosis LIMIT 1").bind(tenant).bind(id).bind(device).fetch_optional(&mut *c).await?;
                    if let Some(reason)=diagnosis {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some(reason);}
                }
                let tenant=tenant.to_string();let device=device.clone();let registration=target.registration_id;let generation=target.generation;let channel_name=channel.as_str();
                operations=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.device=$3 AND ((o.registration=$4 AND o.registration_generation=$5) OR EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=o.tenant_id AND child.id=o.registration AND child.generation=o.registration_generation AND child.device=o.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5)) AND $6='mdm' AND (o.authority->>'kind'<>'agent_install' OR o.authority->>'stage'='install') AND (EXISTS(SELECT 1 FROM mdm_planning.configuration_claims c WHERE c.tenant_id=o.tenant_id AND c.policy=$2 AND c.device=o.device AND c.operation=o.id) OR EXISTS(SELECT 1 FROM mdm_policy.versions v WHERE v.tenant_id=o.tenant_id AND v.id=o.policy_version AND v.policy=$2 AND v.action_kind<>'configuration')) UNION SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND ((r.registration=$4 AND r.generation=$5) OR ($6='mdm' AND EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=r.tenant_id AND child.id=r.registration AND child.generation=r.generation AND child.device=r.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5))) AND v.action_kind=ANY(CASE WHEN $6='mdm' THEN ARRAY['configuration','native_collection','ensure_agent_installed'] ELSE ARRAY['execution','agent_collection','software','request_mdm_enrollment'] END) ORDER BY id").bind(tenant).bind(id).bind(device).bind(registration).bind(generation).bind(channel_name).fetch_all(&mut *c).await?;
            }
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"qualification":object.admission,"sources":object.sources,"scopeResult":object.scope_result,"taskAdmission":task_admission,"operationIds":operations}));
        }

        super::records::decode(json!({"items":items,"nextCursor":super::window::next(codec,&binding,next)?}))
        }.await?;
        Ok(page)
    })).await.map_err(|error| match error { Error::NotFound => super::QueryError::Missing(super::Missing::Policy), other => other.into() })
}
