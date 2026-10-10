use crate::sources::{onboarding, software, storage};
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
    queries::Queries,
    transaction::*,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_policy::Action;
use serde_json::json;
use uuid::Uuid;
pub async fn assignments(
    service: &Queries,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    after: Option<String>,
) -> std::result::Result<super::records::AssignmentPage, crate::queries::QueryError> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.manage(Permission::PolicyRead)?;
    auth.require_all_devices(Permission::InventoryRead)?;
    run(&service.audit_store,&service.runtime,service.tenant,audit,(&service,&auth,audit,after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=ctx;let current=crate::action_admission::current(tx,a).await?;current.require(a,Permission::PolicyRead,None)?;current.require_all_devices(a,Permission::InventoryRead)?;
        let p=storage::read_in(&s.policy_reader,tx,id).await?.ok_or(Error::NotFound)?;
        let onboarding=if matches!(p.definition.action,Action::EnsureAgentInstalled{..}|Action::RequestMdmEnrollment{..}){Some(crate::sources::storage::version_in(&s.policy_reader,tx,p.version).await?.1)}else{None};
        let software=if matches!(p.definition.action,Action::Software {..}) {Some(software::read_in(&s.policy_reader,tx,p.version).await?)}else{None};
        let source=s.source.clone();let tenant=tx.tenant_id();let scope=p.definition.scope;let cursor=after.clone();let channel=crate::source_authority::action_channel(p.definition.action.kind());
        let mut objects=tx.with_connection(move|c|Box::pin(async move {Ok(source.assignment_objects_on(c,tenant,scope,channel,cursor.as_deref()).await)})).await??;
        let t=tenant.to_string();let version=p.version;let channel_name=channel.as_str();let cursor=after.clone();
        let retired=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,serde_json::Value>("SELECT input FROM mdm_planning.policy_assignments WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND channel=$4 AND reason='source_removed' AND object>coalesce($5,'') COLLATE \"C\" ORDER BY object LIMIT 65").bind(t).bind(id).bind(version).bind(channel_name).bind(cursor).fetch_all(c).await})).await?;
        for value in retired {let row:crate::source_authority::AssignmentObject=serde_json::from_value(value).map_err(|_|Error::Malformed)?;if !objects.iter().any(|o|o.object==row.object){objects.push(row);}}
        objects.sort_by_key(|o|o.object.key());
        let more=objects.len()>64;objects.truncate(64);let next=if more {objects.last().map(|o|o.object.key())}else{None};
        let source=s.source.clone();let version=p.version;
        let readable=tx.with_connection(move|c|Box::pin(async move {Ok(source.policy_readable_on(c,tenant,version).await)})).await??;
        let mut items=Vec::new();
        for mut object in objects {
            let mut operations=Vec::new();let mut task_admission=None;
            if !readable {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("source_forbidden".into());}
            if !p.enabled && readable {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("policy_disabled".into());}
            if let Some(target)=&object.target {
                let device=&target.device;
                let eligible=crate::sources::storage::eligible_in(&s.source,tx,&p,device).await?.is_some();
                if !eligible && object.availability==crate::source_authority::Availability::Ready {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("source_pending".into());}
                task_admission=if let Some(software)=&software {let now=crate::storage::now(tx).await?;Some(software.assignment.management_state_in(&s.admission,tx,device,now).await?)}else if let Some(frozen)=&onboarding {Some(onboarding::state_in(&s.admission,tx,device,frozen).await?)}else{None};
                if object.availability==crate::source_authority::Availability::Ready && task_admission.as_ref().is_some_and(|a|!software::TaskAdmission::is_eligible(a)) {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some("target_unavailable".into());}
                if matches!(p.definition.action,Action::Configuration {..}) && (object.availability==crate::source_authority::Availability::Ready || object.reason.as_deref()==Some("policy_disabled")) {
                    let tenant=tenant.to_string();let device=device.clone();
                    let diagnosis=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,String>("SELECT d.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=$3 AND d.diagnosis IS NOT NULL ORDER BY d.diagnosis LIMIT 1").bind(tenant).bind(id).bind(device).fetch_optional(c).await})).await?;
                    if let Some(reason)=diagnosis {object.availability=crate::source_authority::Availability::Unavailable;object.reason=Some(reason);}
                }
                let tenant=tenant.to_string();let device=device.clone();let registration=target.registration_id;let generation=target.generation;let channel_name=channel.as_str();
                operations=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.device=$3 AND ((o.registration=$4 AND o.registration_generation=$5) OR EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=o.tenant_id AND child.id=o.registration AND child.generation=o.registration_generation AND child.device=o.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5)) AND $6='mdm' AND (EXISTS(SELECT 1 FROM mdm_planning.configuration_claims c WHERE c.tenant_id=o.tenant_id AND c.policy=$2 AND c.device=o.device AND c.operation=o.id) OR EXISTS(SELECT 1 FROM mdm_policy.versions v WHERE v.tenant_id=o.tenant_id AND v.id=o.policy_version AND v.policy=$2 AND v.action_kind<>'configuration')) UNION SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND ((r.registration=$4 AND r.generation=$5) OR ($6='mdm' AND EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=r.tenant_id AND child.id=r.registration AND child.generation=r.generation AND child.device=r.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5))) AND v.action_kind=ANY(CASE WHEN $6='mdm' THEN ARRAY['configuration','native_collection','ensure_agent_installed'] ELSE ARRAY['execution','software','request_mdm_enrollment'] END) ORDER BY id").bind(tenant).bind(id).bind(device).bind(registration).bind(generation).bind(channel_name).fetch_all(c).await})).await?;
            }
            items.push(json!({"object":object.object,"channel":object.channel,"availability":object.availability,"reason":object.reason,"target":object.target,"qualification":object.admission,"sources":object.sources,"scopeResult":object.scope_result,"taskAdmission":task_admission,"operationIds":operations}));
        }
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        super::records::decode(json!({"items":items,"nextCursor":next}))
    })).await.map_err(|error| match error { Error::NotFound => super::QueryError::Missing(super::Missing::Policy), other => other.into() })
}
