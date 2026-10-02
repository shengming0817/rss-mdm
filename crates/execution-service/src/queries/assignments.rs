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
use sqlx::Row;
use uuid::Uuid;
pub async fn devices(
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
        let tenant=tx.tenant_id().to_string();let after=after.clone();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("WITH wanted AS (SELECT r.device FROM mdm_policy.policies p JOIN mdm_planning.scopes s ON s.tenant_id=p.tenant_id AND s.id=(p.definition->>'scope')::uuid JOIN mdm_planning.scope_results r ON r.tenant_id=s.tenant_id AND r.run=s.resolution WHERE p.tenant_id=$1::uuid AND p.id=$2 UNION SELECT device FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2 UNION SELECT o.device FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid AND v.policy=$2 AND v.frozen->>'kind'='agent_install') SELECT w.device,ARRAY(SELECT DISTINCT operation FROM (SELECT c.operation FROM mdm_planning.configuration_claims c WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=w.device UNION ALL SELECT o.id FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid AND v.policy=$2 AND o.device=w.device AND v.frozen->>'kind'='agent_install') ops WHERE operation IS NOT NULL ORDER BY operation) AS operations,ARRAY(SELECT DISTINCT d.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=w.device AND d.diagnosis IS NOT NULL ORDER BY d.diagnosis) AS diagnoses FROM wanted w WHERE w.device>coalesce($3,'') COLLATE \"C\" ORDER BY w.device COLLATE \"C\" LIMIT 65").bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more=rows.len()>64;rows.truncate(64);let next=if more {rows.last().map(|r|r.try_get::<String,_>("device")).transpose()?}else{None};
        let mut items=Vec::new();for row in rows {
            let device:String=row.try_get("device")?;
            let eligible=crate::sources::storage::eligible_in(&s.source, tx,&p,&device).await?.is_some();
            let withdrawn=crate::sources::storage::withdrawn_in(&s.source, tx,&p,&device).await?;
            let task_admission=if let Some(software)=&software {let now=crate::storage::now(tx).await?;Some(software.management_state_in(&s.admission,tx,&device,now).await?)}else if let Some(frozen)=&onboarding {Some(onboarding::state_in(&s.admission,tx,&device,frozen).await?)}else{None};
            let runnable=task_admission.as_ref().is_none_or(software::TaskAdmission::is_eligible);
            items.push(json!({"device":device,"assignment":if eligible && runnable{"eligible"}else if withdrawn{"excluded"}else{"pending"},"taskAdmission":task_admission,"operationIds":row.try_get::<Vec<Uuid>,_>("operations")?,"diagnoses":row.try_get::<Vec<String>,_>("diagnoses")?}));
        }
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        super::records::decode(json!({"items":items,"nextCursor":next}))
    }),TransactionOwner::Execution).await.map_err(Into::into)
}
