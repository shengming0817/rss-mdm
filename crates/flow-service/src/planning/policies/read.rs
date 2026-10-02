use super::*;
use rss_mdm_execution_service::sources::{onboarding, software};
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    pub after: Option<Uuid>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    pub scope: Option<Uuid>,
    pub resource: Option<String>,
}
fn limit() -> usize {
    64
}
pub async fn read(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.manage(Permission::PolicyRead)?;
    run(
        &service.planning.audit_store,
        &service.planning.runtime,
        service.planning.tenant,
        audit,
        (&service, &auth, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (s, a, audit) = *ctx;
                a.manage(Permission::PolicyRead)?;
                let policy = storage::read_in(s.planning.policy_store.reader(), tx, id)
                    .await?
                    .ok_or(Error::Planning(
                        crate::planning::error::PlanningError::Missing(
                            crate::planning::error::Missing::Policy,
                        ),
                    ))?;
                let value = storage::view(&policy)?;
                s.planning
                    .audit_store
                    .append_request_in(tx, audit, 200, "success")
                    .await?;
                Ok(value)
            })
        },
        TransactionOwner::Planning,
    )
    .await
}
pub async fn list(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    query: &DirectoryQuery,
) -> std::result::Result<Value, Error> {
    if !(1..=1000).contains(&query.limit)
        || query.after.is_some_and(|v| v.is_nil())
        || query.scope.is_some_and(|v| v.is_nil())
        || query
            .resource
            .as_ref()
            .is_some_and(|v| resource::Id::new(v).is_err())
        || query.action.as_deref().is_some_and(|v| {
            ![
                "execution",
                "configuration",
                "software",
                "ensure_agent_installed",
                "request_mdm_enrollment",
            ]
            .contains(&v)
        })
    {
        return Err(Error::Malformed);
    }
    audit.set_action("management_read");
    auth.manage(Permission::PolicyRead)?;
    run(&service.planning.audit_store,&service.planning.runtime,service.planning.tenant,audit,(&service,&auth,audit,query),|ctx,tx|Box::pin(async move {
        let (s,a,audit,q)=*ctx;a.manage(Permission::PolicyRead)?;
        let tenant=tx.tenant_id().to_string();let query=q.clone();
        let mut ids=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR CASE WHEN $3 THEN id<$2 ELSE id>$2 END) AND ($4::boolean IS NULL OR enabled=$4) AND ($5::text IS NULL OR definition->'action'->>'kind'=$5) AND ($6::uuid IS NULL OR definition->>'scope'=$6::text) AND ($7::text IS NULL OR definition->'action'->'resource'->>'id'=$7) ORDER BY CASE WHEN NOT $3 THEN id END ASC,CASE WHEN $3 THEN id END DESC LIMIT $8")
                .bind(tenant).bind(query.after).bind(query.descending).bind(query.enabled).bind(query.action).bind(query.scope).bind(query.resource).bind((query.limit+1) as i64).fetch_all(c).await
        })).await?;
        let more=ids.len()>q.limit;ids.truncate(q.limit);
        let mut items=Vec::new();for id in &ids {items.push(storage::view(&storage::read_in(s.planning.policy_store.reader(),tx,stored(Uuid::parse_str(id))?).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Policy)))?)?);}
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"items":items,"nextCursor":if more {ids.last()} else {None}}))
    }),TransactionOwner::Planning).await
}
pub async fn devices(
    service: &Policies,
    auth: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    after: Option<String>,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.manage(Permission::PolicyRead)?;
    auth.require_all_devices(Permission::InventoryRead)?;
    run(&service.planning.audit_store,&service.planning.runtime,service.planning.tenant,audit,(&service,&auth,audit,after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=ctx;a.manage(Permission::PolicyRead)?;a.require_all_devices(Permission::InventoryRead)?;
        let p=storage::read_in(s.planning.policy_store.reader(),tx,id).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Policy)))?;
        let onboarding=if matches!(p.definition.action,Action::EnsureAgentInstalled{..}|Action::RequestMdmEnrollment{..}){Some(rss_mdm_execution_service::sources::storage::version_in(s.planning.policy_store.reader(),tx,p.version).await?.1)}else{None};
        let software=if matches!(p.definition.action,Action::Software {..}) {Some(software::read_in(s.planning.policy_store.reader(),tx,p.version).await?)}else{None};
        let tenant=tx.tenant_id().to_string();let after=after.clone();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("WITH wanted AS (SELECT r.device FROM mdm_policy.policies p JOIN mdm_planning.scopes s ON s.tenant_id=p.tenant_id AND s.id=(p.definition->>'scope')::uuid JOIN mdm_planning.scope_results r ON r.tenant_id=s.tenant_id AND r.run=s.resolution WHERE p.tenant_id=$1::uuid AND p.id=$2 UNION SELECT device FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2 UNION SELECT o.device FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid AND v.policy=$2 AND v.frozen->>'kind'='agent_install') SELECT w.device,ARRAY(SELECT DISTINCT operation FROM (SELECT c.operation FROM mdm_planning.configuration_claims c WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=w.device UNION ALL SELECT o.id FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) WHERE o.tenant_id=$1::uuid AND v.policy=$2 AND o.device=w.device AND v.frozen->>'kind'='agent_install') ops WHERE operation IS NOT NULL ORDER BY operation) AS operations,ARRAY(SELECT DISTINCT d.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=w.device AND d.diagnosis IS NOT NULL ORDER BY d.diagnosis) AS diagnoses FROM wanted w WHERE w.device>coalesce($3,'') COLLATE \"C\" ORDER BY w.device COLLATE \"C\" LIMIT 65").bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more=rows.len()>64;rows.truncate(64);let next=if more {rows.last().map(|r|r.try_get::<String,_>("device")).transpose()?}else{None};
        let mut items=Vec::new();for row in rows {
            let device:String=row.try_get("device")?;
            let eligible=rss_mdm_execution_service::sources::storage::eligible_in(&s.execution.source, tx,&p,&device).await?.is_some();
            let withdrawn=rss_mdm_execution_service::sources::storage::withdrawn_in(&s.execution.source, tx,&p,&device).await?;
            let task_admission=if let Some(software)=&software {let now=rss_mdm_execution_service::storage::now(tx).await?;Some(software.management_state_in(&s.execution,tx,&device,now).await?)}else if let Some(frozen)=&onboarding {Some(onboarding::state_in(&s.execution,tx,&device,frozen).await?)}else{None};
            let runnable=task_admission.as_ref().is_none_or(software::TaskAdmission::is_eligible);
            items.push(json!({"device":device,"assignment":if eligible && runnable{"eligible"}else if withdrawn{"excluded"}else{"pending"},"taskAdmission":task_admission,"operationIds":row.try_get::<Vec<Uuid>,_>("operations")?,"diagnoses":row.try_get::<Vec<String>,_>("diagnoses")?}));
        }
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"items":items,"nextCursor":next}))
    }),TransactionOwner::Planning).await
}
