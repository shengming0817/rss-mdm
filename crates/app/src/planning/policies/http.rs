use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
pub(crate) fn routes() -> Router<Arc<Policies>> {
    Router::new()
        .route("/policies/previews", post(super::preview::preview))
        .route("/policies", get(list))
        .route("/policies/{id}", get(read).post(change))
        .route("/policies/{id}/reruns", post(rerun))
        .route("/policies/{id}/devices", get(devices))
}
async fn change(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<Change>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(|_| Error::Malformed)?;
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    service
        .change(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}
async fn read(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.proof.manage(Permission::PolicyRead)?;
    run(
        &service.planning.audit_store,
        &service.planning.runtime,
        service.planning.tenant,
        &audit,
        (&service, &auth, &audit),
        |ctx, tx| {
            Box::pin(async move {
                let (s, a, audit) = *ctx;
                a.proof.manage(Permission::PolicyRead)?;
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
                Ok(Json(value))
            })
        },
        TransactionOwner::Planning,
    )
    .await
}
async fn list(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Query(page): Query<Page>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("management_read");
    auth.proof.manage(Permission::PolicyRead)?;
    run(&service.planning.audit_store,&service.planning.runtime,service.planning.tenant,&audit,(&service,&auth,&audit,page.after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=*ctx;a.proof.manage(Permission::PolicyRead)?;
        let tenant=tx.tenant_id().to_string();let after=after.map(|v|v.to_string());
        let mut ids=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT 65").bind(tenant).bind(after).fetch_all(c).await
        })).await?;
        let more=ids.len()>64;ids.truncate(64);
        let mut items=Vec::new();for id in &ids {items.push(storage::view(&storage::read_in(s.planning.policy_store.reader(),tx,stored(Uuid::parse_str(id))?).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Policy)))?)?);}
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(Json(json!({"items":items,"nextCursor":if more {ids.last()} else {None}})))
    }),TransactionOwner::Planning).await
}

async fn rerun(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<crate::http_operation::Operation<super::rerun::Rerun>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = input.map_err(|_| Error::Malformed)?;
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    service
        .rerun(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DevicePage {
    after: Option<String>,
}
async fn devices(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<DevicePage>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    auth.proof.manage(Permission::PolicyRead)?;
    auth.proof.require_all_devices(Permission::InventoryRead)?;
    run(&service.planning.audit_store,&service.planning.runtime,service.planning.tenant,&audit,(&service,&auth,&audit,page.after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=ctx;a.proof.manage(Permission::PolicyRead)?;a.proof.require_all_devices(Permission::InventoryRead)?;
        let p=storage::read_in(s.planning.policy_store.reader(),tx,id).await?.ok_or(Error::Planning(crate::planning::error::PlanningError::Missing(crate::planning::error::Missing::Policy)))?;
        let software=if matches!(p.definition.behavior,Behavior::Software {..}) {Some(software::read_in(s.planning.policy_store.reader(),tx,p.version).await?)}else{None};
        let tenant=tx.tenant_id().to_string();let after=after.clone();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("WITH wanted AS (SELECT r.device FROM mdm_policy.policies p JOIN mdm_planning.scopes s ON s.tenant_id=p.tenant_id AND s.id=(p.definition->>'scope')::uuid JOIN mdm_planning.scope_results r ON r.tenant_id=s.tenant_id AND r.run=s.resolution WHERE p.tenant_id=$1::uuid AND p.id=$2 UNION SELECT device FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2) SELECT w.device,c.operation,d.diagnosis FROM wanted w LEFT JOIN mdm_planning.configuration_claims c ON c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=w.device LEFT JOIN mdm_planning.configuration_devices d ON d.tenant_id=c.tenant_id AND d.device=c.device WHERE w.device>coalesce($3,'') COLLATE \"C\" ORDER BY w.device COLLATE \"C\" LIMIT 65").bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more=rows.len()>64;rows.truncate(64);let next=if more {rows.last().map(|r|r.try_get::<String,_>("device")).transpose()?}else{None};
        let mut items=Vec::new();for row in rows {
            let device:String=row.try_get("device")?;
            let eligible=storage::eligible_in(tx,&p,&device).await?.is_some();
            let withdrawn=storage::withdrawn_in(tx,&p,&device).await?;
            let task_admission=if let Some(software)=&software {let now=crate::execution::storage::now(tx).await?;Some(software.management_state_in(&s.execution,tx,&device,now).await?)}else{None};
            let runnable=task_admission.as_ref().is_none_or(|v|v["state"]=="eligible");
            items.push(json!({"device":device,"assignment":if eligible && runnable{"eligible"}else if withdrawn{"excluded"}else{"pending"},"taskAdmission":task_admission,"operationId":row.try_get::<Option<Uuid>,_>("operation")?,"diagnosis":row.try_get::<Option<String>,_>("diagnosis")?}));
        }
        s.planning.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(Json(json!({"items":items,"nextCursor":next})))
    }),TransactionOwner::Planning).await
}
