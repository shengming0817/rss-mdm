use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<String>,
}
pub(crate) fn routes() -> Router<Arc<Policies>> {
    Router::new()
        .route("/remote-operations", post(create))
        .route("/remote-operations/{id}", get(read))
        .route("/remote-operations/{id}/cancel", post(cancel))
        .route("/remote-operations/{id}/runs/{run}", get(run_detail))
}
async fn create(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = body.map_err(|_| Error::Malformed)?;
    if input.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    audit.operation(input.operation_id, "management_write");
    audit.target(&input.operation_id.to_string());
    s.create_remote(&a.proof, &input, &audit).await.map(Json)
}
async fn read(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    run(&s.execution.audit_store,&s.execution.runtime,s.planning.tenant,&audit,(&s,&a,&audit,page.after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=ctx;let remote=storage::read_in(tx,id).await?;storage::authorize(&a.proof,&remote.snapshot,Permission::OperationRead)?;
        let tenant=tx.tenant_id().to_string();let after=after.clone();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT t.device,t.status,t.delivery_id,t.diagnosis,r.state AS agent_state,d.status AS mdm_status,");
            query.push(crate::execution::actions::history::RESULT_SUMMARY_SQL).push(" AS result_summary FROM mdm_planning.remote_operation_targets t LEFT JOIN mdm_commands.action_runs r ON(r.tenant_id,r.id)=(t.tenant_id,t.delivery_id) LEFT JOIN rss_device_command.commands d ON d.tenant_id=t.tenant_id AND d.command_id=t.delivery_id::text WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.device>coalesce($3,'') COLLATE \"C\" ORDER BY t.device COLLATE \"C\" LIMIT 65");
            query.build().bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more=rows.len()>64;rows.truncate(64);let next=if more {rows.last().map(|r|r.try_get::<String,_>("device")).transpose()?}else{None};
        let items=rows.iter().map(|r|Ok::<_,sqlx::Error>(json!({"device":r.try_get::<String,_>("device")?,"status":r.try_get::<String,_>("status")?,"deliveryId":r.try_get::<Option<Uuid>,_>("delivery_id")?,"diagnosis":r.try_get::<Option<String>,_>("diagnosis")?,"agentState":r.try_get::<Option<Value>,_>("agent_state")?,"mdmStatus":r.try_get::<Option<String>,_>("mdm_status")?,"result":r.try_get::<Option<Value>,_>("result_summary")?}))).collect::<std::result::Result<Vec<_>,_>>()?;
        let now=crate::action_admission::now(tx).await?;
        let phase=s.execution.remote_phase_in(tx,&remote,now).await?;
        s.execution.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(Json(json!({"operationId":id,"deadline":remote.deadline,"snapshot":remote.snapshot,"phase":phase,"cancellationRequested":remote.cancelled,"deadlineElapsed":now>=remote.deadline,"items":items,"nextCursor":next})))
    }),TransactionOwner::Execution).await
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cancel {
    operation_id: Uuid,
}
async fn cancel(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<Json<Cancel>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Value>, Error> {
    let Json(input) = body.map_err(|_| Error::Malformed)?;
    if input.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    run(&s.planning.audit_store,&s.planning.runtime,s.planning.tenant,&audit,(&s,&a,&audit,&input),|ctx,tx|Box::pin(async move {
        let (s,a,audit,input)=*ctx;let remote=storage::read_in(tx,id).await?;storage::authorize(&a.proof,&remote.snapshot,Permission::OperationCancel)?;
        let auth=crate::action_admission::current(tx,&a.proof).await?;
        match &remote.snapshot {Snapshot::Devices {devices}=>for device in devices {auth.require(&a.proof,Permission::OperationCancel,Some(device))?;},Snapshot::Scope {..}=>auth.require_all_devices(&a.proof,Permission::OperationCancel)?};
        let hash=fingerprint(&(id,input,a.proof.user()))?;
        if let Some(value)=super::super::receipts::replay(tx,input.operation_id,&hash).await? {return Ok(Json(value));}
        let tenant=tx.tenant_id().to_string();tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.remote_operations SET cancelled=true WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).execute(c).await?;Ok(())})).await?;
        storage::wake_in(tx,id).await?;let value=json!({"operationId":id,"cancellationRequested":true});
        super::super::receipts::receipt(tx,input.operation_id,&hash,&value).await?;
        s.planning.audit_store.append_in(tx,&Fact::business(audit,&format!("remote:{id}:cancel:{}",input.operation_id),&hash,200,"success",None)?,false).await?;
        a.proof.check_live()?;Ok(Json(value))
    }),TransactionOwner::Planning).await
}

async fn run_detail(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, run)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action("command_read");
    audit.target(&run.to_string());
    s.execution
        .remote_action_run(&a.proof, id, run, &audit)
        .await
        .map(Json)
}
