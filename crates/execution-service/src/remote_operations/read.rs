use super::*;
use crate::ExecutionService;
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    pub operation_id: Uuid,
}
pub async fn read(
    s: &ExecutionService,
    a: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    after: Option<String>,
) -> std::result::Result<Value, Error> {
    audit.set_action("management_read");
    audit.target(&id.to_string());
    run(&s.audit_store,&s.runtime,s.tenant,audit,(&s,&a,audit,after),|ctx,tx|Box::pin(async move {
        let (s,a,audit,after)=ctx;let remote=storage::read_in(tx,id).await?;storage::authorize(a,&remote.snapshot,Permission::OperationRead)?;
        let tenant=tx.tenant_id().to_string();let after=after.clone();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            let mut query=sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT t.device,t.status,t.delivery_id,t.diagnosis,r.state AS agent_state,d.status AS mdm_status,");
            query.push(crate::actions::history::RESULT_SUMMARY_SQL).push(" AS result_summary FROM mdm_planning.remote_operation_targets t LEFT JOIN mdm_commands.action_runs r ON(r.tenant_id,r.id)=(t.tenant_id,t.delivery_id) LEFT JOIN rss_device_command.commands d ON d.tenant_id=t.tenant_id AND d.command_id=t.delivery_id::text WHERE t.tenant_id=$1::uuid AND t.operation=$2 AND t.device>coalesce($3,'') COLLATE \"C\" ORDER BY t.device COLLATE \"C\" LIMIT 65");
            query.build().bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more=rows.len()>64;rows.truncate(64);let next=if more {rows.last().map(|r|r.try_get::<String,_>("device")).transpose()?}else{None};
        let items=rows.iter().map(|r|Ok::<_,sqlx::Error>(json!({"device":r.try_get::<String,_>("device")?,"status":r.try_get::<String,_>("status")?,"deliveryId":r.try_get::<Option<Uuid>,_>("delivery_id")?,"diagnosis":r.try_get::<Option<String>,_>("diagnosis")?,"agentState":r.try_get::<Option<Value>,_>("agent_state")?,"mdmStatus":r.try_get::<Option<String>,_>("mdm_status")?,"result":r.try_get::<Option<Value>,_>("result_summary")?}))).collect::<std::result::Result<Vec<_>,_>>()?;
        let now=crate::action_admission::now(tx).await?;
        let phase=s.remote_phase_in(tx,&remote,now).await?;
        s.audit_store.append_request_in(tx,audit,200,"success").await?;
        Ok(json!({"operationId":id,"deadline":remote.deadline,"snapshot":remote.snapshot,"phase":phase,"cancellationRequested":remote.cancelled,"deadlineElapsed":now>=remote.deadline,"items":items,"nextCursor":next}))
    }),TransactionOwner::Execution).await
}
pub async fn cancel(
    s: &ExecutionService,
    a: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    input: &Cancel,
) -> std::result::Result<Value, Error> {
    if input.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    audit.operation(input.operation_id, "management_write");
    audit.target(&id.to_string());
    run(&s.audit_store,&s.runtime,s.tenant,audit,(&s,&a,audit,&input),|ctx,tx|Box::pin(async move {
        let (s,a,audit,input)=*ctx;let remote=storage::read_in(tx,id).await?;storage::authorize(a,&remote.snapshot,Permission::OperationCancel)?;
        let auth=crate::action_admission::current(tx,a).await?;
        match &remote.snapshot {Snapshot::Devices {devices}=>for device in devices {auth.require(a,Permission::OperationCancel,Some(device))?;},Snapshot::Scope {..}=>auth.require_all_devices(a,Permission::OperationCancel)?};
        let hash=fingerprint(&(id,input,a.user()))?;
        if let Some(value)=super::receipts::replay(tx,audit,input.operation_id,&hash).await? {return Ok(value);}
        let tenant=tx.tenant_id().to_string();tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.remote_operations SET cancelled=true WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).execute(c).await?;Ok(())})).await?;
        storage::wake_in(tx,id).await?;let value=json!({"operationId":id,"cancellationRequested":true});
        super::receipts::receipt(tx,audit,input.operation_id,&hash,&value).await?;
        s.audit_store.append_in(tx,&Fact::business(audit,&format!("remote:{id}:cancel:{}",input.operation_id),&hash,200,"success",None)?,false).await?;
        a.check_live()?;Ok(value)
    }),TransactionOwner::Execution).await
}
