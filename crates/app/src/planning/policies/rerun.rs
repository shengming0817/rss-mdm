//! Explicit rerun is one durable trigger, consumed lazily by each eligible device.
use super::*;
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Rerun {
    pub deadline: i64,
}
impl Policies {
    pub(crate) async fn rerun(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::http_operation::Operation<Rerun>,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::PolicyWrite)?;
        run(&self.planning.audit_store,&self.planning.runtime,self.planning.tenant,audit,(self,proof,op,audit),|ctx,tx|Box::pin(async move {
            let (s,proof,op,audit)=*ctx;
            let snapshot=crate::action_admission::current(tx,proof).await?;
            snapshot.require(proof,Permission::PolicyWrite,None)?;
            storage::lock(tx,id).await?;
            let policy=storage::read_in(tx,id).await?.ok_or(Error::NotFound)?;
            authorize_snapshot(&snapshot,proof,&policy.definition)?;
            let hash=fingerprint(&(id,op,proof.user()))?;
            if let Some(value)=checked(s.planning.policy_store.replay_in(tx,op.operation_id,&hash).await?)? {return Ok(value);}
            let now=crate::action_admission::now(tx).await?;
            if !policy.enabled || policy.revision as u64!=op.expected_revision {return Err(Error::Conflict.into());}
            if !matches!(policy.definition.behavior,Behavior::Execution {..}) || op.operation_id.is_nil() || op.input.deadline<=now || op.input.deadline>now.saturating_add(604800) {return Err(Error::Malformed.into());}
            checked(s.planning.policy_store.trigger_in(tx,op.operation_id,policy.version,now,op.input.deadline).await?)?;
            let value=json!({"operationId":op.operation_id,"policyId":id,"versionId":policy.version,"deadline":op.input.deadline});
            checked(s.planning.policy_store.receipt_in(tx,op.operation_id,&hash,&value).await?)?;
            s.planning.audit_store.append_in(tx,&Fact::business(audit,&format!("policy:{id}:rerun:{}",op.operation_id),&hash,200,"success",None)?,false).await?;
            proof.check_live()?;Ok(value)
        }),TransactionOwner::Planning).await
    }
}
