//! Explicit rerun is one durable trigger, consumed lazily by each eligible device.
use super::*;
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rerun {
    pub deadline: i64,
}
impl Policies {
    pub async fn rerun(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        op: &crate::operation::Operation<Rerun>,
        audit: &RequestAudit,
    ) -> std::result::Result<Receipt, Error> {
        proof.manage(Permission::PolicyWrite)?;
        run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,op,audit),|ctx,tx|Box::pin(async move {
            let (s,proof,op,audit)=*ctx;
            let snapshot=crate::action_admission::current(tx,proof).await?;
            snapshot.require(proof,Permission::PolicyWrite,None)?;
            crate::transaction::lock(tx).await?;
            storage::lock(tx,id).await?;
            s.audit_store.prepare_in(tx,audit,&[]).await?;
            let policy=storage::read_in(s.policy_store.reader(),tx,id).await?.ok_or(Error::NotFound)?;
            authorize_policy_snapshot(&snapshot,proof,&policy.definition).map_err(Error::from)?;
            if matches!(&policy.definition.action,Action::Execution{parameters,..} if parameters.has_input()) {return Err(Error::Malformed.into());}
            let hash=fingerprint(&(id,op,proof.actor()))?;
            if let Some(value)=checked(s.policy_store.replay_in(tx,op.operation_id,&hash).await?)? {return stored(serde_json::from_value(value));}
            let now=crate::action_admission::now(tx).await?;
            if !policy.state.is_enabled() || policy.revision as u64!=op.expected_revision {return Err(Error::Conflict.into());}
            if !policy.definition.action.kind().supports_rerun() || op.operation_id.is_nil() || op.input.deadline<=now || op.input.deadline>now.saturating_add(604800) {return Err(Error::Malformed.into());}
            checked(s.policy_store.trigger_in(tx,op.operation_id,policy.version,now,op.input.deadline).await?)?;
            if matches!(policy.definition.action, Action::UnmanageDevice { .. }) {
                crate::automation::jobs::enqueue_job_in(tx,Uuid::new_v4(),&crate::automation::JobInput::PolicyReconcile { policy:id }).await?;
            }

            let value=Receipt {operation_id:op.operation_id,policy_id:id,version_id:policy.version,deadline:op.input.deadline};
            checked(s.policy_store.receipt_in(tx,op.operation_id,&hash,&stored(serde_json::to_value(&value))?).await?)?;
            s.audit_store.append_in(tx, &Fact::business(audit, &format!("policy:{id}:rerun:{}",op.operation_id), 200, "success", None)?).await?;
            proof.check_live()?;Ok(value)
        }),TransactionOwner::Planning).await
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub operation_id: Uuid,
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub deadline: i64,
}
