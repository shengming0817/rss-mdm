use super::*;
use crate::operations::{Actor, Operation};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use uuid::Uuid;
impl Quotas {
    pub async fn change(
        &self,
        p: &AuthorizedPrincipal,
        user: Option<&User>,
        change: &Change,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<Configuration, Error> {
        p.manage(Permission::AuthorizationWrite)?;
        let subject = subject(p, user)?;
        if key.is_nil()
            || change.expected_revision >= i64::MAX as u64
            || (user.is_none() && Channel::ALL.iter().any(|c| change.limits.get(*c).is_none()))
        {
            return Err(Error::Malformed);
        }
        p.bind_audit(audit)?;
        audit.operation(key, "registration_quota_change");
        let digest = crate::enrollment::digest(&(
            "registration_quota.v1",
            &subject,
            change.expected_revision,
            &change.limits,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let control = budget.control();
        let result = self.audit.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Malformed)?, &control, (&self.audit,p,&subject,change,&op,audit), |ctx, tx| Box::pin(async move {
            let (store,p,subject,change,op,audit) = *ctx;
            let (value,replayed) = tx.with_connection_context(&mut (p,subject,change,op,audit), |ctx,c| Box::pin(async move {
                let (p,subject,change,op,audit) = *ctx;
                lock_on(c, p.tenant_id()).await?;
                if let Some(old) = crate::operations::replay(c,op).await? {
                    return Ok::<_,Error>((serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,true));
                }
                let current = configuration_on(c,p.tenant_id(),subject).await?;
                if current.revision != change.expected_revision { return Err(Error::Conflict); }
                let revision = current.revision + 1;
                sqlx::query("INSERT INTO mdm_access.registration_quota_settings(tenant_id,subject,revision,agent,windows_mdm,macos_mdm) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,subject) DO UPDATE SET revision=EXCLUDED.revision,agent=EXCLUDED.agent,windows_mdm=EXCLUDED.windows_mdm,macos_mdm=EXCLUDED.macos_mdm")
                    .bind(p.tenant_id()).bind(subject).bind(revision as i64).bind(change.limits.agent.map(i64::from)).bind(change.limits.windows_mdm.map(i64::from)).bind(change.limits.macos_mdm.map(i64::from)).execute(&mut *c).await.map_err(db)?;
                p.manage(Permission::AuthorizationWrite)?;
                let value = Configuration { revision, limits: change.limits.clone() };
                crate::operations::save(c,op,&serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,audit).await?;
                Ok((value,false))
            })).await?;
            let fact = Fact::business(audit,&format!("registration-quota:{}:{}",p.principal_id(),op.key),op.digest.as_bytes(),200,"success",None)?;
            store.append(tx,&fact,replayed).await.map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(value)
        })).await;
        crate::operations::settle(result, audit)
    }
}
