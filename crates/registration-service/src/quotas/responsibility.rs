//! Mutable organization metadata never changes enrollment origin or self-service usage.
use super::*;
use crate::operations::{Actor, Operation};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Responsibility {
    pub revision: u64,
    pub user: Option<User>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponsibilityChange {
    pub expected_revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub user: Option<User>,
}
impl Quotas {
    pub async fn responsibility(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Responsibility, Error> {
        p.enrollment(device)?;
        let mut tx = self.store.begin(p.tenant_id()).await?;
        organization_on(&mut tx, p, device).await?;
        read_on(&mut tx, p.tenant_id(), device).await
    }
    pub async fn assign(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        change: &ResponsibilityChange,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<Responsibility, Error> {
        p.enrollment(device)?;
        rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
        if key.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        if let Some(user) = &change.user {
            user.validate(p.tenant_id(), p.instance_id())
                .map_err(|_| Error::Malformed)?;
        }
        p.bind_audit(audit)?;
        audit.operation(key, "registration_user_change");
        audit.target(device);
        let digest = crate::enrollment::digest(&(
            "registration_user.v1",
            device,
            change.expected_revision,
            &change.user,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let control = budget.control();
        let result = self.audit.write(rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Malformed)?,&control,(&self.audit,p,device,change,&op,audit), |ctx,tx| Box::pin(async move {
            let (store,p,device,change,op,audit) = *ctx;
            let (value,replayed) = tx.with_connection_context(&mut (p,device,change,op,audit), |ctx,c| Box::pin(async move {
                let (p,device,change,op,audit) = *ctx;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2671))").bind(format!("{}:{device}",p.tenant_id())).execute(&mut *c).await.map_err(db)?;
                organization_on(c,p,device).await?;
                if let Some(old) = crate::operations::replay(c,op).await? {
                    return Ok::<_,Error>((serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,true));
                }
                let current = read_on(c,p.tenant_id(),device).await?;
                if current.revision != change.expected_revision { return Err(Error::Conflict); }
                let revision = current.revision+1;
                sqlx::query("INSERT INTO mdm_access.registration_users(tenant_id,device,revision,instance,principal) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision,instance=EXCLUDED.instance,principal=EXCLUDED.principal")
                    .bind(p.tenant_id()).bind(device).bind(revision as i64).bind(change.user.as_ref().map(|u| &u.instance_id)).bind(change.user.as_ref().map(|u| &u.principal_id)).execute(&mut *c).await.map_err(db)?;
                p.enrollment(device)?;
                let value = Responsibility { revision, user: change.user.clone() };
                crate::operations::save(c,op,&serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,audit).await?;
                Ok((value,false))
            })).await?;
            let fact = Fact::business(audit,&format!("registration-user:{}:{}",p.principal_id(),op.key),op.digest.as_bytes(),200,"success",None)?;
            store.append(tx,&fact,replayed).await.map_err(Error::from)?;
            if replayed { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(value)
        })).await;
        crate::operations::settle(result, audit)
    }
}
async fn organization_on(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
) -> Result<(), Error> {
    p.enrollment(device)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r LEFT JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) LEFT JOIN mdm_access.agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.purpose='primary' AND ((r.channel='mdm' AND NOT q.self_service) OR (r.channel='agent' AND g.source='native'))) OR EXISTS(SELECT 1 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND g.device=$2 AND NOT q.self_service AND q.state<>'cancelled')")
        .bind(p.tenant_id()).bind(device).fetch_one(c).await.map_err(db)?;
    if exists { Ok(()) } else { Err(Error::NotFound) }
}
async fn read_on(
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Responsibility, Error> {
    let row = sqlx::query("SELECT revision,instance,principal FROM mdm_access.registration_users WHERE tenant_id=$1::uuid AND device=$2").bind(tenant).bind(device).fetch_optional(c).await.map_err(db)?;
    if let Some(row) = row {
        let instance: Option<String> = row.try_get("instance").map_err(db)?;
        let principal: Option<String> = row.try_get("principal").map_err(db)?;
        let user = instance
            .zip(principal)
            .map(|(instance_id, principal_id)| User {
                tenant_id: tenant.into(),
                instance_id,
                principal_id,
            });
        Ok(Responsibility {
            revision: u64::try_from(row.try_get::<i64, _>("revision").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
            user,
        })
    } else {
        Ok(Responsibility {
            revision: 0,
            user: None,
        })
    }
}
