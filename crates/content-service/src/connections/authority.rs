use super::*;
use crate::service::Error as Failure;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use std::{sync::Arc, time::Duration};
pub struct Authority {
    pub tenant: TenantId,
    pub protection: Arc<Protector>,
    pub audit: Arc<AuditStore>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub revision: i64,
    pub desired_revision: Option<i64>,
    pub versions: Vec<Receipt>,
}
fn failure(value: rss_mdm_audit_integration::TransactionError<Failure>) -> Failure {
    match value {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => e.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Failure::RollbackFailed,
    }
}
fn settle<T>(
    value: rss_transactional_messaging::transaction::LocalTxAttempt<
        T,
        rss_mdm_audit_integration::TransactionError<Failure>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Failure> {
    value.fold(
        |v| {
            if write {
                audit.mark_committed();
            }
            Ok(v)
        },
        |e| Err(failure(e)),
        |e| {
            if write {
                audit.mark_rolled_back();
            }
            Err(failure(e))
        },
        |_| {
            if write {
                audit.mark_rollback_failed();
            }
            Err(Failure::RollbackFailed)
        },
        |_| Err(Failure::CommitUnknown),
        |e| Err(failure(e)),
    )
}
impl Authority {
    pub async fn operation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
    ) -> Result<Receipt, Failure> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Failure::Forbidden);
        }
        p.require(Permission::StorageConfigurationRead, None)?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.read(self.tenant,&budget.control(),(self,p,operation),|(service,p,operation),tx|Box::pin(async move {
            let tenant=service.tenant;let operation=*operation;
            let value=tx.with_connection(move|c|Box::pin(async move {
                let row=sqlx::query("SELECT * FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant.to_string()).bind(operation).fetch_optional(c).await.map_err(|_|Failure::Storage)?.ok_or(Failure::Missing)?;
                Ok::<_,Failure>(receipt(&row)?)
            })).await?;
            p.check_live()?;Ok::<_,Failure>(value)
        })).await;
        settle(result, audit, false)
    }

    pub async fn read(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> Result<Directory, Failure> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Failure::Forbidden);
        }
        p.require(Permission::StorageConfigurationRead, None)?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.read(self.tenant,&budget.control(),(self,p),|(service,p),tx|Box::pin(async move {
            let tenant=service.tenant;
            let directory=tx.with_connection(move|c|Box::pin(async move {
                let (revision,desired): (i64,Option<i64>)=sqlx::query_as("SELECT revision,desired_revision FROM mdm_content_connections.heads WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_optional(&mut *c).await.map_err(|_|Failure::Storage)?.unwrap_or((0,None));
                let rows=sqlx::query("SELECT * FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid ORDER BY revision DESC LIMIT 64").bind(tenant.to_string()).fetch_all(c).await.map_err(|_|Failure::Storage)?;
                Ok::<_,Failure>(Directory {revision,desired_revision:desired,versions:rows.iter().map(receipt).collect::<Result<_,_>>()?})
            })).await?;
            p.check_live()?;Ok::<_,Failure>(directory)
        })).await;
        settle(result, audit, false)
    }
    pub async fn create(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        input: &Request,
    ) -> Result<Receipt, Failure> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Failure::Forbidden);
        }
        p.require(Permission::StorageConfigurationWrite, None)?;
        p.session()?;
        p.bind_audit(audit)?;
        audit.operation(operation, "storage_provision");
        audit.require_request_settlement();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.write(self.tenant,&budget.source_control(),(self,p,audit,operation,input),|(service,p,audit,operation,input),tx|Box::pin(async move {
            let mut context=(*service,*p,*operation,*input);
            let (value,replayed)=tx.with_connection_context(&mut context,|(service,p,operation,input),c|Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
                let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
                rules.require(p,Permission::StorageConfigurationWrite,None)?;
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(|_|Failure::Storage)?;
                if !p.recently_authenticated(now,300)? {return Err(Failure::Forbidden)}
                let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(service.tenant.to_string()).bind(*operation).fetch_one(&mut *c).await.map_err(|_|Failure::Storage)?;
                let actor=format!("{}:{}:{}",p.tenant_id(),p.instance_id(),p.principal_id());
                let value=prepare(c,service.tenant,*operation,input,&actor,&service.protection).await?;
                p.check_live()?;Ok::<_,Failure>((value,replayed))
            })).await?;
            let fingerprint=serde_json::to_vec(&(value.operation_id,value.revision,&value.profile)).map_err(|_|Failure::Malformed)?;
            let fact=Fact::business(audit,&format!("storage-provision:{operation}"),&fingerprint,202,"success",None)?;
            service.audit.append(tx,&fact,replayed).await?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();Ok(value)
        })).await;
        settle(result, audit, true)
    }
}
