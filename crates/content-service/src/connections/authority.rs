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
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub revision: i64,
    pub desired_revision: Option<i64>,
    pub version_count: i64,
    pub current: Option<Receipt>,
    pub latest: Option<Receipt>,
    pub applied: Option<Receipt>,
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
        applied: Option<i64>,
    ) -> Result<Directory, Failure> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Failure::Forbidden);
        }
        p.require(Permission::StorageConfigurationRead, None)?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.read(self.tenant,&budget.control(),(self,p,applied),|(service,p,applied),tx|Box::pin(async move {
            let tenant=service.tenant;let applied=*applied;
            let directory=tx.with_connection(move|c|Box::pin(async move {
                let (revision,desired): (i64,Option<i64>)=sqlx::query_as("SELECT revision,desired_revision FROM mdm_content_connections.heads WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_optional(&mut *c).await.map_err(|_|Failure::Storage)?.unwrap_or((0,None));
                let version_count=sqlx::query_scalar("SELECT count(*) FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut *c).await.map_err(|_|Failure::Storage)?;
                let rows=sqlx::query("SELECT operation_id,revision,profile,state,failure_reason,selected,revoked,qualified_at,expires_at FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND (revision=$2 OR revision=$3 OR revision=$4)").bind(tenant.to_string()).bind(revision).bind(desired).bind(applied).fetch_all(c).await.map_err(|_|Failure::Storage)?;
                let values=rows.iter().map(receipt).collect::<Result<Vec<_>,_>>()?;
                Ok::<_,Failure>(Directory {revision,desired_revision:desired,version_count,current:values.iter().find(|v|Some(v.revision)==desired).cloned(),latest:values.iter().find(|v|v.revision==revision).cloned(),applied:values.iter().find(|v|Some(v.revision)==applied).cloned()})

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
        audit.operation(
            operation,
            "storage_provision",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
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

            let fact=Fact::business(audit, &format!("storage-provision:{operation}"), 202, "success", None)?;
            (if replayed { Ok(()) } else { service.audit.append(tx, &fact).await })?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();Ok(value)
        })).await;
        settle(result, audit, true)
    }
}

pub static HISTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "storage_connection_versions",
    default_limit: 64,
    max_limit: 200,
    order: "revision DESC",
    context: &[],
};

impl Authority {
    pub async fn history(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        q: &rss_mdm_query::window::Query,
        codec: &rss_mdm_query::cursor::CursorCodec,
    ) -> Result<rss_mdm_query::Page<Receipt>, Failure> {
        q.require_schema(&HISTORY).map_err(|_| Failure::Malformed)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Failure::Forbidden);
        }
        p.require(Permission::StorageConfigurationRead, None)?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.read(self.tenant,&budget.control(),(p,q,codec),|ctx,tx|Box::pin(async move{
   tx.with_connection_context(ctx,|(p,q,codec),c|Box::pin(async move{
    rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
    let current=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
    current.require(p,Permission::StorageConfigurationRead,None).map_err(rss_mdm_authorization_service::Error::from)?;
    let binding=rss_mdm_query::cursor::fingerprint(&("storage_connection_versions",p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(|_|Failure::Malformed)?;
    let before:Option<i64>=q.cursor().as_ref().map(|v|codec.decode(&rss_contract::PageCursor::parse(v).map_err(|_|Failure::Malformed)?,&binding).map_err(|_|Failure::Conflict)).transpose()?;
    let rows=sqlx::query("SELECT operation_id,revision,profile,state,failure_reason,selected,revoked,qualified_at,expires_at FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision<$2) ORDER BY revision DESC LIMIT $3").bind(p.tenant_id()).bind(before).bind((q.limit()+1) as i64).fetch_all(c).await.map_err(|_|Failure::Storage)?;
    let more=rows.len()>q.limit();let items=rows.iter().take(q.limit()).map(|r|receipt(r).map_err(Failure::from)).collect::<Result<Vec<_>,_>>()?;
    let next_cursor=if more{items.last().map(|v|codec.encode(&binding,&v.revision).map(|v|v.as_str().to_owned()).map_err(|_|Failure::Conflict)).transpose()?}else{None};
    p.check_live()?;Ok(rss_mdm_query::Page{items,next_cursor})
   })).await
  })).await;
        settle(result, audit, false)
    }
}
