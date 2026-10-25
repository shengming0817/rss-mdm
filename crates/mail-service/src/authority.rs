//! 原业务会话授权和材料写入共用审计事务；只暴露固定 SMTP 资格用例。
use crate::store::{self, Directory, Receipt, Request};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Error, Permission, context::AuthorizedPrincipal};
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub struct Authority {
    pub tenant: TenantId,
    pub protection: Arc<Protector>,
    pub audit: Arc<AuditStore>,
}
fn error(e: crate::Error) -> Error {
    match e {
        crate::Error::Input => Error::Malformed,
        crate::Error::Conflict => Error::Conflict,
        crate::Error::Unknown => Error::CommitUnknown,
        _ => Error::Storage,
    }
}
fn transaction(e: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match e {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => e.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
fn settle<T>(
    value: rss_transactional_messaging::transaction::LocalTxAttempt<
        T,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Error> {
    value.fold(
        |v| {
            if write {
                audit.mark_committed();
            }
            Ok(v)
        },
        |e| Err(transaction(e)),
        |e| {
            if write {
                audit.mark_rolled_back();
            }
            Err(transaction(e))
        },
        |_| {
            if write {
                audit.mark_rollback_failed();
            }
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |e| Err(transaction(e)),
    )
}
impl Authority {
    fn proof(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        write: bool,
    ) -> Result<(), Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        p.require(
            if write {
                Permission::RegistrationConfigurationWrite
            } else {
                Permission::RegistrationConfigurationRead
            },
            None,
        )?;
        p.bind_audit(audit)?;
        Ok(())
    }
    pub async fn read(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> Result<Directory, Error> {
        self.proof(p, audit, false)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let value = self
            .audit
            .read(self.tenant, &budget.control(), p, |p, tx| {
                Box::pin(async move {
                    let tenant = p.tenant_id().to_owned();
                    let value = tx
                        .with_connection(move |c| {
                            Box::pin(
                                async move { store::directory(c, &tenant).await.map_err(error) },
                            )
                        })
                        .await?;
                    p.check_live()?;
                    Ok::<_, Error>(value)
                })
            })
            .await;
        settle(value, audit, false)
    }
    pub async fn operation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: Uuid,
    ) -> Result<Receipt, Error> {
        self.proof(p, audit, false)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let value = self
            .audit
            .read(self.tenant, &budget.control(), p, |p, tx| {
                Box::pin(async move {
                    let tenant = p.tenant_id().to_owned();
                    let value = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                store::operation(c, &tenant, id).await.map_err(error)
                            })
                        })
                        .await?;
                    p.check_live()?;
                    Ok::<_, Error>(value)
                })
            })
            .await;
        settle(value, audit, false)
    }
    pub async fn create(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        id: Uuid,
        input: &Request,
    ) -> Result<Receipt, Error> {
        self.proof(p, audit, true)?;
        p.session()?;
        audit.operation(
            id,
            "smtp_qualification",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(8));
        let result=self.audit.write(self.tenant,&budget.source_control(),(self,p,audit,id,input),|ctx,tx|Box::pin(async move {
            let (service,p,audit,id,input)=ctx;
            let mut context=(*service,*p,*id,*input);
            let (value,replayed)=tx.with_connection_context(&mut context,|(service,p,id,input),c|Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
                let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
                rules.require(p,Permission::RegistrationConfigurationWrite,None)?;
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                if !p.recently_authenticated(now,300)?{return Err(Error::Forbidden);}
                let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(p.tenant_id()).bind(*id).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                let actor=format!("{}:{}:{}",p.tenant_id(),p.instance_id(),p.principal_id());
                let value=store::prepare(c,p.tenant_id(),*id,&actor,input,&service.protection).await.map_err(error)?;
                p.check_live()?;Ok::<_,Error>((value,replayed))
            })).await?;
            let fingerprint=serde_json::to_vec(&(value.operation_id,value.revision,&value.profile)).map_err(|_|Error::Malformed)?;
            let fact=Fact::business(audit,&format!("smtp-qualification:{id}"),&fingerprint,202,"success",None)?;
            service.audit.append(tx,&fact,replayed).await?;
            if replayed{audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();Ok(value)
        })).await;
        settle(result, audit, true)
    }
}

pub static HISTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "smtp_versions",
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
    ) -> Result<rss_mdm_query::Page<Receipt>, Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        p.require(Permission::RegistrationConfigurationRead, None)?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.read(self.tenant,&budget.control(),(p,q,codec),|ctx,tx|Box::pin(async move{
   tx.with_connection_context(ctx,|(p,q,codec),c|Box::pin(async move{
    rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
    let current=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
    current.require(p,Permission::RegistrationConfigurationRead,None).map_err(rss_mdm_authorization_service::Error::from)?;
    let binding=rss_mdm_query::cursor::fingerprint(&("smtp_versions",p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(|_|Error::Malformed)?;
    let before:Option<i64>=q.cursor.as_ref().map(|v|codec.decode(&rss_contract::PageCursor::parse(v).map_err(|_|Error::Malformed)?,&binding).map_err(|_|Error::Conflict)).transpose()?;
    let rows=sqlx::query("SELECT operation_id,revision,profile,state,attempted_at,accepted_at,failure_reason FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND ($2::bigint IS NULL OR revision<$2) ORDER BY revision DESC LIMIT $3").bind(p.tenant_id()).bind(before).bind((q.limit+1) as i64).fetch_all(c).await.map_err(|_|Error::Storage)?;
    let more=rows.len()>q.limit;let items=rows.iter().take(q.limit).map(|r|store::receipt(r).map_err(error)).collect::<Result<Vec<_>,_>>()?;
    let next_cursor=if more{items.last().map(|v|codec.encode(&binding,&v.revision).map(|v|v.as_str().to_owned()).map_err(|_|Error::Conflict)).transpose()?}else{None};
    p.check_live()?;Ok(rss_mdm_query::Page{items,next_cursor})
   })).await
  })).await;
        settle(result, audit, false)
    }
}
