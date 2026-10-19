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
fn transaction(e: rss_audit_postgres::TransactionError<Error>) -> Error {
    match e {
        rss_audit_postgres::TransactionError::Operation(e) => e,
        rss_audit_postgres::TransactionError::Audit(e) => {
            rss_mdm_audit_integration::Error::from(e).into()
        }
        rss_audit_postgres::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
fn settle<T>(
    value: rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_audit_postgres::Committed<T>,
        rss_audit_postgres::TransactionError<Error>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Error> {
    value.fold(
        |v| {
            if write {
                audit.mark_committed();
            }
            Ok(v.into_value())
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
        audit.operation(id, "smtp_qualification");
        audit.require_request_settlement();
        let budget = AuditBudget::new(Duration::from_secs(8));
        let result=self.audit.write(self.tenant,&budget.control(),(self,p,audit,id,input),|ctx,tx|Box::pin(async move {
            let (service,p,audit,id,input)=ctx;
            let mut context=(*service,*p,*id,*input);
            let (value,replayed)=tx.with_connection_context(&mut context,|(service,p,id,input),c|Box::pin(async move {
                rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
                let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
                rules.require(p,Permission::RegistrationConfigurationWrite,None)?;
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                let authenticated=p.session()?.view().auth_time;
                if authenticated>now || now-authenticated>300{return Err(Error::Forbidden);}
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
