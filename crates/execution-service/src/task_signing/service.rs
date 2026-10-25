//! Task-signing management and device acknowledgement use the existing execution/audit owners.
use super::trust;
use crate::{Error, ExecutionService};
use rss_mdm_agent_wire::task_trust::{Acknowledgement, Trust};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Prepare {
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
    },
    Retire {
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        #[serde(rename = "keyId")]
        key_id: String,
    },
    Activate {
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        #[serde(rename = "keyId")]
        key_id: String,
    },
}
fn failure(error: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match error {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => e.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
fn settle<T>(
    attempt: rss_transactional_messaging::transaction::LocalTxAttempt<
        T,
        rss_mdm_audit_integration::TransactionError<Error>,
    >,
    audit: &RequestAudit,
    write: bool,
) -> Result<T, Error> {
    attempt.fold(
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
            Err(Error::RollbackFailed)
        },
        |_| Err(Error::CommitUnknown),
        |e| Err(failure(e)),
    )
}
impl ExecutionService {
    /// Current process signer identity; active authority must still be checked separately.
    pub fn loaded_task_signing_key(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.key_id())
    }

    pub async fn task_trust(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> Result<Trust, Error> {
        read_task_trust(&self.task_signing_audit, self.tenant, p, audit, None).await
    }
    pub async fn task_trust_operation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
    ) -> Result<Trust, Error> {
        read_task_trust(
            &self.task_signing_audit,
            self.tenant,
            p,
            audit,
            Some(operation),
        )
        .await
    }
    pub async fn change_task_trust(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        change: &Change,
    ) -> Result<Trust, Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        p.require(Permission::RegistrationConfigurationWrite, None)?;
        p.session()?;
        p.bind_audit(audit)?;
        audit.operation(
            operation,
            "task_signing_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.task_signing_audit.write(self.tenant,&budget.source_control(),(self,p,audit,operation,change),|(service,p,audit,operation,change),tx|Box::pin(async move {
            let mut context=(*service,*p,*operation,*change);
            let (value,replayed)=tx.with_connection_context(&mut context,|(service,p,operation,change),c|Box::pin(async move {
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
                if !p.recently_authenticated(now,300)? {return Err(Error::Unauthorized)}
                rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
                let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
                rules.require(p,Permission::RegistrationConfigurationWrite,None)?;
                let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(service.tenant.to_string()).bind(*operation).fetch_one(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
                let actor=format!("{}:{}:{}",p.tenant_id(),p.instance_id(),p.principal_id());
                let value=match change {
                    Change::Prepare{expected_revision}=>trust::prepare(c,service.tenant,*operation,*expected_revision,&service.protection,&actor).await?,
                    Change::Retire{expected_revision,key_id}=>trust::retire(c,service.tenant,*operation,*expected_revision,key_id,&service.protection,&actor).await?,
                    Change::Activate{expected_revision,key_id}=>trust::activate(c,service.tenant,*operation,*expected_revision,key_id,&service.protection,&actor).await?,
                };
                p.check_live()?;Ok::<_,Error>((value,replayed))
            })).await?;
            let digest=value.installation_digest().map_err(|_|Error::Malformed)?;
            let fact=Fact::business(audit,&format!("task-signing:{operation}"),digest.as_bytes(),200,"success",None).map_err(|_|Error::Malformed)?;
            service.task_signing_audit.append(tx,&fact,replayed).await?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();Ok(value)
        })).await;
        settle(result, audit, true)
    }
    pub async fn agent_task_trust(
        &self,
        p: &crate::device::DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<Trust, Error> {
        if p.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .task_signing_audit
            .write(
                self.tenant,
                &budget.source_control(),
                (self, p),
                |(service, p), tx| {
                    Box::pin(async move {
                        let mut context = (*service, *p);
                        tx.with_connection_context(&mut context, |(service, p), c| {
                            Box::pin(async move {
                                crate::device::store::revalidate_source(
                                    c,
                                    p,
                                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                                )
                                .await?;
                                trust::current(c, service.tenant).await
                            })
                        })
                        .await
                    })
                },
            )
            .await;
        settle(result, audit, false)
    }
    pub async fn acknowledge_task_trust(
        &self,
        p: &crate::device::DevicePrincipal,
        audit: &RequestAudit,
        input: &Acknowledgement,
    ) -> Result<(), Error> {
        if p.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        input.validate().map_err(|_| Error::Malformed)?;
        audit.operation(
            input.operation,
            "task_signing_ack",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.task_signing_audit.write(self.tenant,&budget.source_control(),(self,p,audit,input),|(service,p,audit,input),tx|Box::pin(async move {
            let mut context=(*p,*input);
            let replayed=tx.with_connection_context(&mut context,|(p,input),c|Box::pin(async move {
                crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::AgentBuiltin).await?;
                let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_task_signing.acknowledgements WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(p.tenant().to_string()).bind(input.operation).fetch_one(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
                trust::acknowledge(c,p,input).await?;Ok::<_,Error>(replayed)
            })).await?;
            let bytes=serde_json::to_vec(input).map_err(|_|Error::Malformed)?;
            let fact=Fact::business(audit,&format!("task-signing-ack:{}",input.operation),&bytes,200,"success",None).map_err(|_|Error::Malformed)?;
            service.task_signing_audit.append(tx,&fact,replayed).await?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}audit.mark_commit_started();Ok(())
        })).await;
        settle(result, audit, true)
    }
}

impl ExecutionService {
    pub async fn observe_task_trust(
        &self,
        p: &crate::device::DevicePrincipal,
        audit: &RequestAudit,
        input: &rss_mdm_agent_wire::task_trust::Observation,
    ) -> Result<(), Error> {
        input.validate().map_err(|_| Error::Malformed)?;
        if p.tenant() != self.tenant
            || input.registration != p.registration()
            || input.generation != p.generation() as u64
        {
            return Err(Error::Forbidden);
        }
        audit.operation(
            input.operation,
            "task_trust_observe",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .task_signing_audit
            .write(
                self.tenant,
                &budget.source_control(),
                (self, p, audit, input),
                |(service, p, audit, input), tx| {
                    Box::pin(async move {
                        let mut context = (*p, *input);
                        let replayed = tx
                            .with_connection_context(&mut context, |(p, input), c| {
                                Box::pin(async move {
                                    crate::device::store::revalidate_source(
                                        c,
                                        p,
                                        rss_mdm_inventory::ReportSource::AgentBuiltin,
                                    )
                                    .await?;
                                    super::observations::record_in(
                                        c,
                                        &p.tenant().to_string(),
                                        input,
                                    )
                                    .await
                                })
                            })
                            .await?;
                        let bytes = serde_json::to_vec(input).map_err(|_| Error::Malformed)?;
                        let fact = Fact::business(
                            audit,
                            &format!("task-trust-observe:{}", input.operation),
                            &bytes,
                            200,
                            "success",
                            None,
                        )
                        .map_err(|_| Error::Malformed)?;
                        service
                            .task_signing_audit
                            .append(tx, &fact, replayed)
                            .await?;
                        audit.mark_commit_started();
                        Ok(())
                    })
                },
            )
            .await;
        settle(result, audit, true)
    }
    pub async fn task_trust_observation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        device: &str,
    ) -> Result<Option<rss_mdm_agent_wire::task_trust::ObservedInstallation>, Error> {
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        p.require(Permission::InventoryRead, Some(device))?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .task_signing_audit
            .read(
                self.tenant,
                &budget.control(),
                (self, p, device),
                |(service, p, device), tx| {
                    Box::pin(async move {
                        let mut context = (*service, *device);
                        let value = tx
                            .with_connection_context(&mut context, |(service, device), c| {
                                Box::pin(async move {
                                    super::observations::latest_in(
                                        c,
                                        &service.tenant.to_string(),
                                        device,
                                    )
                                    .await
                                })
                            })
                            .await?;
                        p.check_live()?;
                        Ok(value)
                    })
                },
            )
            .await;
        settle(result, audit, false)
    }
}

pub async fn read_task_trust(
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: rss_request_context::TenantId,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    operation: Option<Uuid>,
) -> Result<Trust, Error> {
    if p.tenant_id() != tenant.to_string() {
        return Err(Error::Forbidden);
    }
    p.require(Permission::RegistrationConfigurationRead, None)?;
    p.bind_audit(audit)?;
    let budget = AuditBudget::new(Duration::from_secs(6));
    let result = store
        .read(
            tenant,
            &budget.control(),
            (tenant, p, operation),
            |(tenant, p, operation), tx| {
                Box::pin(async move {
                    let tenant = *tenant;
                    let operation = *operation;
                    let value = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                if let Some(id) = operation {
                                    trust::operation(c, tenant, id).await
                                } else {
                                    trust::current(c, tenant).await
                                }
                            })
                        })
                        .await?;
                    p.check_live()?;
                    Ok::<_, Error>(value)
                })
            },
        )
        .await;
    settle(result, audit, false)
}
