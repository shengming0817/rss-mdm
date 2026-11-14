//! Task Trust settles management and device acknowledgements with the existing Audit owner.
use super::trust;
use crate::{Error, Service, Use};
use rss_mdm_agent_wire::task_trust::{Acknowledgement, Trust};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

#[derive(schemars::JsonSchema, Serialize, Deserialize)]
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
pub(crate) fn settle<T>(
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
impl Service {
    pub(crate) fn require_device(
        &self,
        p: &rss_mdm_registration_service::DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<(), Error> {
        audit.bind_scope(p.binding())?;
        if p.profile() != self.signing.profile
            || p.tenant() != audit.binding()?.tenant()
            || audit.profile() != self.signing.profile
            || audit.tenant() != audit.binding()?.tenant().to_string()
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    /// Inspect the same current private material used by an operation, without a startup selection.
    pub async fn signing_material(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Option<(String, u64)>, Error> {
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit
            .write(
                execution,
                &budget.source_control(),
                (&self.signing, execution),
                |context, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(context, |(signing, execution), c| {
                            Box::pin(async move {
                                let current = match trust::current(
                                    signing.profile,
                                    signing.usage,
                                    c,
                                    execution.tenant(),
                                )
                                .await
                                {
                                    Ok(value) => value,
                                    Err(Error::NotFound | Error::Unsupported) => return Ok(None),
                                    Err(error) => return Err(error),
                                };
                                let loaded = trust::load(
                                    signing.profile,
                                    signing.usage,
                                    c,
                                    execution.tenant(),
                                    current.revision,
                                    &signing.protection,
                                )
                                .await?;
                                Ok(Some((loaded.task.key_id().to_owned(), current.revision)))
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(failure(e)),
                |e| Err(failure(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(failure(e)),
            )
    }

    pub async fn task_trust(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> Result<Trust, Error> {
        read_task_trust(
            self.signing.profile,
            self.signing.usage,
            &self.audit,
            p.binding().tenant(),
            p,
            audit,
            None,
        )
        .await
    }
    pub async fn task_trust_operation(
        &self,
        p: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
    ) -> Result<Trust, Error> {
        read_task_trust(
            self.signing.profile,
            self.signing.usage,
            &self.audit,
            p.binding().tenant(),
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
        let profile = self.signing.profile;
        let usage = self.signing.usage;

        if p.profile() != profile {
            return Err(Error::Forbidden);
        }
        p.require(Permission::RegistrationConfigurationWrite, None)?;
        p.session()?;
        p.bind_audit(audit)?;
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::TaskTrust,
            operation,
            "task_signing_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result=self.audit.write(
            p.binding(),&budget.source_control(),(self,p,audit,operation,change),|(service,p,audit,operation,change),tx|Box::pin(async move {
            let mut context=(*service,*p,*operation,*change);
            let (value,replayed)=tx.with_connection_context(&mut context,|(service,p,operation,change),c|Box::pin(async move {
                let now:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
                if !p.recently_authenticated(now,300)? {return Err(Error::Unauthorized)}
                rss_mdm_authorization_service::lock_shared_on(p.authority_profile(),  c,p.tenant_id(),p.instance_id()).await?;
                let rules=rss_mdm_authorization_service::snapshot_on(p.authority_profile(),  c,p.tenant_id(),p.instance_id()).await?;
                rules.require(p,Permission::RegistrationConfigurationWrite,None)?;
                let replayed:bool=sqlx::query_scalar(crate::storage_profile::sql(profile, usage).service_change_task_trust_1).bind(p.binding().tenant().to_string()).bind(*operation).fetch_one(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
                let actor=format!("{}:{}:{}",p.tenant_id(),p.instance_id(),p.principal_id());
                let value=match change {
                    Change::Prepare{expected_revision}=>trust::prepare(profile, usage, c,p.binding().tenant(),*operation,*expected_revision,&service.protection,&actor).await?,
                    Change::Retire{expected_revision,key_id}=>trust::retire(profile, usage, c,p.binding().tenant(),*operation,*expected_revision,key_id,&service.protection,&actor,service.retirement.as_deref()).await?,
                    Change::Activate{expected_revision,key_id}=>trust::activate(profile, usage, c,p.binding().tenant(),*operation,*expected_revision,key_id,&service.protection,&actor).await?,
                };
                p.check_live()?;Ok::<_,Error>((value,replayed))
            })).await?;

            let fact=Fact::business(audit, rss_mdm_audit_integration::operation::OperationOwner::TaskTrust, &format!("task-signing:{}:{operation}",usage.as_str()), 200, "success", None).map_err(|_|Error::Malformed)?;
            (if replayed { Ok(()) } else { service.audit.append(tx, &fact).await })?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            audit.mark_commit_started();Ok(value)
        })).await;
        settle(result, audit, true)
    }
    pub async fn device_trust(
        &self,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        audit: &RequestAudit,
    ) -> Result<Trust, Error> {
        let profile = self.signing.profile;
        let usage = self.signing.usage;

        self.require_device(p, audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .audit
            .write(
                audit.binding()?,
                &budget.source_control(),
                (self, p),
                |(service, p), tx| {
                    Box::pin(async move {
                        let mut context = (*service, *p);
                        tx.with_connection_context(&mut context, |(_, p), c| {
                            Box::pin(async move {
                                rss_mdm_registration_service::device::require_use_in(c, p, usage)
                                    .await?;
                                trust::current(profile, usage, c, p.binding().tenant()).await
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
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        audit: &RequestAudit,
        input: &Acknowledgement,
    ) -> Result<(), Error> {
        let profile = self.signing.profile;
        let usage = self.signing.usage;

        self.require_device(p, audit)?;
        input.validate().map_err(|_| Error::Malformed)?;
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::TaskTrust,
            input.operation,
            "task_signing_ack",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .audit
            .write(
                audit.binding()?,
                &budget.source_control(),
                (self, p, audit, input),
                |(service, p, audit, input), tx| {
                    Box::pin(async move {
                        let mut context = (*p, *input);
                        let replayed = tx
                            .with_connection_context(&mut context, |(p, input), c| {
                                Box::pin(async move {
                                    rss_mdm_registration_service::device::require_use_in(
                                        c, p, usage,
                                    )
                                    .await?;
                                    let replayed: bool = sqlx::query_scalar(
                                        crate::storage_profile::sql(profile, usage)
                                            .service_acknowledge_task_trust_1,
                                    )
                                    .bind(p.tenant().to_string())
                                    .bind(input.operation)
                                    .fetch_one(&mut *c)
                                    .await
                                    .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
                                    trust::acknowledge(profile, usage, c, p, input).await?;
                                    Ok::<_, Error>(replayed)
                                })
                            })
                            .await?;

                        let fact = Fact::business(
                            audit,
                            rss_mdm_audit_integration::operation::OperationOwner::TaskTrust,
                            &format!("task-signing-ack:{}:{}", usage.as_str(), input.operation),
                            200,
                            "success",
                            None,
                        )
                        .map_err(|_| Error::Malformed)?;
                        (if replayed {
                            Ok(())
                        } else {
                            service.audit.append(tx, &fact).await
                        })?;
                        if replayed {
                            audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        audit.mark_commit_started();
                        Ok(())
                    })
                },
            )
            .await;
        settle(result, audit, true)
    }
}

impl Service {
    pub async fn observe_task_trust(
        &self,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        audit: &RequestAudit,
        input: &rss_mdm_agent_wire::task_trust::Observation,
    ) -> Result<(), Error> {
        let profile = self.signing.profile;
        let usage = self.signing.usage;

        self.require_device(p, audit)?;
        input.validate().map_err(|_| Error::Malformed)?;
        if input.device_id != *p.device() {
            return Err(Error::Forbidden);
        }
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::TaskTrust,
            input.operation,
            "task_trust_observe",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .audit
            .write(
                audit.binding()?,
                &budget.source_control(),
                (self, p, audit, input),
                |(service, p, audit, input), tx| {
                    Box::pin(async move {
                        let mut context = (*p, *input);
                        let replayed = tx
                            .with_connection_context(&mut context, |(p, input), c| {
                                Box::pin(async move {
                                    rss_mdm_registration_service::device::require_use_in(
                                        c, p, usage,
                                    )
                                    .await?;
                                    super::observations::record_in(
                                        profile,
                                        usage,
                                        c,
                                        &p.tenant().to_string(),
                                        input,
                                    )
                                    .await
                                })
                            })
                            .await?;

                        let fact = Fact::business(
                            audit,
                            rss_mdm_audit_integration::operation::OperationOwner::TaskTrust,
                            &format!("task-trust-observe:{}", input.operation),
                            200,
                            "success",
                            None,
                        )
                        .map_err(|_| Error::Malformed)?;
                        (if replayed {
                            Ok(())
                        } else {
                            service.audit.append(tx, &fact).await
                        })?;
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
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Option<rss_mdm_agent_wire::task_trust::ObservedInstallation>, Error> {
        let profile = self.signing.profile;
        let usage = self.signing.usage;

        if p.profile() != profile {
            return Err(Error::Forbidden);
        }
        p.require(Permission::InventoryRead, Some(device))?;
        p.bind_audit(audit)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let result = self
            .audit
            .read(
                p.binding().tenant(),
                &budget.control(),
                (self, p, device),
                |(_, p, device), tx| {
                    Box::pin(async move {
                        let mut context = (*p, *device);
                        let value = tx
                            .with_connection_context(&mut context, |(p, device), c| {
                                Box::pin(async move {
                                    super::observations::latest_in(
                                        profile,
                                        usage,
                                        c,
                                        &p.binding().tenant().to_string(),
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
    profile: rss_mdm_install_support::StorageProfile,
    usage: Use,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: rss_request_context::TenantId,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    operation: Option<Uuid>,
) -> Result<Trust, Error> {
    if p.profile() != profile || p.tenant_id() != tenant.to_string() {
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
                                    trust::operation(profile, usage, c, tenant, id).await
                                } else {
                                    trust::current(profile, usage, c, tenant).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::transaction::LocalTxAttempt;
    #[test]
    fn settlement_preserves_unknown_and_failed_rollback() {
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            rss_transactional_messaging::fence::ExecutionBinding::new(
                rss_transactional_messaging::fence::StorageIdentity::new([1; 16], [2; 16]).unwrap(),
                rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
                rss_transactional_messaging::fence::Epoch::new(1).unwrap(),
            ),
            "task-trust",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let result = settle::<()>(
            LocalTxAttempt::commit_unknown(rss_mdm_audit_integration::TransactionError::Operation(
                Error::Conflict,
            )),
            &audit,
            true,
        );
        assert!(matches!(result, Err(Error::CommitUnknown)));
        let result = settle::<()>(
            LocalTxAttempt::rollback_failed(
                rss_mdm_audit_integration::TransactionError::Operation(Error::Conflict),
            ),
            &audit,
            true,
        );
        assert!(matches!(result, Err(Error::RollbackFailed)));
    }
}
