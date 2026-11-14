//! Product administrator grant and Identity account share the target transaction.
use super::service::{Service, project};
use super::*;
use rss_identity_core::account::{LoginKey, Password};
use rss_identity_postgres::ProvisioningError;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use serde::Deserialize;

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AdministratorInput {
    pub(super) login: String,
    pub(super) password: String,
}
impl Drop for AdministratorInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}
impl Service {
    pub(super) async fn create_administrator(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        tenant: &str,
        operation: Uuid,
        body: AdministratorInput,
        cutoff: rss_request_context::Deadline,
    ) -> std::result::Result<Receipt, Error> {
        validate_tenant(&self.installation, tenant).map_err(project)?;
        proof.require(Permission::TenantAdministratorCreate, None)?;
        if tenant == self.management.to_string() {
            return Err(Error::Forbidden);
        }
        let login = LoginKey::parse(&body.login).map_err(|_| Error::Malformed)?;
        let password = Password::new(body.password.clone()).map_err(|_| Error::Malformed)?;
        let canonical = zeroize::Zeroizing::new(
            serde_json::to_vec(&(tenant, login.as_str(), &body.password))
                .map_err(|_| Error::Malformed)?,
        );
        let tag = ring::hmac::sign(&self.fingerprint, &canonical);
        let digest: String = tag
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = serde_json::json!({"action":"administrator_create","tenantId":tenant,"login":login.as_str(),"fingerprint":digest});
        self.registry_read(
            Some(cutoff),
            (self, proof, tenant),
            |(service, proof, tenant), c| {
                Box::pin(async move {
                    service
                        .authorize(c, proof, Permission::TenantAdministratorCreate)
                        .await?;
                    tenant_on(c, tenant, false).await
                })
            },
        )
        .await?;
        let slot = self
            .provisioning_slots
            .try_acquire()
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        // The original first-use fact is committed on the shared runtime before account work.
        let target_id = TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
        let target_binding = self
            .installation
            .execution(target_id, self.execution_epoch)
            .map_err(|_| Error::Malformed)?;
        let runtime = &self.provisioning_runtime;
        let installation = &self.installation;
        let claimed = runtime
            .local_tx_with_context(
                target_binding,
                rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                    cutoff,
                    &crate::lifecycle::RuntimeTimer,
                ),
                installation,
                |installation, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(installation, move |installation, c| {
                            Box::pin(async move {
                                sqlx::query_scalar::<_, bool>(
                                    "SELECT public.claim_tenant_use($1::uuid,$2,$3::uuid,$4,$5,$6)",
                                )
                                .bind(target_binding.tenant().to_string())
                                .bind(target_binding.epoch().get())
                                .bind(&installation.instance_id)
                                .bind(&installation.target[..])
                                .bind(&installation.lineage[..])
                                .bind(installation.audit_mode.as_str())
                                .fetch_one(c)
                                .await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(pg_error(e)),
                |e| Err(pg_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(pg_error(e)),
            )?;
        if !claimed {
            return Err(Error::Forbidden);
        }
        let provisioner = &self.provisioner;
        let source = &self.provisioning_audit;
        let result = async {
        let prepared = provisioner
            .prepare_local_account(login, password, rss_transactional_messaging::policy::OperationDeadline::from_cutoff(cutoff, &crate::lifecycle::RuntimeTimer))
            .await
            .map_err(crate::identity::failure)?;
        let actor = proof.shared_session()?;
        let operator = serde_json::json!({"kind":"session","tenantId":proof.tenant_id(),"instanceId":proof.instance_id(),"principalId":proof.principal_id()});
        audit.owned_operation(rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
            operation,
            "tenant_administrator_create",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target(tenant);
        audit.require_final_request();
        let target_audit = audit.tenant_fact_copy(target_binding,"tenant_administrator_create");
        // This context only supplies target fact coordinates; the source request owns settlement.
        target_audit.finalize(None);
        target_audit.set_principal(proof.principal_id(), proof.instance_id());
        target_audit.owned_operation(rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
            operation,
            "tenant_administrator_create",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let fact = Fact::business(
            &target_audit, rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
            &format!("tenant-administrator:{operation}"),
            200,
            "success",
            None,
        )
        .and_then(|fact| fact.with_details(serde_json::json!({"operator":operator})))
        .map_err(|_| Error::Malformed)?;
        let saved_error = std::sync::OnceLock::new();
        let outcome = runtime.local_tx_with_context(target_binding,rss_transactional_messaging::policy::OperationDeadline::from_cutoff(cutoff, &crate::lifecycle::RuntimeTimer),
            (self, &provisioner, actor, Some(prepared), request, operator, fact, audit, &saved_error, &source, &target_audit),
            |(service,provisioner,actor,prepared,request,operator,fact,audit,saved_error,source,target_audit),tx| Box::pin(async move {
                let result = async {
                    source.prepare_in(tx,target_audit,&[]).await?;
                    tx.with_connection(|c| Box::pin(async move {
                        sqlx::query("SELECT pg_advisory_xact_lock(2346)").execute(c).await?;
                        Ok(())
                    })).await.map_err(pg_error)?;
                    // Revalidate source session and current grants on every replay, under the source fence.
                    provisioner.authorize_in(tx,actor.clone()).await.map_err(provisioning_error)?;
                    let operation_request = request.clone();
                    let original = tx.with_connection(move |c| Box::pin(async move {
                        Ok(receipt_on(c,operation).await)
                    })).await.map_err(pg_error)?.map_err(project)?;
                    if let Some((receipt, original)) = original {
                        if original != operation_request { return Err(Error::Conflict); }
                        audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                        return Ok(receipt);
                    }
                    let account = provisioner.create_local_account_in(tx,actor.clone(),prepared.take().ok_or(Error::Malformed)?).await.map_err(provisioning_error)?;
                    let tenant = target_id.to_string();
                    let principal = account.key().principal.as_uuid().to_string();
                    let rule_id = Uuid::new_v4();
                    let user = rss_mdm_authorization_service::User {
                        instance_id: service.installation.instance_id.clone(), tenant_id: tenant.clone(), principal_id: principal.clone(),
                    };
                    let targets=crate::administration::baseline::manifest::build(uuid::Uuid::parse_str(&user.tenant_id).map_err(|_|Error::Malformed)?)?.targets();
                    tx.with_connection(move |c| Box::pin(async move {
                        Ok(async {
                            let (_,authority)=rss_mdm_authorization_service::baseline::grant_administrator_on(target_binding, rss_mdm_install_support::StorageProfile::Mdm, c,user,rule_id,targets).await?;
                            crate::administration::baseline::reserve_on(c,&authority).await
                        }.await)
                    })).await.map_err(pg_error)??;
                    let receipt = Receipt { operation_id: operation,action:Action::AdministratorCreate,result:ReceiptResult::Administrator(Administrator {
                        tenant_id:tenant.clone(),principal_id:principal,login:request["login"].as_str().ok_or(Error::Malformed)?.into(),rule_id,rule_revision:1,
                    })};
                    let receipt_json = serde_json::to_value(&receipt).map_err(|_| Error::Malformed)?;
                    let request = request.clone();
                    let operator = operator.clone();
                    tx.with_connection(move |c| Box::pin(async move {
                        sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt,operator) VALUES($1,$2::uuid,'administrator_create',$3,$4,$5)")
                            .bind(operation).bind(&tenant).bind(request).bind(receipt_json).bind(operator).execute(c).await?;
                        Ok(())
                    })).await.map_err(pg_error)?;
                    source.append_in(tx, fact).await?;
                    audit.mark_commit_started();
                    Ok(receipt)
                }.await;
                result.map_err(|error| { let _ = saved_error.set(error); PgError::from(sqlx::Error::Protocol("tenant administrator rejected".into())) })
            })).await;
        let rejected = saved_error.into_inner();
        outcome.fold(
            |receipt| {
                if audit.snapshot().write_outcome
                    == rss_mdm_audit_integration::WriteOutcome::Unknown
                {
                    audit.mark_committed();
                }
                Ok(receipt)
            },
            |error| Err(pg_error(error)),
            |error| {
                audit.mark_rolled_back();
                Err(rejected.unwrap_or_else(|| pg_error(error)))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |error| Err(pg_error(error)),
        )
        }.await;
        drop(slot);
        result
    }
}
pub(super) fn pg_error(error: PgError) -> Error {
    match error.kind() {
        rss_transactional_messaging::error::MessagingErrorKind::Conflict => Error::Conflict,
        rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost => Error::Forbidden,
        _ => Error::Unavailable(Failure::Database),
    }
}
fn provisioning_error(error: ProvisioningError) -> Error {
    match error {
        ProvisioningError::Rejected => Error::Forbidden,
        ProvisioningError::Storage(error) => pg_error(error),
        ProvisioningError::Authority(error) => crate::identity::failure(error),
        ProvisioningError::Rule(rss_identity_core::account::AccountRuleError::AlreadyExists) => {
            Error::Conflict
        }
        ProvisioningError::Rule(_) => Error::Forbidden,
    }
}
