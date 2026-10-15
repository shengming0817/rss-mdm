//! Product administrator grant and Identity account share the target transaction.
use super::*;
use rss_identity_core::account::{LoginKey, Password};
use rss_identity_postgres::{AccountProvisioner, ProvisioningError};
use rss_transactional_messaging_postgres::{PgError, PgRuntime};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct AdministratorBody {
    login: String,
    password: String,
}
impl Drop for AdministratorBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}
impl Service {
    pub(super) async fn provisioner(
        &self,
        target: TenantId,
        epoch: i64,
    ) -> std::result::Result<(Arc<PgRuntime>, AccountProvisioner), Error> {
        let runtime = crate::identity::open_runtime(
            &self.config.provisioning_database,
            &self.installation.target,
            &self.installation.lineage,
            &[(self.management, 1), (target, epoch)],
        )
        .await?;
        let provisioner = AccountProvisioner::connect(
            runtime.clone(),
            self.kdf.clone(),
            crate::identity::authority_config(
                self.installation.validate().map_err(|_| Error::Malformed)?,
                vec![self.management, target],
            )?,
            self.management,
            self.policy.clone(),
            crate::identity::deadline(),
        )
        .await
        .map_err(crate::identity::failure)?;
        Ok((runtime, provisioner))
    }
    async fn create_administrator(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        tenant: &str,
        operation: Uuid,
        body: AdministratorBody,
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
        let target = self
            .registry_read((self, proof, tenant), |(service, proof, tenant), c| {
                Box::pin(async move {
                    service
                        .authorize(c, proof, Permission::TenantAdministratorCreate)
                        .await?;
                    tenant_on(c, tenant, false).await
                })
            })
            .await?;
        // Permanent claim precedes provisioning, including failed attempts; deletion can no longer race.
        claim_database_use(
            &self.config.provisioning_database,
            &self.installation,
            tenant,
            target.current_epoch,
        )
        .await?;
        let target_id = TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
        let (runtime, provisioner) = self.provisioner(target_id, target.current_epoch).await?;
        let prepared = provisioner
            .prepare_local_account(login, password, crate::identity::deadline())
            .await
            .map_err(crate::identity::failure)?;
        let actor = proof.shared_session();
        let operator = serde_json::json!({"kind":"session","tenantId":proof.tenant_id(),"instanceId":proof.instance_id(),"principalId":proof.principal_id()});
        audit.operation(operation, "tenant_administrator_create");
        audit.target(tenant);
        audit.require_request_settlement();
        let target_audit = RequestAudit::new(tenant.into(), "tenant_administrator_create");
        // This context only supplies target fact coordinates; the source request owns settlement.
        target_audit.finalize(None);
        target_audit.set_principal(proof.principal_id(), proof.instance_id());
        target_audit.operation(operation, "tenant_administrator_create");
        let fact = Fact::business(
            &target_audit,
            &format!("tenant-administrator:{operation}"),
            digest.as_bytes(),
            200,
            "success",
            None,
        )
        .and_then(|fact| fact.with_details(serde_json::json!({"operator":operator})))
        .map_err(|_| Error::Malformed)?;
        let saved_error = std::sync::OnceLock::new();
        let outcome = runtime.local_tx_with_context(target_id,crate::identity::deadline(),
            (self, &provisioner, actor, Some(prepared), request, operator, fact, audit, &saved_error),
            |(service,provisioner,actor,prepared,request,operator,fact,audit,saved_error),tx| Box::pin(async move {
                let result = async {
                    service.audit.lock_in(tx).await.map_err(|_| Error::Unavailable(Failure::Database))?;
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
                    tx.with_connection(move |c| Box::pin(async move {
                        Ok(rss_mdm_authorization_service::store::grant_tenant_administrator_on(c, user, rule_id).await)
                    })).await.map_err(pg_error)?.map_err(Error::from)?;
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
                    service.audit.append_in(tx,fact,false).await.map_err(|_| Error::Unavailable(Failure::Database))?;
                    audit.mark_commit_started();
                    Ok(receipt)
                }.await;
                result.map_err(|error| { let _ = saved_error.set(error); PgError::from(sqlx::Error::Protocol("tenant administrator rejected".into())) })
            })).await;
        let rejected = saved_error.into_inner();
        let result = outcome.fold(
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
        );
        runtime.close().await;
        result
    }
}
fn pg_error(error: PgError) -> Error {
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
pub(super) async fn administrator(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    body: std::result::Result<Json<AdministratorBody>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    service
        .create_administrator(
            &auth.proof,
            &audit,
            &tenant,
            operation(&headers)?,
            body.map_err(|e| HttpFailure(Error::Http(e.into())))?.0,
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
