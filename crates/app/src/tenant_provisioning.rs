//! Complete tenant creation starts one durable operation; host execution never runs in HTTP.
use super::*;
use crate::setup::model::{Phase, Provisioning};
use rss_identity_core::account::{LoginKey, Password};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Body {
    name: String,
    administrator_login: String,
    administrator_password: String,
}
impl Drop for Body {
    fn drop(&mut self) {
        self.administrator_password.zeroize();
    }
}
pub(super) async fn create(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    body: std::result::Result<Json<Body>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<(axum::http::StatusCode, Json<Receipt>), HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    let operation = operation(&headers)?;
    let receipt = service
        .provision(&auth.proof, &audit, operation, &body)
        .await?;
    let complete =
        matches!(&receipt.result,ReceiptResult::Provisioning(p) if p.phase==Phase::Enabled);
    Ok((
        if complete {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::ACCEPTED
        },
        Json(receipt),
    ))
}
impl Service {
    async fn provision(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        body: &Body,
    ) -> std::result::Result<Receipt, Error> {
        proof.shared_session()?;
        proof.require(Permission::TenantCreate, None)?;
        proof.require(Permission::TenantAdministratorCreate, None)?;
        if body.name.trim().is_empty()
            || body.name.chars().count() > 128
            || body.name.contains('\0')
        {
            return Err(Error::Malformed);
        }
        let login = LoginKey::parse(&body.administrator_login).map_err(|_| Error::Malformed)?;
        Password::new(body.administrator_password.clone()).map_err(|_| Error::Malformed)?;
        let canonical = zeroize::Zeroizing::new(
            serde_json::to_vec(&(&body.name, login.as_str(), &body.administrator_password))
                .map_err(|_| Error::Malformed)?,
        );
        let digest = ring::hmac::sign(&self.fingerprint, &canonical)
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let (receipt, administrator_operation) = self
            .reserve_provisioning(proof, audit, operation, &body.name, &digest)
            .await?;
        let ReceiptResult::Provisioning(progress) = &receipt.result else {
            return Err(Error::Conflict);
        };
        if progress.administrator_id.is_some() {
            return Ok(receipt);
        }
        let child_audit =
            RequestAudit::new(self.management.to_string(), "tenant_administrator_create");
        proof.bind_audit(&child_audit)?;
        let result = self
            .create_administrator(
                proof,
                &child_audit,
                &progress.tenant_id.to_string(),
                administrator_operation,
                administrator::AdministratorBody {
                    login: login.as_str().into(),
                    password: body.administrator_password.clone(),
                },
            )
            .await;
        child_audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        let account = result?;
        let ReceiptResult::Administrator(account) = account.result else {
            return Err(Error::Conflict);
        };
        let principal = Uuid::parse_str(&account.principal_id).map_err(|_| Error::Malformed)?;
        self.record_administrator(proof, operation, principal).await
    }
    async fn reserve_provisioning(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        name: &str,
        digest: &str,
    ) -> std::result::Result<(Receipt, Uuid), Error> {
        audit.operation(operation, "tenant_provision");
        audit.require_request_settlement();
        let fact = Fact::business(
            audit,
            &format!("tenant-provision:{operation}"),
            digest.as_bytes(),
            202,
            "success",
            None,
        )
        .map_err(|_| Error::Malformed)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let attempt=self.audit.write(self.management,&budget.source_control(),(self,proof,operation,name,digest,fact,audit),|(service,proof,operation,name,digest,fact,audit),tx|Box::pin(async move {
            let mut context=(&**service,*proof,*operation,*name,*digest);
            let (receipt,administrator_operation,replayed)=tx.with_connection_context(&mut context,|(service,proof,operation,name,digest),c|Box::pin(async move {
                sqlx::query("SELECT pg_advisory_xact_lock(2346)").execute(&mut *c).await.map_err(|_|Reason::Storage)?;
                service.authorize(c,proof,Permission::TenantCreate).await?;
                service.authorize(c,proof,Permission::TenantAdministratorCreate).await?;
                if let Some((receipt,request))=receipt_on(c,*operation).await? {
                    if receipt.action!=Action::Provision || request["fingerprint"].as_str()!=Some(*digest) {return Err(Reason::Conflict);}
                    let child=Uuid::parse_str(request["administratorOperationId"].as_str().ok_or(Reason::Storage)?).map_err(|_|Reason::Storage)?;
                    return Ok((receipt,child,true));
                }
                let tenant=Uuid::new_v4();let administrator_operation=Uuid::new_v4();
                let tenant_text=tenant.to_string();
                let mutation=Mutation {installation:&service.installation,tenant_id:&tenant_text,operation_id:*operation,action:Action::Create,initial_epoch:Some(1),expected_revision:None,name:Some(name),notes:None};
                insert_tenant_on(c,&mutation).await?;
                let receipt=Receipt {operation_id:*operation,action:Action::Provision,result:ReceiptResult::Provisioning(Provisioning {
                    operation_id:*operation,tenant_id:tenant,administrator_id:None,host_id:Uuid::new_v4(),revision:1,phase:Phase::Reserved,blocked:None,origin:None,application:None,
                })};
                let actor=serde_json::json!({"kind":"session","tenantId":proof.tenant_id(),"instanceId":proof.instance_id(),"principalId":proof.principal_id()});
                let request=serde_json::json!({"fingerprint":digest,"administratorOperationId":administrator_operation});
                sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt,operator) VALUES($1,$2,'provision',$3,$4,$5)")
                    .bind(*operation).bind(tenant).bind(request).bind(serde_json::to_value(&receipt).map_err(|_|Reason::Storage)?).bind(actor)
                    .execute(&mut *c).await.map_err(|_|Reason::Storage)?;
                scope(c,proof.tenant_id()).await?;
                Ok::<_,Reason>((receipt,administrator_operation,false))
            })).await?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            else {service.audit.append(tx,fact,false).await.map_err(|_|Reason::Storage)?;}
            audit.mark_commit_started();
            Ok::<_,Reason>((receipt,administrator_operation))
        })).await;
        attempt.fold(
            |value| {
                audit.mark_committed();
                Ok(value)
            },
            |error| Err(tx_error(error)),
            |error| {
                audit.mark_rolled_back();
                Err(tx_error(error))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |error| Err(tx_error(error)),
        )
    }

    async fn record_administrator(
        &self,
        proof: &AuthorizedPrincipal,
        operation: Uuid,
        principal: Uuid,
    ) -> std::result::Result<Receipt, Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        connection.close_on_drop();
        let mut tx = connection
            .begin()
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        sqlx::raw_sql("SET LOCAL statement_timeout='6s'; SET LOCAL lock_timeout='6s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        sqlx::query("SELECT pg_advisory_xact_lock(2346)")
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        self.authorize(&mut tx, proof, Permission::TenantAdministratorCreate)
            .await
            .map_err(project)?;
        let (mut receipt, _) = receipt_on(&mut tx, operation)
            .await
            .map_err(project)?
            .ok_or(Error::Conflict)?;
        let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
            return Err(Error::Conflict);
        };
        if progress.administrator_id.is_some_and(|id| id != principal) {
            return Err(Error::Conflict);
        }
        if progress.administrator_id.is_none() {
            progress.administrator_id = Some(principal);
            progress.phase = Phase::HostPending;
            progress.revision = progress.revision.checked_add(1).ok_or(Error::Conflict)?;
            sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=$2 WHERE operation_id=$1 AND action='provision'")
                .bind(operation).bind(serde_json::to_value(&receipt).map_err(|_|Error::Malformed)?)
                .execute(&mut *tx).await.map_err(|_|Error::Unavailable(Failure::Database))?;
        }
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(receipt)
    }
}
