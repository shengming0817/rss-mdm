//! One durable tenant operation composes existing account and baseline receipts.
use super::administrator::AdministratorInput;
use super::service::{Service, project, tx_error};
use super::*;
use crate::administration::baseline::Phase;
use rss_identity_core::account::{LoginKey, Password};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use serde::Deserialize;
use zeroize::Zeroize;

#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Progress {
    pub tenant_id: Uuid,
    pub administrator_id: Option<Uuid>,
    pub phase: Phase,
    pub blocked: Option<String>,
    pub entry_path: String,
}
impl Progress {
    pub(crate) fn pending(tenant_id: Uuid, administrator_id: Option<Uuid>) -> Self {
        Self {
            tenant_id,
            administrator_id,
            phase: Phase::Pending,
            blocked: None,
            entry_path: format!("/tenants/{tenant_id}"),
        }
    }
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Provision {
    name: String,
    administrator_login: String,
    administrator_password: String,
}
impl Drop for Provision {
    fn drop(&mut self) {
        self.administrator_password.zeroize();
    }
}
impl Service {
    pub(super) async fn provision(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        body: &Provision,
        cutoff: rss_request_context::Deadline,
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
        let (mut receipt, administrator_operation) = self
            .reserve_provisioning(proof, audit, operation, &body.name, &digest, cutoff)
            .await?;
        let ReceiptResult::Provisioning(progress) = &receipt.result else {
            return Err(Error::Conflict);
        };
        if progress.administrator_id.is_some() {
            return Ok(receipt);
        }
        let child_audit = audit.transaction_copy();
        proof.bind_audit(&child_audit)?;
        let result = self
            .create_administrator(
                proof,
                &child_audit,
                &progress.tenant_id.to_string(),
                administrator_operation,
                AdministratorInput {
                    login: login.as_str().into(),
                    password: body.administrator_password.clone(),
                },
                cutoff,
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
        let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
            return Err(Error::Conflict);
        };
        progress.administrator_id = Some(principal);
        Ok(receipt)
    }
    async fn reserve_provisioning(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        operation: Uuid,
        name: &str,
        digest: &str,
        cutoff: rss_request_context::Deadline,
    ) -> std::result::Result<(Receipt, Uuid), Error> {
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
            operation,
            "tenant_provision",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.require_final_request();
        let fact = Fact::business(
            audit,
            rss_mdm_audit_integration::operation::OperationOwner::TenantAdministration,
            &format!("tenant-provision:{operation}"),
            202,
            "success",
            None,
        )
        .map_err(|_| Error::Malformed)?;
        let budget = AuditBudget::until(cutoff);
        let attempt=self.audit.write(
            proof.binding(),&budget.source_control(),(self,proof,operation,name,digest,fact,audit),|(service,proof,operation,name,digest,fact,audit),tx|Box::pin(async move {
            let mut context=(&**service,*proof,*operation,*name,*digest);
            let (receipt,administrator_operation,replayed)=tx.with_connection_context(&mut context,|(service,proof,operation,name,digest),c|Box::pin(async move { async {
                sqlx::query("SELECT pg_advisory_xact_lock(2346)").execute(&mut *c).await.map_err(|_|Reason::Storage)?;
                service.authorize(c,proof,Permission::TenantCreate).await?;
                service.authorize(c,proof,Permission::TenantAdministratorCreate).await?;
                if let Some((mut receipt,request))=receipt_on(c,*operation).await? {
                    if receipt.action!=Action::Provision || request["fingerprint"].as_str()!=Some(*digest) {return Err(Reason::Conflict);}
                    let child=Uuid::parse_str(request["administratorOperationId"].as_str().ok_or(Reason::Storage)?).map_err(|_|Reason::Storage)?;
                    service.project_initialization(c, &mut receipt).await?;
                    return Ok((receipt,child,true));
                }
                let tenant=Uuid::new_v4();let administrator_operation=Uuid::new_v4();
                let tenant_text=tenant.to_string();
                let mutation=Mutation {installation:&service.installation,tenant_id:&tenant_text,operation_id:*operation,action:Action::Create,initial_epoch:Some(service.execution_epoch),expected_revision:None,name:Some(name),notes:None};
                insert_tenant_on(c,&mutation).await?;
                let receipt=Receipt {operation_id:*operation,action:Action::Provision,result:ReceiptResult::Provisioning(Progress::pending(tenant, None))};
                let actor=serde_json::json!({"kind":"session","tenantId":proof.tenant_id(),"instanceId":proof.instance_id(),"principalId":proof.principal_id()});
                let request=serde_json::json!({"fingerprint":digest,"administratorOperationId":administrator_operation});
                sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt,operator) VALUES($1,$2,'provision',$3,$4,$5)")
                    .bind(*operation).bind(tenant).bind(request).bind(serde_json::to_value(&receipt).map_err(|_|Reason::Storage)?).bind(actor)
                    .execute(&mut *c).await.map_err(|_|Reason::Storage)?;
                scope(c,proof.tenant_id()).await?;
                Ok::<_,Reason>((receipt,administrator_operation,false))
            }.await.map_err(project) })).await?;
            if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
            else {service.audit.append(tx, fact).await?;}
            audit.mark_commit_started();
            Ok::<_,Error>((receipt,administrator_operation))
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
}

impl Service {
    pub(super) async fn project_initialization(
        &self,
        c: &mut PgConnection,
        receipt: &mut Receipt,
    ) -> Result<()> {
        let ReceiptResult::Provisioning(progress) = &mut receipt.result else {
            return Ok(());
        };
        if progress.phase == Phase::Configured {
            return Ok(());
        }
        let child: Option<Uuid> = sqlx::query_scalar("SELECT (request->>'administratorOperationId')::uuid FROM public.mdm_tenant_operations WHERE operation_id=$1 AND action='provision'")
            .bind(receipt.operation_id).fetch_optional(&mut *c).await.map_err(|_|Reason::Storage)?;
        if let Some(child) = child
            && let Some((account, _)) = receipt_on(c, child).await?
        {
            let ReceiptResult::Administrator(account) = account.result else {
                return Err(Reason::Storage);
            };
            if account.tenant_id != progress.tenant_id.to_string() {
                return Err(Reason::Storage);
            }
            progress.administrator_id =
                Some(Uuid::parse_str(&account.principal_id).map_err(|_| Reason::Storage)?);
        }
        if progress.administrator_id.is_none() {
            return Ok(());
        }
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT phase,blocked FROM mdm_initialization.baselines WHERE tenant_id=$1",
        )
        .bind(progress.tenant_id)
        .fetch_optional(c)
        .await
        .map_err(|_| Reason::Storage)?;
        if let Some((phase, blocked)) = row {
            progress.phase = serde_json::from_value(serde_json::Value::String(phase))
                .map_err(|_| Reason::Storage)?;
            progress.blocked = blocked;
        }
        Ok(())
    }
    /// The original baseline owner calls this after all of its durable steps are configured.
    pub(crate) async fn complete_initialization(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> std::result::Result<(), Error> {
        self.source_runtime.local_tx(binding, crate::identity::deadline(), |tx| Box::pin(async move {
            tx.with_connection(|c| Box::pin(async move {
                sqlx::query("UPDATE public.mdm_tenant_operations o SET receipt=jsonb_set(jsonb_set(jsonb_set(o.receipt,'{result,phase}','\"configured\"'::jsonb),'{result,blocked}','null'::jsonb),'{result,administratorId}',a.receipt->'result'->'principalId') FROM public.mdm_tenant_operations a,mdm_initialization.baselines b WHERE o.tenant_id=$1::uuid AND o.action='provision' AND o.receipt->'result'->>'phase'<>'configured' AND a.operation_id=(o.request->>'administratorOperationId')::uuid AND a.action='administrator_create' AND a.tenant_id=o.tenant_id AND b.tenant_id=o.tenant_id AND b.phase='configured'")
                    .bind(binding.tenant().to_string()).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok, |e|Err(super::administrator::pg_error(e)), |e|Err(super::administrator::pg_error(e)), |_|Err(Error::RollbackFailed), |_|Err(Error::CommitUnknown), |e|Err(super::administrator::pg_error(e)))
    }
    /// Bounded discovery of existing initialization intents; no startup tenant list or scheduler.
    pub(crate) async fn pending_initializations(
        &self,
        after: Option<Uuid>,
    ) -> std::result::Result<Vec<Uuid>, Error> {
        sqlx::query_scalar("SELECT b.tenant_id FROM mdm_initialization.baselines b JOIN public.mdm_tenants t USING(tenant_id) WHERE NOT t.deleted AND ($1::uuid IS NULL OR b.tenant_id>$1) AND (b.phase<>'configured' OR EXISTS(SELECT FROM public.mdm_tenant_operations o WHERE o.tenant_id=b.tenant_id AND o.action='provision' AND o.receipt->'result'->>'phase'<>'configured')) ORDER BY b.tenant_id LIMIT 32")
            .bind(after).fetch_all(&self.pool).await.map_err(|_|Error::Unavailable(Failure::Database))
    }
}
