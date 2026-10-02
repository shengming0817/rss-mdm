//! Independently assembled execution reads. No writer, outbox, recovery store or signing key.
use crate::*;
use rss_mdm_policy::Action;
use serde_json::json;
#[derive(Clone)]
pub struct Admission {
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) agent_installation: crate::agent_install::Config,
}
pub struct Queries {
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) apple_store: Arc<dyn channels::AppleStore>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) inputs: Arc<Inputs>,
    pub(crate) admission: Admission,
    pub(crate) signed: bool,
    pub(crate) content_available: bool,
}
impl ExecutionService {
    pub(crate) fn admission(&self) -> Admission {
        Admission {
            source: self.source.clone(),
            software: self.software.clone(),
            agent_store: self.agent_store.clone(),
            agent_installation: self.agent_installation.clone(),
        }
    }
    pub fn queries(&self) -> Arc<Queries> {
        Arc::new(Queries {
            source: self.source.clone(),
            protection: self.protection.clone(),
            agent_store: self.agent_store.clone(),
            apple_store: self.apple_store.clone(),
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                self.runtime.clone(),
                self.tenant,
            ),
            audit_store: self.audit_store.clone(),
            runtime: self.runtime.clone(),
            tenant: self.tenant,
            inputs: self.inputs(),
            admission: self.admission(),
            signed: self.signer.is_some(),
            content_available: self.content.is_some(),
        })
    }
}
impl Queries {
    pub(crate) async fn command_status(
        &self,
        tx: &mut PgTransaction<'_>,
        op: &storage::Operation,
    ) -> Result<dc::Status> {
        let tenant = tx.tenant_id().to_string();
        let id = op.id.to_string();
        let status=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(tenant).bind(id).fetch_optional(c).await
        })).await?.ok_or(Error::Unavailable(Failure::CommandInvariant))?;
        stored(dc::Status::restore(&status))
    }
}
pub mod assignments;
pub mod preview;

impl Queries {
    pub async fn read(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<records::CommandDetail, Error> {
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,device,id,audit),|ctx,tx|Box::pin(async move {
            let (service,proof,device,id,audit) = *ctx;
            storage::authorized(tx,proof,device,Permission::OperationRead).await?;
            let op=storage::load(tx,&service.protection,id).await?;
            if op.device!=device{return Err(Error::Forbidden.into());}
            let command=service.command_status(tx,&op).await?;
            let now=storage::now(tx).await?;let approved=storage::approval_valid(&service.source, &service.protection,tx,&op,now).await?;
            let observation=protocol::observation(tx,&service.protection,service.apple_store.clone(),&op,command).await?;
            let agent_installation=if op.approval.agent_package().is_some(){Some(super::native_installation::installation_observation(tx,service.apple_store.clone(),service.agent_store.clone(),&op).await?)}else{None};
            service.audit_store.append_request_in(tx,audit,200,"success").await?;
            records::decode(json!({"operationId":op.id,"commandId":op.id,"revision":op.revision,"task":op.request.task.summary()?,"target":op.request.target,"inputVersion":op.request.input_version,"deadline":op.request.deadline,"dispatchFailure":op.dispatch_failure,"authorization":if approved{"approved"}else{"blocked"},"commandStatus":crate::service::status(command),"observation":observation,"agentInstallation":agent_installation}))
        }),crate::transaction::TransactionOwner::Execution).await
    }
}

use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy::Definition;
pub fn authorize_snapshot(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    definition: &Definition,
) -> std::result::Result<(), crate::Error> {
    let permission = match definition.action {
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
    };
    if matches!(definition.action, Action::EnsureAgentInstalled { .. }) {
        snapshot.require_all_devices(proof, Permission::Enrollment)?;
    }
    snapshot.require(proof, Permission::ScopeRead, None)?;
    snapshot.require_all_devices(proof, permission)?;
    Ok(())
}
pub mod records;
