//! Independently assembled execution reads. No writer, outbox, recovery store or signing key.
use crate::*;
#[derive(Clone)]
pub struct Admission {
    pub(crate) software_distribution: crate::SoftwareDistribution,
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
}
pub struct Queries {
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) apple_results: Arc<dyn channels::AppleResults>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) inputs: Arc<Inputs>,
    pub(crate) admission: Admission,
    pub(crate) signed: bool,
    pub(crate) content_available: bool,
}
pub struct Dependencies {
    pub source: Arc<dyn source_authority::SourceAuthority>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_store: Arc<dyn channels::Agent>,
    pub apple_results: Arc<dyn channels::AppleResults>,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub inputs: Arc<Inputs>,
    pub signed: bool,
    pub content_available: bool,
}
impl Queries {
    pub fn new(dependencies: Dependencies) -> Self {
        let admission = Admission {
            software_distribution: dependencies.inputs.software_distribution,
            source: dependencies.source.clone(),
            software: dependencies.inputs.software.clone(),
            agent_store: dependencies.agent_store.clone(),
        };
        Self {
            admission,
            source: dependencies.source,
            protection: dependencies.protection,
            agent_store: dependencies.agent_store,
            apple_results: dependencies.apple_results,
            policy_reader: dependencies.policy_reader,
            runtime: dependencies.runtime,
            tenant: dependencies.tenant,
            inputs: dependencies.inputs,
            signed: dependencies.signed,
            content_available: dependencies.content_available,
        }
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
    ) -> std::result::Result<records::CommandDetail, QueryError> {
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, device, id, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, proof, device, id, audit) = *ctx;
                    storage::authorized(tx, proof, device, Permission::OperationRead).await?;
                    let op = storage::load(tx, &service.protection, id).await?;
                    if op.device != device {
                        return Err(Error::Forbidden.into());
                    }
                    let command = service.command_status(tx, &op).await?;
                    let now = storage::now(tx).await?;
                    let authorized = storage::authority_valid(
                        &service.source,
                        &service.protection,
                        tx,
                        &op,
                        now,
                    )
                    .await?;
                    let native_values = service.native_values_in(tx, proof, device, &op).await?;
                    let observation = protocol::observation(
                        tx,
                        &service.protection,
                        service.apple_results.clone(),
                        &op,
                        command,
                        native_values,
                    )
                    .await?;
                    let agent_installation = if op.authority.agent_package().is_some() {
                        Some(
                            super::native_installation::installation_observation(
                                tx,
                                service.apple_results.clone(),
                                service.agent_store.clone(),
                                &op,
                            )
                            .await?,
                        )
                    } else {
                        None
                    };
                    audit.require_final_request();
                    Ok(records::CommandDetail {
                        operation_id: op.id,
                        command_id: op.id,
                        revision: op.revision,
                        task: op.request.task.summary()?,
                        target: op.request.target,
                        input_version: op.request.input_version,
                        deadline: op.request.deadline,
                        dispatch_failure: op.dispatch_failure,
                        authorization: if authorized { "authorized" } else { "blocked" }.into(),
                        command_status: crate::service::status(command).into(),
                        observation,
                        agent_installation: agent_installation.map(records::decode).transpose()?,
                    })
                })
            },
        )
        .await
        .map_err(Into::into)
    }
}

use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
pub mod records;

mod error;
pub use error::{Missing, QueryError};

impl Queries {
    pub(crate) async fn native_values_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        op: &storage::Operation,
    ) -> Result<bool> {
        let snapshot = crate::action_admission::current(tx, proof).await?;
        self.native_values(&snapshot, proof, device, op)
    }
    pub(crate) fn native_values(
        &self,
        snapshot: &crate::authorization::Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        op: &storage::Operation,
    ) -> Result<bool> {
        let mut native_values = true;
        if !op.authority.control_matches(
            &op.request,
            op.registration,
            op.registration_generation,
        )? && matches!(
            op.request.task,
            Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command { .. }
                    | rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
            }
        ) {
            let mut required = op.request.task.permissions()?;
            required.extend_from_slice(op.authority.required());
            required.sort();
            required.dedup();
            if required.is_empty() {
                return Err(Error::Forbidden.into());
            }
            for permission in required {
                snapshot.require(proof, permission, permission.device().then_some(device))?;
            }
        }
        if op.request.profile_target().is_some() {
            let mut required = op.request.task.permissions()?;
            required.extend_from_slice(op.authority.required());
            required.push(Permission::InventoryCollect);
            required.sort();
            required.dedup();
            for permission in required {
                match snapshot.require(proof, permission, permission.device().then_some(device)) {
                    Ok(()) => {}
                    Err(crate::authorization::error::AuthorizationError::Forbidden) => {
                        native_values = false
                    }
                    Err(error) => return Err(Error::from(error).into()),
                }
            }
        }
        Ok(native_values)
    }
}
pub mod ddm;

mod lifecycle;
