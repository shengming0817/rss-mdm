//! Independently assembled execution reads. No writer, outbox, recovery store or signing key.
use crate::*;
#[derive(Clone)]
pub struct Admission {
    pub(crate) software_distribution: crate::SoftwareDistribution,
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
}
mod snapshot;

#[cfg(feature = "integration")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReadPhase {
    Facts,
    Authority,
}
#[cfg(feature = "integration")]
type ReadGate = (
    ReadPhase,
    tokio::sync::oneshot::Sender<()>,
    Arc<tokio::sync::Notify>,
);
pub struct Queries {
    #[cfg(feature = "integration")]
    read_gate: std::sync::Mutex<Option<ReadGate>>,
    pub(crate) read_pool: sqlx::PgPool,
    clock: Arc<dyn rss_request_context::Clock>,
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
    pub read_pool: sqlx::PgPool,
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
    pub fn new(clock: Arc<dyn rss_request_context::Clock>, dependencies: Dependencies) -> Self {
        let admission = Admission {
            software_distribution: dependencies.inputs.materials.software_distribution,
            source: dependencies.source.clone(),
            software: dependencies.inputs.materials.software.clone(),
            agent_store: dependencies.agent_store.clone(),
        };
        Self {
            #[cfg(feature = "integration")]
            read_gate: Default::default(),
            read_pool: dependencies.read_pool,
            clock,
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
    pub(crate) async fn command_status_on(
        &self,
        c: &mut sqlx::PgConnection,
        op: &storage::Operation,
    ) -> Result<dc::Status> {
        let status = sqlx::query_scalar::<_, String>("SELECT status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2")
            .bind(self.tenant.to_string()).bind(op.id.to_string()).fetch_optional(c).await?
            .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
        stored(dc::Status::restore(&status))
    }
}

pub mod assignments;
pub mod preview;
pub mod window;

impl Queries {
    pub async fn read(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        audit: &RequestAudit,
    ) -> std::result::Result<records::CommandDetail, QueryError> {
        self.snapshot(proof, (self, proof, device, id, audit), |ctx, c, basis| {
            Box::pin(async move {
                let (service, proof, device, id, audit) = *ctx;
                basis
                    .grant
                    .require(proof, Permission::OperationRead, Some(device))?;
                let op = storage::load_on(c, service.tenant, &service.protection, id).await?;
                if op.device != device {
                    return Err(Error::Forbidden.into());
                }
                #[cfg(feature = "integration")]
                service.read_checkpoint(ReadPhase::Facts).await?;
                let command = service.command_status_on(c, &op).await?;
                let now = basis.now;
                let grant = &basis.grant;
                let operations = std::collections::BTreeMap::from([(op.id, op)]);
                let mut decisions = crate::authorization_decision::batch(
                    service,
                    c,
                    proof,
                    grant,
                    &operations,
                    &std::collections::BTreeMap::from([(id, command)]),
                    now,
                )
                .await?;
                let decision = decisions.remove(&id).ok_or(Error::Conflict)?;
                let op = operations.into_values().next().ok_or(Error::Conflict)?;
                let native_values = service.native_values(grant, proof, device, &op)?;
                let observation = protocol::observation_on(
                    c,
                    service.tenant,
                    &service.protection,
                    service.apple_results.clone(),
                    &op,
                    command,
                    native_values,
                )
                .await?;
                let agent_installation = if op.authority.agent_package().is_some() {
                    Some(
                        super::native_installation::installation_observation_on(
                            c,
                            service.tenant,
                            service.apple_results.clone(),
                            service.agent_store.clone(),
                            &op,
                            false,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                proof.check_live()?;
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
                    authorization: decision.authorization,
                    reauthorization: decision.reauthorization,
                    command_status: records::CommandStatus(command),
                    observation,
                    agent_installation: agent_installation.map(records::decode).transpose()?,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}

use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
pub mod records;

mod error;
pub use error::{Missing, QueryError};

impl Queries {
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

#[cfg(feature = "integration")]
impl Queries {
    pub fn pause_read(
        &self,
        phase: ReadPhase,
    ) -> (tokio::sync::oneshot::Receiver<()>, Arc<tokio::sync::Notify>) {
        let (send, receive) = tokio::sync::oneshot::channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        assert!(
            self.read_gate
                .lock()
                .expect("read gate")
                .replace((phase, send, resume.clone()))
                .is_none()
        );
        (receive, resume)
    }
    pub(crate) async fn read_checkpoint(&self, phase: ReadPhase) -> std::result::Result<(), Error> {
        let gate = {
            let mut slot = self.read_gate.lock().expect("read gate");
            if slot.as_ref().is_some_and(|g| g.0 == phase) {
                slot.take()
            } else {
                None
            }
        };
        if let Some((_, send, resume)) = gate {
            let _ = send.send(());
            tokio::time::timeout(std::time::Duration::from_secs(5), resume.notified())
                .await
                .map_err(|_| Error::Unavailable(Failure::RequestDeadline))?;
        }
        Ok(())
    }
}
