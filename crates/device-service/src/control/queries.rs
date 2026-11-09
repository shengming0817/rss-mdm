//! Independently assembled execution reads. No writer, outbox, recovery store or signing key.
use crate::control::*;
mod snapshot;
pub use snapshot::Basis;

pub struct Queries {
    pub(crate) read_pool: sqlx::PgPool,
    clock: Arc<dyn rss_request_context::Clock>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) windows_results: Arc<dyn crate::control::windows_results::Store>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
}
pub struct Dependencies {
    pub read_pool: sqlx::PgPool,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub windows_results: Arc<dyn crate::control::windows_results::Store>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
}
impl Queries {
    pub fn new(clock: Arc<dyn rss_request_context::Clock>, dependencies: Dependencies) -> Self {
        Self {
            read_pool: dependencies.read_pool,
            clock,
            protection: dependencies.protection,
            windows_results: dependencies.windows_results,
            apple_results: dependencies.apple_results,
            runtime: dependencies.runtime,
            tenant: dependencies.tenant,
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

impl Queries {
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
    )]
    pub async fn read_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &authorization::Snapshot,
        now: i64,
        device: &str,
        id: Uuid,
        redacted: bool,
    ) -> crate::control::Result<records::CommandDetail> {
        grant.require(proof, Permission::OperationRead, Some(device))?;
        let service = self;
        let op = storage::load_on(c, service.tenant, &service.protection, id).await?;
        if op.device != device {
            return Err(Error::Forbidden.into());
        }

        let command = service.command_status_on(c, &op).await?;
        let operations = std::collections::BTreeMap::from([(op.id, op)]);
        let mut decisions = crate::control::authorization_decision::batch(
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
        let native_values = !redacted && service.native_values(grant, proof, device, &op)?;
        let observation = protocol::observation_on(
            c,
            service.tenant,
            service.windows_results.clone(),
            service.apple_results.clone(),
            &op,
            command,
            native_values,
        )
        .await?;
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
        })
    }
}

use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
pub mod records;

mod error;
pub use error::{Missing, QueryError};

impl Queries {
    pub(crate) fn native_values(
        &self,
        snapshot: &crate::control::authorization::Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        op: &storage::Operation,
    ) -> Result<bool> {
        let mut native_values = true;
        if !op.authority.control_matches(&op.request)?
            && matches!(
                op.request.task,
                Task::Macos {
                    request: rss_mdm_apple_mdm::native::request::Request::Command { .. }
                        | rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                }
            )
        {
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
                    Err(crate::control::authorization::error::AuthorizationError::Forbidden) => {
                        native_values = false
                    }
                    Err(error) => return Err(Error::from(error).into()),
                }
            }
        }
        Ok(native_values)
    }
}

impl Queries {
    pub async fn decisions_on(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        grant: &authorization::Snapshot,
        ids: Vec<Uuid>,
        now: i64,
    ) -> crate::control::Result<
        std::collections::BTreeMap<Uuid, crate::control::authorization_decision::Decision>,
    > {
        let operations = storage::load_many_on(c, self.tenant, &self.protection, ids).await?;
        let mut statuses = std::collections::BTreeMap::new();
        for op in operations.values() {
            statuses.insert(op.id, self.command_status_on(c, op).await?);
        }
        let decisions = crate::control::authorization_decision::batch(
            self,
            c,
            proof,
            grant,
            &operations,
            &statuses,
            now,
        )
        .await?;
        Ok(decisions)
    }
}
