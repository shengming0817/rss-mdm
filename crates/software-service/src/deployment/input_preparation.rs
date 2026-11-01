//! Execution-owned resource preparation inside the caller's original transaction.
use crate::deployment::frozen::FrozenSoftwareAction;
pub(crate) mod preview;
mod publication;
mod request;
mod software;
use crate::deployment::authorization::{Permission, context::AuthorizedPrincipal};
use crate::deployment::{Error, Inputs, action_contract::*, frozen::Published, transaction::*};
pub use request::{PublicationAuthority, PublicationInput};
use rss_mdm_policy::{Action, Platform, SoftwareIntent};
use rss_mdm_resource::{self as resource, self as r};
use rss_transactional_messaging_postgres::PgTransaction;

impl Inputs {
    /// Freeze and authorize immutable execution material, without committing or creating assignments.
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        authority: &PublicationAuthority<'_>,
    ) -> Result<Published> {
        self.validate_in(tx)?;
        authority
            .snapshot
            .require_all_devices(authority.proof, Permission::SoftwareDeploy)?;
        let frozen = match input {
            PublicationInput::AgentInstall {
                binding,
                schedule,
                lifetime,
            } => Published::AgentInstall {
                action: Box::new(
                    self.freeze_agent_in(
                        tx,
                        authority.proof,
                        authority.snapshot,
                        binding,
                        schedule,
                        *lifetime,
                    )
                    .await?,
                ),
            },

            _ => self.freeze_resource_in(tx, input).await?,
        };
        Ok(frozen)
    }
    pub(crate) async fn active_version_in(
        &self,
        tx: &mut PgTransaction<'_>,
        resource: &str,
        version: &str,
    ) -> Result<r::Version> {
        self.validate_in(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Conflict.into());
        }
        let (version, state) = checked(
            rss_mdm_resource_postgres::lock_reference_in(
                tx,
                &checked_input(r::Id::new(resource))?,
                &checked_input(r::Id::new(version))?,
            )
            .await?,
        )?;
        if (version.kind() == r::Kind::Software && state == r::State::Archived)
            || (version.kind() != r::Kind::Software && state != r::State::Active)
        {
            return Err(Error::Conflict.into());
        }
        Ok(version)
    }
}

/// Check the execution capabilities required by a prepared action.
pub fn authorize_action(
    snapshot: &crate::deployment::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::deployment::Error> {
    if matches!(action, Action::EnsureAgentInstalled { .. }) {
        snapshot.require_all_devices(proof, Permission::Enrollment)?;
    }
    snapshot.require_all_devices(proof, action_permission(action))?;
    Ok(())
}

impl Inputs {
    /// Resolve only backend-owned software lifecycle; caller retains Policy authorization and locks.
    pub async fn software_binding_in(
        &self,
        tx: &mut PgTransaction<'_>,
        action: &rss_mdm_policy::Action,
    ) -> Result<Option<[u8; 32]>> {
        self.validate_in(tx)?;
        if let rss_mdm_policy::Action::EnsureAgentInstalled { packages, .. } = action {
            let tenant = tx.tenant_id();
            let mut bindings = Vec::new();
            for (target, id) in packages {
                let id = *id;
                let package = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::agent_packages::resolve_in(c, tenant, id)
                                .await
                                .map_err(crate::deployment::agent_preparation::publication_error))
                        })
                    })
                    .await??;
                bindings.push((*target, id, package.digest, package.lifecycle));
            }
            return Ok(Some(
                crate::deployment::transaction::fingerprint(&bindings)?
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            ));
        }
        Ok(None)
    }
}

/// Primary operation permission shared by publication and targeted admission.
pub fn action_permission(action: &Action) -> Permission {
    match *action {
        Action::Credential { .. } => Permission::SecurityOperate,
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. }
        | Action::AgentCollection { .. }
        | Action::TelemetryProfile { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,
        Action::Software { .. } | Action::EnsureAgentInstalled { .. } => Permission::SoftwareDeploy,
        Action::RequestMdmEnrollment { .. } => Permission::Enrollment,
        Action::DeviceAccess { .. } => Permission::AccountWrite,
        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
    }
}
