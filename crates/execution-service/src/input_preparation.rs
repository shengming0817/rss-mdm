//! Execution-owned resource preparation inside the caller's original transaction.
pub(crate) mod preview;
mod publication;
mod request;
mod software;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, action_contract::*, frozen::Frozen, transaction::*};
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
    ) -> Result<Frozen> {
        self.validate_in(tx)?;
        let mut frozen = match input {
            PublicationInput::DeviceAccess {
                mac,
                windows,
                self_enrollment,
                role,
            } => {
                if !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                authority
                    .snapshot
                    .require_all_devices(authority.proof, Permission::AccountWrite)?;
                let frozen = Frozen::DeviceAccess {
                    configuration: rss_mdm_agent_wire::runtime::AccessConfiguration {
                        mac: (*mac).clone(),
                        windows: (*windows).clone(),
                        self_enrollment: *self_enrollment,
                        enabled: true,
                        role: role.map(|r| match r {
                            rss_mdm_policy::AccessRole::Standard => {
                                rss_mdm_agent_wire::runtime::AccessRole::Standard
                            }
                            rss_mdm_policy::AccessRole::Administrator => {
                                rss_mdm_agent_wire::runtime::AccessRole::Administrator
                            }
                        }),
                    },
                };
                if let Frozen::DeviceAccess { configuration, .. } = &frozen {
                    configuration.validate().map_err(|_| Error::Malformed)?;
                }
                frozen
            }
            PublicationInput::Unmanage { schedule, lifetime } => {
                authority
                    .snapshot
                    .require_all_devices(authority.proof, Permission::DeviceUnmanage)?;
                Frozen::UnmanageDevice {
                    schedule: (*schedule).clone(),
                    run_lifetime_seconds: *lifetime,
                    actor: authority.proof.actor(),
                }
            }
            PublicationInput::Credential {
                operation,
                architecture,
                schedule,
                frequency,
                lifetime,
            } => {
                if !self.materials.recovery_enabled || !self.materials.signing_enabled {
                    return Err(Error::Unsupported.into());
                }
                Frozen::Credential {
                    frequency: *frequency,
                    action: Box::new(crate::credential_tasks::FrozenCredential {
                        operation: (*operation).clone(),
                        input: ExecutionInput {
                            platform: Platform::Windows,
                            architecture: *architecture,
                            schedule: (*schedule).clone(),
                            run_lifetime_seconds: *lifetime,
                        },
                    }),
                }
            }
            PublicationInput::AgentInstall {
                binding,
                schedule,
                lifetime,
            } => Frozen::AgentInstall {
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
            PublicationInput::Enrollment {
                organization,
                schedule,
                lifetime,
            } => Frozen::MdmEnrollment {
                action: Box::new(self.prepare_enrollment(
                    authority.proof,
                    authority.snapshot,
                    *organization,
                    schedule,
                    *lifetime,
                )?),
            },
            _ => self.freeze_resource_in(tx, input).await?,
        };
        frozen.authorize_native(authority.proof, authority.snapshot, authority.devices)?;
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
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::Error> {
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
                            Ok(
                                rss_mdm_software_service::agent_packages::resolve_in(c, tenant, id)
                                    .await
                                    .map_err(crate::agent_preparation::publication_error),
                            )
                        })
                    })
                    .await??;
                bindings.push((*target, id, package.digest, package.lifecycle));
            }
            return Ok(Some(
                crate::transaction::fingerprint(&bindings)?
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
        Action::Credential { ref operation, .. } => crate::credential_tasks::permission(operation),
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
