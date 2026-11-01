//! Execution-owned resource preparation inside the caller's original transaction.
pub(crate) mod preview;
mod request;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use crate::{Error, Inputs, action_contract::*, frozen::Frozen, transaction::*};
pub use request::{PublicationAuthority, PublicationInput};
use rss_mdm_policy::Action;
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
        };
        frozen.authorize_native(authority.proof, authority.snapshot, authority.devices)?;
        Ok(frozen)
    }
}

/// Check the execution capabilities required by a prepared action.
pub fn authorize_action(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::Error> {
    snapshot.require_all_devices(proof, action_permission(action)?)?;
    Ok(())
}

impl Inputs {}

/// Primary operation permission shared by publication and targeted admission.
pub fn action_permission(action: &Action) -> std::result::Result<Permission, Error> {
    Ok(match *action {
        Action::Credential { ref operation, .. } => crate::credential_tasks::permission(operation),
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. }
        | Action::AgentCollection { .. }
        | Action::TelemetryProfile { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,

        Action::DeviceAccess { .. } => Permission::AccountWrite,
        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
        _ => return Err(Error::Unsupported),
    })
}
