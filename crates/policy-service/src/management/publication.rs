//! Freeze the changed version in the Policy writer's transaction.
use super::*;
use rss_mdm_authorization_service::Snapshot;
use rss_mdm_software_service::deployment::input_preparation::PublicationInput;

impl Policies {
    pub(super) async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &Policy,
        verified: Option<&rss_mdm_content_service::Verified>,
        proof: &AuthorizedPrincipal,
        snapshot: &Snapshot,
    ) -> Result<Value> {
        let action = &policy.definition.action;
        let frozen = match action {
            Action::Software { .. } | Action::EnsureAgentInstalled { .. } => {
                let input = PublicationInput::try_from(action).map_err(Error::from)?;
                let frozen = self
                    .software
                    .publish_in(tx, &input, proof, snapshot)
                    .await?;
                return serde_json::to_value(frozen)
                    .map_err(|_| Error::Unavailable(crate::Failure::PreparationContract).into());
            }
            Action::RequestMdmEnrollment {
                organization,
                schedule,
                run_lifetime_seconds,
            } => {
                let frozen = rss_mdm_registration_service::enrollment::tasks::policy::publish(
                    &self.enrollment_entries,
                    proof,
                    snapshot,
                    *organization,
                    schedule,
                    *run_lifetime_seconds,
                    policy.definition.self_service.as_ref(),
                )
                .map_err(Error::from)?;
                return serde_json::to_value(frozen)
                    .map_err(|_| Error::Unavailable(crate::Failure::PreparationContract).into());
            }
            Action::TelemetryProfile { resource } => serde_json::to_value(
                telemetry::freeze(
                    self.profile(),
                    tx,
                    resource,
                    proof,
                    snapshot,
                    self.profile_validator.as_ref(),
                    policy.id,
                    policy.version,
                )
                .await?,
            ),
            Action::Configuration { resource, exit } => serde_json::to_value(
                self.configuration
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .freeze_in(
                        tx,
                        crate::configuration::publication::Publication {
                            policy: policy.id,
                            version: policy.version,
                            binding: resource,
                            exit: *exit,
                        },
                        verified,
                        proof,
                        snapshot,
                    )
                    .await?,
            ),
            Action::UnmanageDevice {
                schedule,
                run_lifetime_seconds,
            } => serde_json::to_value(
                rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice {
                    schedule: schedule.clone(),
                    run_lifetime_seconds: *run_lifetime_seconds,
                    actor: proof.actor(),
                },
            ),
            Action::DeviceAccess {
                mac,
                windows,
                self_enrollment,
                role,
            } => {
                use rss_mdm_agent_wire::runtime::{AccessConfiguration, AccessRole};
                let configuration = AccessConfiguration {
                    mac: mac.clone(),
                    windows: windows.clone(),
                    self_enrollment: *self_enrollment,
                    enabled: true,
                    role: role.map(|r| match r {
                        rss_mdm_policy::AccessRole::Standard => AccessRole::Standard,
                        rss_mdm_policy::AccessRole::Administrator => AccessRole::Administrator,
                    }),
                };
                configuration.validate().map_err(|_| Error::Malformed)?;
                return Ok(json!({"kind":"device_access","configuration":configuration}));
            }
            Action::Credential {
                operation,
                architecture,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => serde_json::to_value(
                self.credentials
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .publish_in(
                        tx,
                        &rss_mdm_recovery_credentials::tasks::publication::Publication {
                            operation,
                            architecture: *architecture,
                            schedule,
                            frequency: *frequency,
                            lifetime: *run_lifetime_seconds,
                        },
                        proof,
                        snapshot,
                    )?,
            ),
            Action::Execution {
                resource,
                parameters,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => serde_json::to_value(
                self.script
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .publish_in(
                        tx,
                        &rss_mdm_script_service::inputs::Publication {
                            binding: resource,
                            parameters: rss_mdm_script_service::Parameters::Sources(parameters),
                            schedule,
                            frequency: *frequency,
                            lifetime: *run_lifetime_seconds,
                        },
                        verified.ok_or(Error::Conflict)?,
                        proof,
                        snapshot,
                    )
                    .await?,
            ),
            Action::AgentCollection {
                resource,
                schedule,
                frequency,
                run_lifetime_seconds,
            }
            | Action::NativeCollection {
                resource,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => serde_json::to_value(
                self.collections
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .publish_in(
                        tx,
                        &rss_mdm_inventory_service::collection::execution::inputs::Publication {
                            channel: if matches!(action, Action::AgentCollection { .. }) {
                                rss_mdm_inventory::Channel::Agent
                            } else {
                                rss_mdm_inventory::Channel::Mdm
                            },
                            binding: resource,
                            schedule,
                            frequency: *frequency,
                            lifetime: *run_lifetime_seconds,
                        },
                        verified.ok_or(Error::Conflict)?,
                        proof,
                        snapshot,
                    )
                    .await?,
            ),
        };
        checked_input(frozen)
    }
}
