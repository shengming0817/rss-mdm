//! Borrowed execution requests. No Policy identity, Scope, rollout or wire DTO.
use rss_mdm_policy::{
    Action, ExactResourceBinding, Exit, Frequency, SoftwareDelivery, SoftwareIntent,
    SoftwareResourceBinding, schedule::Schedule,
};
use serde_json::Value;
use uuid::Uuid;

/// Publication sources differ from already complete immediate-call values.
#[derive(Clone, Copy)]
pub enum ScriptParameters<'a> {
    Sources(&'a rss_mdm_policy::ParameterSources),
    Values(&'a Value),
}
impl ScriptParameters<'_> {
    pub(super) fn checked(
        self,
        definition: &rss_mdm_resource::ScriptDefinition,
    ) -> crate::transaction::Result<rss_mdm_policy::ParameterSources> {
        use rss_mdm_policy::{ParameterSource, ParameterSources};
        let sources = match self {
            Self::Sources(sources) => sources.clone(),
            Self::Values(values) => {
                definition
                    .validate_parameters(values)
                    .map_err(|_| crate::Error::Malformed)?;
                ParameterSources(
                    values
                        .as_object()
                        .ok_or(crate::Error::Malformed)?
                        .iter()
                        .map(|(k, v)| (k.clone(), ParameterSource::Fixed { value: v.clone() }))
                        .collect(),
                )
            }
        };
        sources.validate()?;
        let properties = definition
            .spec()
            .parameters
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(crate::Error::Malformed)?;
        if sources.0.len() != properties.len()
            || sources.0.keys().any(|k| !properties.contains_key(k))
        {
            return Err(crate::Error::Malformed.into());
        }
        definition
            .validate_fixed_parameters(&sources.fixed_values())
            .map_err(|_| crate::Error::Malformed)?;
        Ok(sources)
    }
}
/// Resource-only preflight input, usable by persistent and immediate callers.
#[derive(Clone, Copy)]
pub enum ResourcePreparation<'a> {
    Script {
        binding: &'a ExactResourceBinding,
        parameters: ScriptParameters<'a>,
    },
    AgentCollection {
        binding: &'a ExactResourceBinding,
    },
    NativeCollection {
        binding: &'a ExactResourceBinding,
    },
    Configuration {
        binding: &'a ExactResourceBinding,
    },
    Software {
        binding: &'a SoftwareResourceBinding,
    },
}
impl ResourcePreparation<'_> {
    pub(super) fn identity(&self) -> rss_mdm_policy::ResourceIdentity<'_> {
        match self {
            Self::Script { binding, .. }
            | Self::AgentCollection { binding }
            | Self::NativeCollection { binding }
            | Self::Configuration { binding } => binding.identity(),
            Self::Software { binding } => binding.identity(),
        }
    }
}

/// Material to freeze inside the caller's original transaction.
pub enum PublicationInput<'a> {
    Unmanage {
        schedule: &'a Schedule,
        lifetime: u32,
    },
    Credential {
        operation: &'a rss_mdm_policy::CredentialOperation,
        architecture: rss_mdm_policy::Architecture,
        schedule: &'a Schedule,
        frequency: Frequency,
        lifetime: u32,
    },
    Script {
        binding: &'a ExactResourceBinding,
        parameters: ScriptParameters<'a>,
        schedule: &'a Schedule,
        frequency: Frequency,
        lifetime: u32,
    },
    AgentCollection {
        binding: &'a ExactResourceBinding,
        schedule: &'a Schedule,
        frequency: Frequency,
        lifetime: u32,
    },
    NativeCollection {
        binding: &'a ExactResourceBinding,
        schedule: &'a Schedule,
        frequency: Frequency,
        lifetime: u32,
    },
    Configuration {
        binding: &'a ExactResourceBinding,
        exit: Exit,
    },
    Software {
        channel: rss_mdm_policy::SoftwareChannel,
        binding: &'a SoftwareResourceBinding,
        delivery: &'a SoftwareDelivery,
        intent: SoftwareIntent,
        schedule: &'a Schedule,
        lifetime: u32,
    },
    AgentInstall {
        binding: &'a std::collections::BTreeMap<rss_mdm_policy::SoftwareTarget, Uuid>,
        schedule: &'a Schedule,
        lifetime: u32,
    },
    Enrollment {
        organization: Uuid,
        schedule: &'a Schedule,
        lifetime: u32,
    },
}
impl<'a> PublicationInput<'a> {
    /// Resource preflight input; enrollment has no resource.
    pub fn resource(&self) -> Option<ResourcePreparation<'a>> {
        Some(match self {
            Self::Script {
                binding,
                parameters,
                ..
            } => ResourcePreparation::Script {
                binding,
                parameters: *parameters,
            },
            Self::AgentCollection { binding, .. } => {
                ResourcePreparation::AgentCollection { binding }
            }
            Self::NativeCollection { binding, .. } => {
                ResourcePreparation::NativeCollection { binding }
            }
            Self::Configuration { binding, .. } => ResourcePreparation::Configuration { binding },
            Self::Software { binding, .. } => ResourcePreparation::Software { binding },
            Self::Unmanage { .. }
            | Self::Credential { .. }
            | Self::Enrollment { .. }
            | Self::AgentInstall { .. } => {
                return None;
            }
        })
    }
}
impl<'a> TryFrom<&'a Action> for PublicationInput<'a> {
    type Error = crate::Error;
    fn try_from(action: &'a Action) -> Result<Self, Self::Error> {
        Ok(match action {
            Action::TelemetryProfile { .. } => return Err(crate::Error::Unsupported),
            Action::UnmanageDevice {
                schedule,
                run_lifetime_seconds,
            } => Self::Unmanage {
                schedule,
                lifetime: *run_lifetime_seconds,
            },
            Action::Credential {
                operation,
                architecture,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => Self::Credential {
                operation,
                architecture: *architecture,
                schedule,
                frequency: *frequency,
                lifetime: *run_lifetime_seconds,
            },
            Action::Execution {
                resource,
                parameters,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => Self::Script {
                binding: resource,
                parameters: ScriptParameters::Sources(parameters),
                schedule,
                frequency: *frequency,
                lifetime: *run_lifetime_seconds,
            },
            Action::AgentCollection {
                resource,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => Self::AgentCollection {
                binding: resource,
                schedule,
                frequency: *frequency,
                lifetime: *run_lifetime_seconds,
            },
            Action::NativeCollection {
                resource,
                schedule,
                frequency,
                run_lifetime_seconds,
            } => Self::NativeCollection {
                binding: resource,
                schedule,
                frequency: *frequency,
                lifetime: *run_lifetime_seconds,
            },
            Action::Configuration { resource, exit } => Self::Configuration {
                binding: resource,
                exit: *exit,
            },
            Action::Software {
                channel,
                resource,
                delivery,
                intent,
                schedule,
                run_lifetime_seconds,
                ..
            } => Self::Software {
                channel: *channel,
                binding: resource,
                delivery,
                intent: *intent,
                schedule,
                lifetime: *run_lifetime_seconds,
            },
            Action::EnsureAgentInstalled {
                packages,
                schedule,
                run_lifetime_seconds,
            } => Self::AgentInstall {
                binding: packages,
                schedule,
                lifetime: *run_lifetime_seconds,
            },
            Action::RequestMdmEnrollment {
                organization,
                schedule,
                run_lifetime_seconds,
            } => Self::Enrollment {
                organization: *organization,
                schedule,
                lifetime: *run_lifetime_seconds,
            },
        })
    }
}

/// Native grants are bound to the exact current authority and persisted owner identity.
pub struct PublicationAuthority<'a> {
    pub proof: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
    pub snapshot: &'a rss_mdm_authorization_service::Snapshot,
    pub owner: crate::configuration::Owner,
    pub devices: Option<&'a std::collections::BTreeSet<String>>,
}
