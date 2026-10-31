//! Borrowed execution requests. No Policy identity, Scope, rollout or wire DTO.
use rss_mdm_policy::{
    Action, Frequency, SoftwareDelivery, SoftwareIntent, SoftwareResourceBinding,
    schedule::Schedule,
};
use uuid::Uuid;

/// Resource-only preflight input, usable by persistent and immediate callers.
#[derive(Clone, Copy)]
pub enum ResourcePreparation<'a> {
    Software {
        binding: &'a SoftwareResourceBinding,
    },
}
impl ResourcePreparation<'_> {
    pub(super) fn identity(&self) -> rss_mdm_policy::ResourceIdentity<'_> {
        match self {
            Self::Software { binding } => binding.identity(),
        }
    }
}

/// Material to freeze inside the caller's original transaction.
pub enum PublicationInput<'a> {
    DeviceAccess {
        mac: &'a Option<rss_mdm_agent_wire::platform_sso::LoginConfiguration>,
        windows: &'a rss_mdm_agent_wire::runtime::AccessWindowsConfiguration,
        self_enrollment: bool,
        role: Option<rss_mdm_policy::AccessRole>,
    },
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
            Self::Software { binding, .. } => ResourcePreparation::Software { binding },
            Self::DeviceAccess { .. }
            | Self::Unmanage { .. }
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
            Action::DeviceAccess {
                mac,
                windows,
                self_enrollment,
                role,
            } => Self::DeviceAccess {
                mac,
                windows,
                self_enrollment: *self_enrollment,
                role: *role,
            },
            Action::TelemetryProfile { .. } => {
                return Err(crate::Error::Unsupported);
            }
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
            Action::Execution { .. }
            | Action::AgentCollection { .. }
            | Action::NativeCollection { .. }
            | Action::Configuration { .. } => return Err(crate::Error::Unsupported),
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
    pub devices: Option<&'a std::collections::BTreeSet<String>>,
}
