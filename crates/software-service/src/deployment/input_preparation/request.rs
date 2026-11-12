//! Borrowed execution requests. No Policy identity, Scope, rollout or wire DTO.
use rss_mdm_policy::{
    Action, SoftwareDelivery, SoftwareIntent, SoftwareResourceBinding, schedule::Schedule,
};
use uuid::Uuid;

/// Material to freeze inside the caller's original transaction.
pub enum PublicationInput<'a> {
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
}
impl<'a> PublicationInput<'a> {
    /// The remaining resource-bound action is software.
    pub(super) fn resource(&self) -> Option<rss_mdm_policy::ResourceIdentity<'a>> {
        Some(match self {
            Self::Software { binding, .. } => binding.identity(),
            Self::AgentInstall { .. } => {
                return None;
            }
        })
    }
}
impl<'a> TryFrom<&'a Action> for PublicationInput<'a> {
    type Error = crate::deployment::Error;
    fn try_from(action: &'a Action) -> Result<Self, Self::Error> {
        Ok(match action {
            Action::TelemetryProfile { .. } => {
                return Err(crate::deployment::Error::Unsupported);
            }

            Action::Execution { .. }
            | Action::AgentCollection { .. }
            | Action::NativeCollection { .. }
            | Action::Configuration { .. } => return Err(crate::deployment::Error::Unsupported),
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

            _ => return Err(crate::deployment::Error::Unsupported),
        })
    }
}

/// Native grants are bound to the exact current authority and persisted owner identity.
pub struct PublicationAuthority<'a> {
    pub proof: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
    pub snapshot: &'a rss_mdm_authorization_service::Snapshot,
    pub devices: Option<&'a std::collections::BTreeSet<rss_mdm_agent_wire::DeviceId>>,
}
