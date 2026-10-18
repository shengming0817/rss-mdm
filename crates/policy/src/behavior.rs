//! Assignment scheduling capabilities; resource applicability belongs to execution owners.
use serde::{Deserialize, Serialize};

/// Closed authored action identity, shared by persistence and query parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Server-owned retirement of all managed channels.
    UnmanageDevice,
    /// Native recovery material management.
    Credential,
    /// Agent script or collection.
    Execution,
    /// Native MDM collection.
    NativeCollection,
    /// Declarative native reads over the Agent channel.
    AgentCollection,
    /// Persistent native configuration.
    Configuration,
    /// Software assignment.
    Software,
    /// Approved Agent installation from MDM.
    EnsureAgentInstalled,
    /// Standard enrollment entry requested through Agent.
    RequestMdmEnrollment,
}
/// Assignment driver selection, never a device authorization or capability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentBehavior {
    /// Server-owned execution independent of endpoint connectivity.
    DeviceLifecycle,
    /// Lazily admitted at Agent check-in.
    AgentCheckIn,
    /// Native reads driven by bounded collection recovery.
    NativeCollectionRecovery,
    /// Persistent native effects driven by Scope and assignment changes.
    NativeDesired,
}
impl ActionKind {
    /// Complete closed set for deriving database predicates.
    pub const ALL: [Self; 9] = [
        Self::UnmanageDevice,
        Self::Credential,
        Self::Execution,
        Self::NativeCollection,
        Self::AgentCollection,
        Self::Configuration,
        Self::Software,
        Self::EnsureAgentInstalled,
        Self::RequestMdmEnrollment,
    ];
    /// Persisted discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnmanageDevice => "unmanage_device",
            Self::Credential => "credential",
            Self::Execution => "execution",
            Self::NativeCollection => "native_collection",
            Self::AgentCollection => "agent_collection",
            Self::Configuration => "configuration",
            Self::Software => "software",
            Self::EnsureAgentInstalled => "ensure_agent_installed",
            Self::RequestMdmEnrollment => "request_mdm_enrollment",
        }
    }
    /// Whether the existing Agent execution path consumes explicit Policy triggers.
    pub const fn supports_rerun(self) -> bool {
        matches!(
            self,
            Self::UnmanageDevice
                | Self::Credential
                | Self::AgentCollection
                | Self::Execution
                | Self::RequestMdmEnrollment
        )
    }
}
impl crate::Action {
    /// Select exactly one write channel from the complete authored action.
    pub const fn target_channel(&self) -> Option<SoftwareChannel> {
        use crate::Action;
        match self {
            Action::UnmanageDevice { .. } => None,
            Action::Software { channel, .. } => Some(*channel),
            Action::NativeCollection { .. }
            | Action::Configuration { .. }
            | Action::EnsureAgentInstalled { .. } => Some(SoftwareChannel::Mdm),
            _ => Some(SoftwareChannel::Agent),
        }
    }
    /// Select the existing driver using the complete authored input.
    pub const fn assignment_behavior(&self) -> AssignmentBehavior {
        match self {
            crate::Action::UnmanageDevice { .. } => AssignmentBehavior::DeviceLifecycle,
            crate::Action::NativeCollection { .. } => AssignmentBehavior::NativeCollectionRecovery,
            _ if matches!(self.target_channel(), Some(SoftwareChannel::Mdm)) => {
                AssignmentBehavior::NativeDesired
            }
            _ => AssignmentBehavior::AgentCheckIn,
        }
    }
}
/// A software assignment has one write channel; there is no automatic fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareChannel {
    /// Existing Agent task execution.
    Agent,
    /// Native MDM package execution.
    Mdm,
}
impl SoftwareChannel {
    /// Canonical persisted discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Mdm => "mdm",
        }
    }
}
impl AssignmentBehavior {
    /// Fixed-channel kinds. Software additionally requires its authored channel predicate.
    pub fn kinds(self) -> Vec<&'static str> {
        match self {
            Self::DeviceLifecycle => vec!["unmanage_device"],
            Self::AgentCheckIn => vec![
                "credential",
                "agent_collection",
                "execution",
                "request_mdm_enrollment",
            ],
            Self::NativeCollectionRecovery => vec!["native_collection"],
            Self::NativeDesired => vec!["configuration", "ensure_agent_installed"],
        }
    }
}
