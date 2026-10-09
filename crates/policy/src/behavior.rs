//! Assignment scheduling capabilities; resource applicability belongs to execution owners.
use serde::{Deserialize, Serialize};

/// Closed authored action identity, shared by persistence and query parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Agent script or collection.
    Execution,
    /// Native MDM collection.
    NativeCollection,
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
    /// Lazily admitted at Agent check-in.
    AgentCheckIn,
    /// Native reads driven by bounded collection recovery.
    NativeCollectionRecovery,
    /// Persistent native effects driven by Scope and assignment changes.
    NativeDesired,
}
impl ActionKind {
    /// Complete closed set for deriving database predicates.
    pub const ALL: [Self; 6] = [
        Self::Execution,
        Self::NativeCollection,
        Self::Configuration,
        Self::Software,
        Self::EnsureAgentInstalled,
        Self::RequestMdmEnrollment,
    ];
    /// Original endpoint channel selected by this action; no peer broadcast is permitted.
    pub const fn target_channel(self) -> &'static str {
        match self {
            Self::Execution | Self::Software | Self::RequestMdmEnrollment => "agent",
            Self::NativeCollection | Self::Configuration | Self::EnsureAgentInstalled => "mdm",
        }
    }
    /// Persisted discriminator.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::NativeCollection => "native_collection",
            Self::Configuration => "configuration",
            Self::Software => "software",
            Self::EnsureAgentInstalled => "ensure_agent_installed",
            Self::RequestMdmEnrollment => "request_mdm_enrollment",
        }
    }
    /// Select the existing assignment driver.
    pub const fn assignment_behavior(self) -> AssignmentBehavior {
        match self {
            Self::Execution | Self::Software | Self::RequestMdmEnrollment => {
                AssignmentBehavior::AgentCheckIn
            }
            Self::NativeCollection => AssignmentBehavior::NativeCollectionRecovery,
            Self::Configuration | Self::EnsureAgentInstalled => AssignmentBehavior::NativeDesired,
        }
    }
    /// Whether the existing Agent execution path consumes explicit Policy triggers.
    pub const fn supports_rerun(self) -> bool {
        matches!(self, Self::Execution | Self::RequestMdmEnrollment)
    }
}
impl AssignmentBehavior {
    /// Derive SQL discriminator parameters from the canonical behavior mapping.
    pub fn kinds(self) -> Vec<&'static str> {
        ActionKind::ALL
            .into_iter()
            .filter(|kind| kind.assignment_behavior() == self)
            .map(ActionKind::as_str)
            .collect()
    }
}
