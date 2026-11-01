//! Authored Policy preview input and stable collection query contracts.
use serde::Deserialize;
/// A draft evaluated against an optional exact Scope result.
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    /// Complete desired Policy definition; preview does not publish it.
    #[serde(deserialize_with = "crate::definition_input")]
    pub definition: Box<crate::Definition>,
    /// Optional Scope publication identity required by the caller.
    pub scope_result: Option<uuid::Uuid>,
}
/// Stable query identity shared by every action's preview provider.
pub static PREVIEW_SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_previews",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
/// Stable query identity for Policy's complete-object assignment pages.
pub static ASSIGNMENTS_SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "policy_assignments",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};

/// Typed explanation of current admission for a Policy action.
#[derive(schemars::JsonSchema, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAdmissionState {
    /// Policy is paused.
    Paused,
    /// Native software delivery is disabled.
    MdmSoftwareDisabled,
    /// The current time is outside the execution window.
    OutsideWindow,
    /// The target is outside the current Scope.
    OutsideScope,
    /// Scope publication is not ready.
    ScopePending,
    /// The target is outside the active rollout stage.
    OutsideStage,
    /// The scheduled opening time has not arrived.
    Scheduled,
    /// The preceding rollout success threshold is unmet.
    SuccessGate,
    /// No qualifying registration exists.
    MissingRegistration,
    /// More than one registration matches.
    AmbiguousRegistration,
    /// The current channel lacks a required capability.
    UnsupportedCapability,
    /// No resource variant matches this platform.
    MissingVariant,
    /// The durable source authorization was withdrawn.
    AuthorizationWithdrawn,
    /// The required permission was withdrawn.
    PermissionWithdrawn,
    /// No current channel fact is available.
    ChannelUnknown,
    /// The required Inventory projection is pending.
    ProjectionPending,
    /// Current evidence already satisfies the desired state.
    AlreadySatisfied,
    /// The endpoint is enrolled in another organization.
    OrganizationConflict,
    /// Required native management rights are unavailable.
    MissingNativeRights,
    /// The endpoint architecture is unknown.
    MissingArchitecture,
    /// An installation is still in progress.
    InstallationPending,
    /// Recovery requires a current observation.
    RecoveryObservationPending,
    /// The installation recovery retry budget is exhausted.
    RecoveryRetryExhausted,
    /// The current target may be admitted.
    Eligible,
}
/// Admission explanation with an optional zero-based rollout stage.
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
pub struct TaskAdmission {
    state: TaskAdmissionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<usize>,
}
impl TaskAdmission {
    /// Bind the explanation to the stage evaluated by the business owner.
    pub fn new(state: TaskAdmissionState, stage: Option<usize>) -> Self {
        Self { state, stage }
    }
    /// Whether the business owner found the target eligible now.
    pub fn is_eligible(&self) -> bool {
        matches!(self.state, TaskAdmissionState::Eligible)
    }
}
