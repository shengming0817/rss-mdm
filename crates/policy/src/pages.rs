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
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
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
    /// A new authenticated Agent check-in is required; this is not a start promise.
    WaitingCheckIn,
    /// No eligible manual/custom trigger has been persisted.
    WaitingTrigger,
    /// The owner has not reached the minimum interval since its recorded reference time.
    IntervalNotElapsed,
    /// The original run must settle before another normal occurrence is admitted.
    ExecutionPending,
    /// The current version/entry/trigger identity has already been consumed.
    FrequencyConsumed,
    /// An earlier execution may have had an effect; automatic repetition remains blocked.
    EffectUnknown,
    /// The existing per-device capacity boundary is currently full.
    CapacityBusy,
    /// The configured scheduling lifetime has ended.
    ScheduleEnded,
    /// An invocation requires explicit input and cannot be admitted by a periodic poll.
    InputRequired,
    /// The current lifecycle does not permit new work.
    LifecycleBlocked,
    /// The collection report source is not enabled for the current registration.
    ReportSourceUnavailable,
    /// The current target may be admitted.
    Eligible,
}
/// Admission explanation with an optional zero-based rollout stage.
#[derive(schemars::JsonSchema, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskAdmission {
    state: TaskAdmissionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<usize>,
    /// Proven lower bound only; absence means that no start time can be promised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_allowed_start_at: Option<i64>,
}
impl TaskAdmission {
    /// Bind the explanation to the stage evaluated by the business owner.
    pub fn new(state: TaskAdmissionState, stage: Option<usize>) -> Self {
        Self {
            state,
            stage,
            next_allowed_start_at: None,
        }
    }
    /// Whether the business owner found the target eligible now.
    pub fn is_eligible(&self) -> bool {
        matches!(self.state, TaskAdmissionState::Eligible)
    }
    /// State evaluated by the business owner in the current fact snapshot.
    pub fn state(&self) -> TaskAdmissionState {
        self.state
    }
    /// Attach an owner-proven time lower bound without predicting a device event.
    pub fn not_before(mut self, at: Option<i64>) -> Self {
        self.next_allowed_start_at = at;
        self
    }
}

/// Evidence about one real current trigger identity, independent of historical results.
#[derive(schemars::JsonSchema, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CurrentRecord {
    /// No current trigger identity is known; no absence claim can be made.
    Unknown,
    /// The exact current trigger identity was checked and has no accepted run.
    Absent,
    /// The original accepted run for that exact identity.
    Present {
        /// Original task identity owned by the current Policy.
        task_id: uuid::Uuid,
    },
}
