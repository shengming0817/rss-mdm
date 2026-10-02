//! Typed read facts. Summary results cannot expose full output or diagnostic streams.
use crate::actions::state::RunState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionKind {
    Command,
    ActionRun,
}
impl ExecutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::ActionRun => "action_run",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionCursor {
    pub id: Uuid,
    pub kind: ExecutionKind,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T, C> {
    pub items: Vec<T>,
    pub next_cursor: Option<C>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory<T, C, S> {
    pub items: Vec<T>,
    pub next_cursor: Option<C>,
    pub statistics: S,
    pub as_of: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionStatistics {
    total: u64,
    commands: u64,
    action_runs: u64,
    unknown: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Direct,
    Policy,
    RemoteOperation,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionSummary {
    pub id: Uuid,
    pub kind: ExecutionKind,
    pub device: String,
    registration_id: Uuid,
    generation: i64,
    origin: Origin,
    pub policy: Option<Uuid>,
    pub remote_operation: Option<Uuid>,
    deadline: i64,
    status: String,
    evidence: ExecutionEvidence,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum ExecutionEvidence {
    Command(Box<CommandEvidence>),
    Run(RunEvidence),
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommandEvidence {
    command_status: String,
    observation: NativeObservation,
    dispatch_failure: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_installation: Option<InstallationObservation>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunEvidence {
    state: RunState,
    effect: String,
    result: Option<SummaryResult>,
}
pub type ExecutionDirectory = Directory<ExecutionSummary, ExecutionCursor, ExecutionStatistics>;

#[derive(Serialize)]
#[serde(transparent)]
pub struct SummaryResult(Value);
impl<'de> Deserialize<'de> for SummaryResult {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut value = Value::deserialize(d)?;
        fn strip(v: &mut Value) {
            match v {
                Value::Object(fields) => {
                    fields.remove("output");
                    fields.remove("stdout");
                    fields.remove("stderr");
                    for v in fields.values_mut() {
                        strip(v);
                    }
                }
                Value::Array(items) => {
                    for v in items {
                        strip(v);
                    }
                }
                _ => (),
            }
        }
        strip(&mut value);
        Ok(Self(value))
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    task_id: Uuid,
    device: String,
    registration_id: Uuid,
    generation: i64,
    occurrence: String,
    available_at: i64,
    deadline: i64,
    state: RunState,
    effect: String,
    user_action: Option<String>,
    result: Option<SummaryResult>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunCursor {
    available_at: i64,
    task_id: Uuid,
}
pub type RunPage = Page<RunSummary, RunCursor>;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetail {
    task_id: Uuid,
    device: String,
    registration_id: Uuid,
    generation: i64,
    available_at: i64,
    deadline: i64,
    state: RunState,
    effect: String,
    user_action: Option<String>,
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<Uuid>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandDetail {
    operation_id: Uuid,
    command_id: Uuid,
    revision: i64,
    task: Value,
    target: crate::NativeTarget,
    input_version: String,
    deadline: i64,
    dispatch_failure: Option<Value>,
    authorization: String,
    command_status: String,
    observation: NativeObservation,
    agent_installation: Option<InstallationObservation>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeObservation {
    protocol: String,
    observation_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipts: Option<Vec<NativeReceipt>>,
    progress: String,
    effect: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    effect_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received_at: Option<i64>,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum NativeReceipt {
    Windows(WindowsReceipt),
    Apple(AppleReceipt),
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowsReceipt {
    phase: crate::AttemptPhase,
    ordinal: i64,
    session: i64,
    message: i64,
    command: i64,
    parent_command: Option<i64>,
    item: i32,
    kind: String,
    uri: Option<String>,
    status: Option<i32>,
    value: Option<String>,
    accepted: Option<bool>,
    received_at: Option<i64>,
    result_accepted: Option<bool>,
    result_received_at: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    redacted: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppleReceipt {
    phase: String,
    state: String,
    received_at: Option<i64>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationObservation {
    protocol: String,
    delivery: String,
    installation: String,
    agent_registration: Option<AgentRegistration>,
    observed_at: Option<i64>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentRegistration {
    device_id: String,
    registration_id: Uuid,
    state: String,
    capabilities: Option<Vec<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Supported,
    Unsupported,
    Blocked,
    Unknown,
    Ready,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    ProductNotConfigured,
    NotRegistered,
    CapabilityUnknown,
    CapabilityNotSupported,
    PermissionDenied,
}
#[derive(Deserialize, Serialize)]
pub struct Support {
    state: SupportState,
    reason: Option<CapabilityReason>,
}
#[derive(Deserialize, Serialize)]
pub struct Permission {
    allowed: bool,
    reason: Option<CapabilityReason>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    action: String,
    channel: String,
    product_support: Support,
    device_prerequisite: Support,
    permission: Permission,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSummary {
    pub id: Uuid,
    resource: String,
    resource_version: String,
    kind: String,
    created_at: i64,
    deadline: i64,
    cancellation_requested: bool,
    staged: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteStatistics {
    total: u64,
    cancellation_requested: u64,
    staging: u64,
}
pub type RemoteDirectory = Directory<RemoteSummary, Uuid, RemoteStatistics>;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDetail {
    operation_id: Uuid,
    deadline: i64,
    snapshot: crate::remote_operations::Snapshot,
    phase: crate::remote_execution::RemotePhase,
    cancellation_requested: bool,
    deadline_elapsed: bool,
    items: Vec<RemoteTarget>,
    next_cursor: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTarget {
    device: String,
    status: String,
    delivery_id: Option<Uuid>,
    diagnosis: Option<String>,
    agent_state: Option<RunState>,
    mdm_status: Option<String>,
    result: Option<SummaryResult>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    device: String,
    assignment: String,
    task_admission: Option<crate::sources::software::TaskAdmission>,
    operation_ids: Vec<Uuid>,
    diagnoses: Vec<String>,
}
pub type AssignmentPage = Page<Assignment, String>;
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    action: rss_mdm_policy::Action,
    scope_result: Uuid,
    items: Vec<PreviewTarget>,
    next_cursor: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewTarget {
    device: String,
    eligibility: crate::source_authority::ScopeAdmission,
    task_admission: Option<crate::sources::software::TaskAdmission>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollout {
    policy_id: Uuid,
    version_id: Uuid,
    paused: bool,
    as_of: i64,
    stages: Vec<Stage>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Stage {
    scope: Uuid,
    opens_at: i64,
    minimum_verified_percent: Option<u8>,
    open: bool,
    total_targets: u64,
    reported: u64,
    unknown: u64,
    waiting_user: u64,
    waiting_reboot: u64,
    failed: u64,
    verified_success: u64,
    unsupported_capability: u64,
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(v: Value) -> crate::transaction::Result<T> {
    crate::transaction::stored(serde_json::from_value(v))
}

#[cfg(test)]
#[path = "../../tests/query_records.rs"]
mod tests;
