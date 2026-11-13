//! Typed read facts. Summary results cannot expose full output or diagnostic streams.
use rss_mdm_task_state::RunState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
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
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionStatistics {
    total: u64,
    commands: u64,
    action_runs: u64,
    unknown: u64,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Direct,
    Policy,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionMetadata {
    pub id: Uuid,
    pub kind: ExecutionKind,
    pub device: rss_mdm_agent_wire::DeviceId,
    origin: Origin,
    pub policy: Option<Uuid>,
    deadline: i64,
    pub(crate) status: String,
}
#[derive(schemars::JsonSchema, Serialize)]
pub struct ExecutionSummary<O = NativeObservation> {
    #[serde(flatten)]
    pub metadata: ExecutionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ExecutionEvidence<O>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<crate::deployment::authorization_decision::Authorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reauthorization: Option<crate::deployment::authorization_decision::Reauthorization>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ExecutionEvidence<O = NativeObservation> {
    Command(Box<CommandEvidence<O>>),
    Run(Box<RunEvidence>),
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandEvidence<O = NativeObservation> {
    pub command_status: CommandStatus,
    pub observation: O,
    pub dispatch_failure: Option<crate::deployment::DispatchFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_installation: Option<InstallationObservation>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvidence {
    state: RunState,
    effect: String,
    result: Option<SummaryResult>,
}
pub type ExecutionDirectory = Page<ExecutionSummary, String>;

pub use crate::deployment::actions::result::SummaryResult;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<rss_mdm_agent_wire::runtime::TaskAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<Uuid>,
    pub task_id: Uuid,
    device: rss_mdm_agent_wire::DeviceId,
    occurrence: String,
    pub available_at: i64,
    deadline: i64,
    state: RunState,
    effect: String,
    user_action: Option<String>,
    result: Option<SummaryResult>,
}
pub type RunPage = Page<RunSummary, String>;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunNode {
    step_id: [u8; 32],
    definition: rss_mdm_agent_wire::runtime::SoftwareStepDefinition,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetail {
    /// Nodes from this attempt's frozen material, without executable content or streams.
    pub nodes: Vec<RunNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<rss_mdm_agent_wire::runtime::TaskAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<Uuid>,
    task_id: Uuid,
    device: rss_mdm_agent_wire::DeviceId,
    available_at: i64,
    deadline: i64,
    state: RunState,
    effect: String,
    user_action: Option<String>,
    result: Option<crate::deployment::actions::result::RunResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<Uuid>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandDetail<O = NativeObservation> {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub revision: i64,
    pub task: crate::deployment::TaskSummary,
    pub target: crate::deployment::NativeTarget,
    pub input_version: String,
    pub deadline: i64,
    pub dispatch_failure: Option<crate::deployment::DispatchFailure>,
    pub authorization: crate::deployment::authorization_decision::Authorization,
    pub reauthorization: crate::deployment::authorization_decision::Reauthorization,
    pub command_status: CommandStatus,
    pub observation: O,
    pub agent_installation: Option<InstallationObservation>,
}
pub enum NativeObservation {
    Apple {
        facts: rss_mdm_apple_mdm::native::evidence::ReadEvidence,
        progress: CommandStatus,
        effect_confirmed: bool,
    },
    Declarations {
        facts: Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>,
        progress: CommandStatus,
    },
    Windows {
        receipts: Vec<WindowsReceipt>,
        progress: CommandStatus,
        effect: rss_mdm_windows_mdm::native::verification::EffectState,
        reason: Option<&'static str>,
    },
}
impl NativeObservation {}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsReceipt {
    pub phase: crate::deployment::AttemptPhase,
    pub ordinal: i64,
    pub session: i64,
    pub message: i64,
    pub command: i64,
    pub parent_command: Option<i64>,
    pub item: i32,
    pub kind: String,
    pub uri: Option<String>,
    pub status: Option<i32>,
    pub value: Option<String>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
    pub result_accepted: Option<bool>,
    pub result_received_at: Option<i64>,
    pub frames: Vec<WindowsFrame>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFrame {
    pub message: i64,
    pub command: i64,
    pub start_byte: i64,
    pub end_byte: i64,
    pub total_bytes: i64,
    pub status: Option<i32>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapObservation {
    pub state: String,
    pub delivery: Uuid,
    pub cleanup: Option<Uuid>,
    pub cleanup_complete: bool,
    pub cleanup_retry_at: i64,
    pub deadline: i64,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationObservation {
    pub bootstrap: Option<BootstrapObservation>,
    pub protocol: String,
    pub delivery: String,
    pub installation: String,
    pub agent_registration: Option<AgentRegistration>,
    pub observed_at: Option<i64>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRegistration {
    pub device_id: rss_mdm_agent_wire::DeviceId,
    pub state: String,
    pub capabilities: Option<Vec<String>>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Supported,
    Unsupported,
    Blocked,
    Unknown,
    Ready,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    ProductNotConfigured,
    NotRegistered,
    CapabilityUnknown,
    CapabilityNotSupported,
    PermissionDenied,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
pub struct Support {
    pub state: SupportState,
    pub reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
pub struct Permission {
    pub allowed: bool,
    pub reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub action: String,
    pub channel: String,
    pub product_support: Support,
    pub device_prerequisite: Support,
    pub permission: Permission,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub object: rss_mdm_agent_wire::ObjectRef,
    pub channel: Option<rss_mdm_inventory::Channel>,
    pub availability: crate::deployment::scope::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub qualification: crate::deployment::scope::ScopeAdmission,
    pub sources: Vec<crate::deployment::scope::DeviceObject>,
    pub scope_result: Option<Uuid>,
    pub task_admission: Option<rss_mdm_policy::pages::TaskAdmission>,
    pub operation_ids: Vec<Uuid>,
}
pub type AssignmentPage = Page<Assignment, String>;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub action: rss_mdm_policy::Action,
    pub scope_result: Uuid,
    pub items: Vec<PreviewTarget>,
    pub next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewTarget {
    pub object: rss_mdm_agent_wire::ObjectRef,
    pub channel: Option<rss_mdm_inventory::Channel>,
    pub availability: crate::deployment::scope::Availability,
    pub reason: Option<String>,
    pub target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    pub eligibility: crate::deployment::scope::ScopeAdmission,
    pub task_admission: Option<rss_mdm_policy::pages::TaskAdmission>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollout {
    pub policy_id: Uuid,
    pub version_id: Uuid,
    pub paused: bool,
    pub as_of: i64,
    pub stages: Vec<Stage>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    pub ready: bool,
    pub as_of: Option<i64>,
    pub scope: Uuid,
    pub opens_at: i64,
    pub minimum_verified_percent: Option<u8>,
    pub open: bool,
    pub total_targets: u64,
    pub reported: u64,
    pub unknown: u64,
    pub waiting_user: u64,
    pub waiting_reboot: u64,
    pub failed: u64,
    pub verified_success: u64,
    pub unsupported_capability: u64,
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    v: Value,
) -> crate::deployment::transaction::Result<T> {
    crate::deployment::transaction::stored(serde_json::from_value(v))
}

/// The shared command owner's closed public state, without a second state table.
#[derive(Clone, Copy, Debug)]
pub struct CommandStatus(pub rss_device_command::Status);
impl Serialize for CommandStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}
impl<'de> Deserialize<'de> for CommandStatus {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        rss_device_command::Status::ALL
            .into_iter()
            .find(|s| s.as_str() == value)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("unknown command state"))
    }
}
impl schemars::JsonSchema for CommandStatus {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CommandStatus".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"string","enum":rss_device_command::Status::ALL.map(|s|s.as_str())})
    }
}
