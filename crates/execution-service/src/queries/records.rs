//! Typed read facts. Summary results cannot expose full output or diagnostic streams.
use crate::actions::state::RunState;
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
    pub device: String,
    registration_id: Uuid,
    generation: i64,
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
    pub authorization: Option<crate::authorization_decision::Authorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reauthorization: Option<crate::authorization_decision::Reauthorization>,
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
    pub dispatch_failure: Option<crate::DispatchFailure>,
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

pub use crate::actions::result::SummaryResult;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<rss_mdm_agent_wire::runtime::TaskAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<Uuid>,
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
    device: String,
    registration_id: Uuid,
    generation: i64,
    available_at: i64,
    deadline: i64,
    state: RunState,
    effect: String,
    user_action: Option<String>,
    result: Option<crate::actions::result::RunResult>,
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
    pub task: crate::TaskSummary,
    pub target: crate::NativeTarget,
    pub input_version: String,
    pub deadline: i64,
    pub dispatch_failure: Option<crate::DispatchFailure>,
    pub authorization: crate::authorization_decision::Authorization,
    pub reauthorization: crate::authorization_decision::Reauthorization,
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
impl NativeObservation {
    pub(crate) fn redact_values(&mut self) {
        if let Self::Windows { receipts, .. } = self {
            for receipt in receipts {
                receipt.value = None;
                receipt.redacted = true;
            }
        }
    }
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsReceipt {
    pub phase: crate::AttemptPhase,
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
    state: String,
    delivery: Uuid,
    cleanup: Option<Uuid>,
    cleanup_complete: bool,
    cleanup_retry_at: i64,
    deadline: i64,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationObservation {
    bootstrap: Option<BootstrapObservation>,
    protocol: String,
    delivery: String,
    installation: String,
    agent_registration: Option<AgentRegistration>,
    observed_at: Option<i64>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentRegistration {
    device_id: String,
    registration_id: Uuid,
    state: String,
    capabilities: Option<Vec<String>>,
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
    state: SupportState,
    reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
pub struct Permission {
    allowed: bool,
    reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    action: String,
    channel: String,
    product_support: Support,
    device_prerequisite: Support,
    permission: Permission,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    object: crate::source_authority::ObjectRef,
    channel: Option<rss_mdm_inventory::Channel>,
    availability: crate::source_authority::Availability,
    reason: Option<String>,
    target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    qualification: crate::source_authority::ScopeAdmission,
    sources: Vec<crate::source_authority::DeviceObject>,
    scope_result: Option<Uuid>,
    task_admission: Option<crate::sources::software::TaskAdmission>,
    operation_ids: Vec<Uuid>,
}
pub type AssignmentPage = Page<Assignment, String>;
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    action: rss_mdm_policy::Action,
    scope_result: Uuid,
    items: Vec<PreviewTarget>,
    next_cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewTarget {
    object: crate::source_authority::ObjectRef,
    channel: Option<rss_mdm_inventory::Channel>,
    availability: crate::source_authority::Availability,
    reason: Option<String>,
    target: Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>,
    eligibility: crate::source_authority::ScopeAdmission,
    task_admission: Option<crate::sources::software::TaskAdmission>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollout {
    policy_id: Uuid,
    version_id: Uuid,
    paused: bool,
    as_of: i64,
    stages: Vec<Stage>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Stage {
    ready: bool,
    as_of: Option<i64>,
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

#[cfg(test)]
mod native_summary_tests {
    use super::*;
    #[test]
    fn summaries_never_serialize_native_values_or_nested_evidence() {
        let value:SummaryResult=serde_json::from_value(serde_json::json!({"native":{"private":"device-data"},"queries":{},"planDigest":vec![1;32],"outputReference":{"bytes":5,"sha256":"digest"},"trusted":true,"receivedAt":1,"diagnostics":null})).unwrap();
        let output = serde_json::to_value(value).unwrap();
        assert!(output.get("native").is_none());
        assert!(
            serde_json::from_value::<SummaryResult>(
                serde_json::json!({"nested":[{"native":{"secret":"value"}}]})
            )
            .is_err()
        );
        assert_eq!(output["diagnostics"], serde_json::Value::Null);
    }
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
