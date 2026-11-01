use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    LifecycleBlocked,
    RegistrationChanged,
    InputMismatch,
    SourceInvalid,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authorization {
    Authorized,
    Blocked { reason: BlockReason },
    NotApplicable,
}
impl Authorization {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReauthorizationReason {
    PermissionDenied,
    Terminal,
    AlreadyReceived,
    Expired,
    RegistrationChanged,
    InputMismatch,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Reauthorization {
    Available { confirmation_required: bool },
    Unavailable { reason: ReauthorizationReason },
    NotApplicable,
}

pub enum NativeObservation {
    Apple {
        facts: rss_mdm_apple_mdm::native::evidence::ReadEvidence,
        progress: rss_device_command::Status,
        effect_confirmed: bool,
    },
    Declarations {
        facts: Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>,
        progress: rss_device_command::Status,
    },
    Windows {
        receipts: Vec<WindowsReceipt>,
        progress: rss_device_command::Status,
        effect: rss_mdm_windows_mdm::native::verification::EffectState,
        reason: Option<&'static str>,
    },
}
impl NativeObservation {
    pub fn redact_values(&mut self) {
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
    pub phase: super::super::model::AttemptPhase,
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

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Detail<O = NativeObservation> {
    pub operation_id: Uuid,
    pub command_id: Uuid,
    pub revision: i64,
    pub task: super::super::model::TaskSummary,
    pub target: super::super::NativeTarget,
    pub input_version: String,
    pub deadline: i64,
    pub dispatch_failure: Option<super::super::model::DispatchFailure>,
    pub authorization: Authorization,
    #[serde(serialize_with = "status")]
    #[schemars(with = "String")]
    pub command_status: rss_device_command::Status,
    pub observation: O,
}
pub struct Evidence {
    pub command_status: rss_device_command::Status,
    pub observation: NativeObservation,
    pub dispatch_failure: Option<super::super::model::DispatchFailure>,
}
pub struct Declaration {
    pub registration: Uuid,
    pub generation: i64,
    pub redacted: bool,
    pub observation: NativeObservation,
}
pub struct Assignment {
    pub diagnosis: Option<String>,
    pub operations: Vec<Uuid>,
}

fn status<S: serde::Serializer>(v: &rss_device_command::Status, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.as_str())
}
