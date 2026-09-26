//! Planning rejection semantics and their protocol projection.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PlanningError {
    #[error("frozen configuration rejected")]
    Plan(PlanFailure),
    #[error("configuration target limit exceeded")]
    TargetLimit,
    #[error("planning object not found")]
    Missing(Missing),
    #[error("action plan rejected")]
    Action(ActionRejection),
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub enum Missing {
    Device,
    Group,
    Scope,
    Policy,
    Preview,
    Rule,
    Action,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub enum ActionRejection {
    ScopeUnavailable,
    ScopeStale,
    TargetsEmpty,
    TargetsLimit,
    ResourceUnavailable,
    Capacity,
}
impl IntoResponse for PlanningError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Plan(v) => (StatusCode::CONFLICT, v.reason.code()),
            Self::TargetLimit => (StatusCode::BAD_REQUEST, "configuration_target_limit"),
            Self::Missing(v) => (
                StatusCode::NOT_FOUND,
                match v {
                    Missing::Device => "planning_device_not_found",
                    Missing::Group => "group_not_found",
                    Missing::Scope => "scope_not_found",
                    Missing::Policy => "policy_not_found",
                    Missing::Preview => "plan_preview_not_found",
                    Missing::Rule => "group_rule_not_found",
                    Missing::Action => "action_plan_not_found",
                },
            ),
            Self::Action(v) => match v {
                ActionRejection::ScopeUnavailable => (StatusCode::CONFLICT, "scope_unavailable"),
                ActionRejection::ScopeStale => (StatusCode::CONFLICT, "scope_stale"),
                ActionRejection::TargetsEmpty => (StatusCode::BAD_REQUEST, "action_targets_empty"),
                ActionRejection::TargetsLimit => (StatusCode::BAD_REQUEST, "action_target_limit"),
                ActionRejection::ResourceUnavailable => {
                    (StatusCode::CONFLICT, "script_resource_unavailable")
                }
                ActionRejection::Capacity => (StatusCode::CONFLICT, "action_capacity_exceeded"),
            },
        };
        let mut body = serde_json::json!({"code":code});
        if let Self::Plan(v) = self {
            body["device"] = serde_json::json!(v.device);
            body["stage"] = serde_json::json!(v.stage);
        }
        (status, Json(body)).into_response()
    }
}
/// Safe product failure context; no source documents or database errors escape.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PlanFailure {
    pub reason: PlanFailureReason,
    pub device: Option<String>,
    pub stage: PlanStage,
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanFailureReason {
    CapabilityUnknown,
    PlatformUnsupported,
    StalePlan,
    OwnerConflict,
}
impl PlanFailureReason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CapabilityUnknown => "capability_unknown",
            Self::PlatformUnsupported => "platform_unsupported",
            Self::StalePlan => "stale_plan",
            Self::OwnerConflict => "owner_conflict",
        }
    }
    pub(crate) fn at(self, device: Option<&str>, stage: PlanStage) -> crate::Error {
        crate::Error::Planning(PlanningError::Plan(PlanFailure {
            reason: self,
            device: device.map(str::to_owned),
            stage,
        }))
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStage {
    Preview,
    Save,
    Execute,
}

impl From<ActionRejection> for crate::Error {
    fn from(value: ActionRejection) -> Self {
        Self::Planning(PlanningError::Action(value))
    }
}
