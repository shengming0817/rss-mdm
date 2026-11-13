use rss_mdm_audit_integration::activity::ActivityOrigin;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub device: rss_mdm_agent_wire::DeviceId,
}
pub struct AgentRun {
    pub id: Uuid,
    pub policy_version: Uuid,
    pub origin: ActivityOrigin,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: rss_mdm_task_state::RunState,
    pub result: Option<super::result::AgentCollection>,
    pub source_objects: Vec<crate::objects::DeviceObject>,
}
/// Native collection owns delivery only. Terminal quality/reason is read directly
/// from collection_runs and is never mirrored into an execution result state.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeDelivery {
    Queued,
    Prepared,
    Sent,
    Cancelled,
}

/// Report lifecycle, independent of report quality, asset projection and retirement certainty.
/// The directory SQL mirrors this pure mapping and is checked against it on PostgreSQL.
pub fn native_terminal_status(sealed: bool, reason: &str, result: &str) -> Option<&'static str> {
    if !sealed {
        return None;
    }
    Some(match reason {
        "complete" if result == "failed" => "failed",
        "complete" => "succeeded",
        "timeout" => "expired",
        _ => "cancelled",
    })
}
pub struct NativeRun {
    pub id: Uuid,
    pub policy_version: Uuid,
    pub origin: ActivityOrigin,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub delivery: NativeDelivery,
    pub collection_run: Option<Uuid>,
    pub started_at: Option<i64>,
    pub source_objects: Vec<crate::objects::DeviceObject>,
}

/// Public native task progress is derived from the report, without a mirrored execution state.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NativeProgress {
    pub delivery: NativeDelivery,
    pub report: Option<NativeReport>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NativeReport {
    pub id: Uuid,
    pub result: String,
    pub reason: Option<String>,
    pub sealed_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::native_terminal_status;
    #[test]
    fn report_lifecycle_does_not_claim_projection_or_retirement_certainty() {
        for (sealed, reason, result, expected) in [
            (false, "timeout", "failed", None),
            (true, "complete", "failed", Some("failed")),
            (true, "complete", "snapshot", Some("succeeded")),
            (true, "complete", "partial", Some("succeeded")),
            (true, "timeout", "failed", Some("expired")),
            (true, "revoked", "partial", Some("cancelled")),
        ] {
            assert_eq!(native_terminal_status(sealed, reason, result), expected);
        }
    }
}
