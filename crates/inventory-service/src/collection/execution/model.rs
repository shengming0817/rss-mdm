use rss_mdm_audit_integration::activity::ActivityOrigin;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeDelivery {
    Queued,
    Prepared,
    Sent,
    Cancelled,
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
