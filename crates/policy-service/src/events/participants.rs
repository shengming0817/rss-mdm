//! Policy requests only foreign execution admission and progress that it consumes.
use super::*;
use crate::inputs::Pending;
use crate::transaction::Fault;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
pub trait ExecutionEvents: Send + Sync {
    fn verify_event_device_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        principal: &'a rss_mdm_registration_service::DevicePrincipal,
        input: Option<&'a wire::PolicyEventRequest>,
    ) -> Pending<'a, (), Fault>;
    fn apply_event_context_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        target: &'a Target,
        context: &'a wire::SoftwareExecutionContext,
    ) -> Pending<'a, (), Fault>;
    fn event_parent_current_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        target: &'a Target,
        source: &'a wire::PolicyEventSource,
    ) -> Pending<'a, bool, Fault>;
    fn accept_policy_event_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a rss_mdm_policy::Policy,
        target: &'a Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::PolicyEventDecision, Fault>;
}
pub trait ExecutionProgress: Send + Sync {
    fn policy_event_operation_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        reference: &'a wire::PolicyEventOperation,
    ) -> Pending<'a, EventOperationProgress, Fault>;
}

/// The actual operation owner's progress, retaining the established untagged HTTP shape.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum EventOperationProgress {
    Run {
        reference: wire::PolicyEventOperation,
        state: rss_mdm_task_state::RunState,
        allowed_actions: [String; 0],
    },
    Native {
        reference: wire::PolicyEventOperation,
        #[serde(serialize_with = "serialize_native_status")]
        #[schemars(schema_with = "native_status_schema")]
        state: rss_device_command::Status,
        agent_installation: Option<InstallationObservation>,
        allowed_actions: [String; 0],
    },
    Retirement {
        reference: wire::PolicyEventOperation,
        state: rss_mdm_device_service::lifecycle::Retirement,
        allowed_actions: [String; 0],
    },
}
fn serialize_native_status<S: serde::Serializer>(
    status: &rss_device_command::Status,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(status.as_str())
}
fn native_status_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","enum":rss_device_command::Status::ALL.map(|s|s.as_str())})
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
    pub device_id: String,
    pub registration_id: Uuid,
    pub state: String,
    pub capabilities: Option<Vec<String>>,
}
