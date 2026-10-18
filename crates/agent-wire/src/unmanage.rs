//! Fixed retirement task. No arbitrary executable, path, or erase instruction.
use crate::runtime::{
    TaskArchitecture, TaskAuthorization, TaskPermit, TaskPlatform, WIRE_VERSION, WireError,
    strict_uuid,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Administrator-authorized retirement of the installation holding this registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnmanageTaskSpec {
    /// Exact wire major.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Tenant authenticated by the server.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Original Agent endpoint.
    pub device_id: String,
    /// Registration which the local installation must still hold.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration_id: Uuid,
    /// Original registration revision; never adopt a replacement identity.
    pub generation: u64,
    /// Product retirement operation.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub retirement_id: Uuid,
    /// Existing durable execution task.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub task_id: Uuid,
    /// Exact delivery attempt.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub attempt_id: Uuid,
    /// Offer or freshly authorized start.
    pub permit: TaskPermit,
    /// Expiration of this signed permission.
    pub expires_at: i64,
    /// End of the execution budget.
    pub deadline: i64,
    /// Exact target platform.
    pub platform: TaskPlatform,
    /// Exact target architecture.
    pub architecture: TaskArchitecture,
    /// Published Policy responsible for the accepted retirement.
    pub authorization: TaskAuthorization,
}
impl UnmanageTaskSpec {
    /// Canonical bytes bind every target and authorization field in a dedicated domain.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.authorization.validate(self.tenant_id)?;
        if self.wire_version != WIRE_VERSION
            || self.tenant_id.is_nil()
            || self.registration_id.is_nil()
            || self.retirement_id.is_nil()
            || self.task_id.is_nil()
            || self.attempt_id.is_nil()
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.expires_at <= 0
            || self.deadline < self.expires_at
            || self.device_id.is_empty()
            || self.device_id.len() > 256
            || self.device_id.chars().any(char::is_control)
            || key_id.is_empty()
            || key_id.len() > 128
            || !matches!(self.authorization, TaskAuthorization::Policy { .. })
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-agent-unmanage-v1-ed25519\0".to_vec();
        bytes.extend(serde_json::to_vec(&(key_id, self)).map_err(|_| WireError::InvalidValue)?);
        Ok(bytes)
    }
}
/// Reported terminal effect; lack of a report is never completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnmanageOutcome {
    /// The protected installation owner verified its removal and credential cleanup.
    Completed,
    /// The owner confirmed a failure and retained its recovery evidence.
    Failed,
    /// Execution started but its effect could not be confirmed.
    Unknown,
}
