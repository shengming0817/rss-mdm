//! Contracts for authenticated Agent service calls on behalf of an employee.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
/// Origin attested by the authenticated system service, never taken from model arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScriptCaller {
    /// Interactive employee action.
    Human,
    /// AI tool action forwarded by the system service.
    Ai,
}
/// Authenticated product user; contains no session credential.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptActor {
    /// Product tenant.
    pub tenant_id: Uuid,
    /// Identity instance.
    pub instance_id: Uuid,
    /// Authenticated principal.
    pub principal_id: Uuid,
}
/// Server decision covered by the same signature as all script execution inputs.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScriptAuthorization {
    /// Ordinary scheduled Policy execution.
    Policy {
        /// Policy identity.
        policy_id: Uuid,
        /// Immutable execution version.
        policy_version: Uuid,
    },
    /// Existing Remote Operation execution.
    RemoteOperation {
        /// Operation identity.
        operation_id: Uuid,
    },
    /// Targeted Policy self-service invocation.
    SelfService {
        /// Idempotency identity of the call.
        request_id: Uuid,
        /// Real employee identity.
        actor: ScriptActor,
        /// Trusted service's caller classification.
        source: ScriptCaller,
        /// Policy identity.
        policy_id: Uuid,
        /// Configuration revision approved at invocation.
        policy_revision: u64,
        /// Immutable execution version.
        policy_version: Uuid,
        /// Effective AI switch.
        allow_ai: bool,
        /// Closed risk level, one or two.
        #[schemars(schema_with = "risk_schema")]
        risk_level: u8,
        /// Confirmation attested for this exact request by the service.
        confirmed: bool,
    },
}
impl ScriptAuthorization {
    /// Validate closed authorization coordinates and mandatory AI confirmation.
    pub fn validate(&self, tenant: Uuid) -> Result<(), super::runtime::WireError> {
        let valid = match self {
            Self::Policy {
                policy_id,
                policy_version,
            } => !policy_id.is_nil() && !policy_version.is_nil(),
            Self::RemoteOperation { operation_id } => !operation_id.is_nil(),
            Self::SelfService {
                request_id,
                actor,
                source,
                policy_id,
                policy_revision,
                policy_version,
                allow_ai,
                risk_level,
                confirmed,
            } => {
                !request_id.is_nil()
                    && actor.tenant_id == tenant
                    && !actor.instance_id.is_nil()
                    && !actor.principal_id.is_nil()
                    && !policy_id.is_nil()
                    && *policy_revision > 0
                    && !policy_version.is_nil()
                    && matches!(risk_level, 1 | 2)
                    && (*source != ScriptCaller::Ai
                        || (*allow_ai && (*risk_level == 1 || *confirmed)))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(super::runtime::WireError::InvalidValue)
        }
    }
}
/// Exact Resource identity accompanying its signed digest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptResource {
    /// Logical Resource identity.
    pub id: String,
    /// Immutable Resource version.
    pub version: String,
    /// Exact selected variant.
    pub variant: String,
}
/// One call-time request. The device is selected exclusively by its credential.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceInvoke {
    /// Durable idempotency identity.
    pub operation_id: Uuid,
    /// Policy chosen from the authorized directory.
    pub policy_id: Uuid,
    /// Current configuration CAS.
    pub policy_revision: u64,
    /// Immutable execution version returned by the directory.
    pub policy_version: Uuid,
    /// Caller origin attested by the device service.
    pub source: ScriptCaller,
    /// Service-attested employee confirmation for these exact inputs.
    pub confirmed: bool,
    /// Exactly the Policy's Input parameters; Fixed values cannot be submitted.
    pub parameters: BTreeMap<String, serde_json::Value>,
}
/// Bounded directory pagination; source is attested by the authenticated service.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceDirectory {
    /// Caller origin.
    pub source: ScriptCaller,
    /// Last examined Policy identity.
    pub after: Option<Uuid>,
}

fn risk_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"integer","enum":[1,2]})
}
