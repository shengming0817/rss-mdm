//! Contracts for authenticated Agent service calls on behalf of an employee.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
/// Origin attested by the authenticated system service, never taken from model arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelfServiceCaller {
    /// Interactive employee action.
    Human,
    /// AI tool action forwarded by the system service.
    Ai,
}
/// Authenticated product user; contains no session credential.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceUser {
    /// Product tenant.
    pub tenant_id: Uuid,
    /// Identity instance.
    pub instance_id: Uuid,
    /// Authenticated principal.
    pub principal_id: Uuid,
}
/// Subject selected by the server's explicit Policy access basis.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelfServiceSubject {
    /// Device credential plus effective device scope; no enterprise session.
    Device,
    /// A live enterprise session matched by product authorization.
    User {
        /// Authenticated enterprise coordinates, without a credential.
        user: SelfServiceUser,
    },
}
impl SelfServiceSubject {
    fn valid(&self, tenant: Uuid) -> bool {
        match self {
            Self::Device => true,
            Self::User { user } => {
                user.tenant_id == tenant
                    && !user.instance_id.is_nil()
                    && !user.principal_id.is_nil()
            }
        }
    }
}
/// Server decision covered by the same signature as all script execution inputs.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskAuthorization {
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
        subject: SelfServiceSubject,
        /// Trusted service's caller classification.
        source: SelfServiceCaller,
        /// Policy identity.
        policy_id: Uuid,
        /// Configuration revision approved at invocation.
        policy_revision: u64,
        /// Immutable execution version.
        policy_version: Uuid,
        /// Effective AI switch.
        allow_ai: bool,
        /// Closed risk level, one or two.
        #[serde(deserialize_with = "deserialize_risk")]
        #[schemars(schema_with = "risk_schema")]
        risk_level: u8,
        /// Confirmation attested for this exact request by the service.
        confirmed: bool,
    },
}
impl TaskAuthorization {
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
                subject,
                source,
                policy_id,
                policy_revision,
                policy_version,
                allow_ai,
                risk_level,
                confirmed,
            } => {
                !request_id.is_nil()
                    && subject.valid(tenant)
                    && !policy_id.is_nil()
                    && *policy_revision > 0
                    && !policy_version.is_nil()
                    && matches!(risk_level, 1 | 2)
                    && (*source != SelfServiceCaller::Ai
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
pub struct TaskResource {
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
    pub source: SelfServiceCaller,
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
    pub source: SelfServiceCaller,
    /// Last examined Policy identity.
    pub after: Option<Uuid>,
}

fn risk_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"integer","enum":[1,2]})
}

/// Published presentation and invocation settings; values are normalized by Policy CAS.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceMetadata {
    /// Whether this script is published for self service.
    pub published: bool,
    /// Directory display name.
    pub display_name: String,
    /// Intended purpose.
    pub description: String,
    /// Preconditions shown before invocation.
    pub prerequisites: String,
    /// Expected effects shown before invocation.
    pub side_effects: String,
    /// Presentation category.
    pub category: String,
    /// Search terms.
    pub keywords: Vec<String>,
    /// Effective administrator AI switch.
    pub allow_ai: bool,
    #[serde(deserialize_with = "deserialize_risk")]
    #[schemars(schema_with = "risk_schema")]
    /// Effective risk level, one or two.
    pub risk_level: u8,
}
/// Public source of one Resource-declared parameter.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScriptParameterSource {
    /// Administrator literal.
    Fixed {
        #[schemars(schema_with = "scalar_schema")]
        /// Administrator-selected scalar checked against the Resource schema.
        value: serde_json::Value,
    },
    /// Required call-time input.
    Input {},
}
/// Directory response consumed by the Agent service and employee UI.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceDirectoryResponse {
    /// Authorized directory entries.
    pub items: Vec<SelfServiceDirectoryItem>,
    /// Last examined Policy when another page may exist.
    pub next_cursor: Option<Uuid>,
    /// Server observation time in Unix seconds.
    pub as_of: i64,
}
/// One currently authorized script and its Resource-owned parameter schema.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceDirectoryItem {
    /// Logical Policy identity.
    pub policy_id: Uuid,
    /// Current configuration CAS revision.
    pub policy_revision: u64,
    /// Immutable execution version.
    pub policy_version: Uuid,
    /// Normalized presentation and invocation settings.
    pub self_service: SelfServiceMetadata,
    /// Closed task kind and the exact invocation interface.
    pub task: SelfServiceTask,
}
/// One directory interface; software does not inherit script parameter semantics.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SelfServiceTask {
    /// Resource-owned script execution interface.
    Script {
        /// Exact Resource selection.
        resource: TaskResource,
        /// Required operating-system identity.
        run_as: crate::runtime::ExecutionIdentity,
        /// Complete sources for script parameters.
        parameter_sources: BTreeMap<String, ScriptParameterSource>,
        /// Full resolved parameter constraints owned by Resource.
        parameter_schema: serde_json::Value,
    },
    /// Explicit request for approved AvailableInstall software.
    Software {
        /// Exact Resource selection.
        resource: TaskResource,
        /// Required operating-system identity of the root operation.
        run_as: crate::runtime::ExecutionIdentity,
        /// Exact effect target, distinct from enterprise login.
        target: crate::runtime::SoftwareExecutionTarget,
    },
}
/// Durable acceptance receipt; retries return the same Run identity.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceAccepted {
    /// Durable idempotency identity of the invocation.
    pub request_id: Uuid,
    /// Durable Run identity.
    pub run_id: Uuid,
    /// Logical Policy identity.
    pub policy_id: Uuid,
    /// Current configuration CAS revision.
    pub policy_revision: u64,
    /// Immutable execution version.
    pub policy_version: Uuid,
}
/// Public delivery observation, independent of the server reducer implementation.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskDelivery {
    /// Awaiting a device claim.
    Queued,
    /// Claimed by one leased attempt.
    Claimed {
        /// Attempt identity.
        attempt: Uuid,
        /// Lease expiry in Unix seconds.
        lease_until: i64,
    },
    /// Receipt acknowledged by one leased attempt.
    Received {
        /// Attempt identity.
        attempt: Uuid,
        /// Lease expiry in Unix seconds.
        lease_until: i64,
    },
}
/// Public execution observation. Unknown never authorizes a blind retry.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecution {
    /// No Start has been admitted.
    NotStarted,
    /// Execution was admitted and is running.
    Running,
    /// A successful result was recorded.
    Succeeded,
    /// A failed result was recorded.
    Failed,
    /// Execution awaits a reboot observation.
    WaitingReboot,
    /// The effect is uncertain.
    Unknown,
}
/// Public cancellation observation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunCancellation {
    /// No cancellation requested.
    None,
    /// Cancellation requested but not acknowledged.
    Requested,
    /// Cancellation acknowledged or stopped before execution.
    Confirmed,
}
/// Current durable Run observation, without server-side reducer methods.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRunState {
    /// Current delivery observation.
    pub delivery: TaskDelivery,
    /// Current execution observation.
    pub execution: TaskExecution,
    /// Current cancellation observation.
    pub cancellation: RunCancellation,
    /// Final Run deadline in Unix seconds.
    pub deadline: i64,
    /// Server time at which execution was admitted.
    pub started_at: Option<i64>,
}
/// Status of an invocation by this device and authenticated employee.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceStatus {
    /// Durable idempotency identity of the invocation.
    pub request_id: Uuid,
    /// Durable Run identity.
    pub run_id: Uuid,
    /// Current attempt identity, if claimed.
    pub attempt_id: Option<Uuid>,
    /// Current durable Run observation.
    pub state: TaskRunState,
    /// Earliest server admission time in Unix seconds.
    pub available_at: i64,
    /// Final Run deadline in Unix seconds.
    pub deadline: i64,
    /// Authorized result with native collection time and server receipt time.
    #[schemars(required, schema_with = "nullable_schema::<SelfServiceResult>")]
    #[serde(deserialize_with = "crate::runtime::required_option")]
    pub result: Option<SelfServiceResult>,
}
/// Authorized evidence; execution state is available independently from sensitive output.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelfServiceResult {
    /// Script evidence returned only when output-read permissions permit it.
    Script {
        /// Original bounded script evidence.
        evidence: ScriptRunResult,
    },
    /// Software outcome; process streams and native evidence stay in management reads.
    Software {
        /// Current independent detection outcome.
        effect: SelfServiceSoftwareEffect,
    },
}
/// Closed software effect projection.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelfServiceSoftwareEffect {
    /// Independently satisfied.
    Verified,
    /// Independently failed.
    Failed,
    /// Waiting for reboot and detection.
    WaitingReboot,
    /// Effect unresolved; no blind retry.
    Unknown,
}
/// Server-persisted script evidence; only Resource output has a dynamic shape.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptRunResult {
    /// Agent's original collection timestamp in Unix seconds.
    pub collected_at: i64,
    /// Server receipt timestamp in Unix seconds.
    pub received_at: i64,
    /// Original process exit code, absent when unavailable.
    #[schemars(required, schema_with = "nullable_schema::<i32>")]
    #[serde(deserialize_with = "crate::runtime::required_option")]
    pub exit_code: Option<i32>,
    /// Original completeness classification.
    pub quality: crate::runtime::OutputQuality,
    /// Whether the output matches the Resource schema.
    pub schema_valid: bool,
    /// Whether the output satisfies Resource budgets.
    pub budget_valid: bool,
    /// Resource-defined output, or null when retained only by reference.
    pub output: serde_json::Value,
    /// Digest and size when output is retained by reference.
    #[schemars(required, schema_with = "nullable_schema::<ScriptOutputReference>")]
    #[serde(deserialize_with = "crate::runtime::required_option")]
    pub output_reference: Option<ScriptOutputReference>,
    /// Original bounded process diagnostics.
    pub diagnostics: crate::runtime::TaskDiagnostics,
    /// Whether this evidence may contribute current inventory facts.
    pub trusted: bool,
}
/// Reference for output too large or outside its declared Resource budget.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptOutputReference {
    /// Exact encoded JSON byte count.
    pub bytes: u64,
    /// SHA-256 of those exact bytes.
    pub sha256: String,
}

fn scalar_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"anyOf":[{"type":"string","pattern":"^[^\\u0000]*$"},{"type":"boolean"},{"type":"integer","minimum":-9223372036854775808i64,"maximum":9223372036854775807i64}]})
}

fn deserialize_risk<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(deserializer)?;
    if matches!(value, 1 | 2) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("invalid script risk level"))
    }
}

// Required JSON keys may still carry an explicit null.
pub(crate) fn nullable_schema<T: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    generator.subschema_for::<Option<T>>()
}
