//! Strict task messages. Authentication and durable authority remain server responsibilities.
#[path = "tasks/context.rs"]
mod context;
use super::{WIRE_VERSION, WireError, strict_uuid};
pub use context::{
    SoftwareExecutionContext, SoftwareExecutionTarget, SoftwareInteractiveUser,
    SoftwareReadCredential,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Maximum encoded task event, including a 1 MiB result and bounded envelope.
pub const MAX_TASK_REQUEST_BYTES: usize = 1_114_112;
/// Maximum cancellation coordinates returned by one task claim.
pub const MAX_TASK_CANCELLATIONS: usize = 128;
/// Maximum UTF-8 bytes retained for each diagnostic stream.
pub const MAX_TASK_DIAGNOSTIC_BYTES: usize = 16 * 1024;
/// Seven-day upper bound for software execution evidence.
pub const MAX_TASK_DURATION_MS: u64 = 604_800_000;

pub(crate) fn version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(d)?;
    if value != WIRE_VERSION {
        return Err(serde::de::Error::custom("unsupported wire version"));
    }
    Ok(value)
}
fn accepted<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    if !bool::deserialize(d)? {
        return Err(serde::de::Error::custom("acceptance required"));
    }
    Ok(true)
}
pub(crate) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}
/// Cancellation applies only to this exact task attempt; it asserts no rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskCancellation {
    /// Task identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    task_id: Uuid,
    /// Attempt to stop.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    attempt_id: Uuid,
}
impl TaskCancellation {
    /// Construct one cancellation for an exact non-nil task attempt.
    pub fn new(task_id: Uuid, attempt_id: Uuid) -> Result<Self, WireError> {
        if task_id.is_nil() || attempt_id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            task_id,
            attempt_id,
        })
    }
    /// Task identity.
    pub const fn task_id(&self) -> Uuid {
        self.task_id
    }
    /// Attempt to stop.
    pub const fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
}
/// Poll response; the offer still requires signature verification and a separate start permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskClaimResponse {
    /// Sole supported major.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    wire_version: u8,
    /// At most one offered task.
    #[serde(deserialize_with = "required_option")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<SignedTask>"
    )]
    task: Option<SignedTask>,
    /// Authenticated cancellation requests.
    #[schemars(extend("maxItems" = 128))]
    #[serde(deserialize_with = "cancellations")]
    cancellations: Vec<TaskCancellation>,
}
impl TaskClaimResponse {
    /// Construct a bounded poll response with the fixed wire version.
    pub fn new(
        task: Option<SignedTask>,
        cancellations: Vec<TaskCancellation>,
    ) -> Result<Self, WireError> {
        if cancellations.len() > MAX_TASK_CANCELLATIONS {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            wire_version: WIRE_VERSION,
            task,
            cancellations,
        })
    }
    /// Offered task, if any.
    pub const fn task(&self) -> Option<&SignedTask> {
        self.task.as_ref()
    }
    /// Consume the response and return its offered task.
    pub fn into_task(self) -> Option<SignedTask> {
        self.task
    }
    /// Authenticated cancellation requests.
    pub fn cancellations(&self) -> &[TaskCancellation] {
        &self.cancellations
    }
}
/// A durable event receipt. Acceptance alone cannot authorize process execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEventAck {
    /// Sole supported major.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    wire_version: u8,
    /// The event was durably accepted.
    #[serde(deserialize_with = "accepted")]
    #[schemars(extend("const" = true))]
    accepted: bool,
    /// Only Start may return a freshly signed start permit.
    #[serde(deserialize_with = "required_option")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<SignedTask>"
    )]
    permit: Option<SignedTask>,
    /// Stop this attempt; execution effects may remain unknown.
    cancel_requested: bool,
}
impl TaskEventAck {
    /// Construct a durable accepted receipt with the fixed wire version.
    pub const fn new(permit: Option<SignedTask>, cancel_requested: bool) -> Self {
        Self {
            wire_version: WIRE_VERSION,
            accepted: true,
            permit,
            cancel_requested,
        }
    }
    /// The event was durably accepted.
    pub const fn accepted(&self) -> bool {
        self.accepted
    }
    /// Freshly signed start permit, if any.
    pub const fn permit(&self) -> Option<&SignedTask> {
        self.permit.as_ref()
    }
    /// Consume the receipt and return its start permit.
    pub fn into_permit(self) -> Option<SignedTask> {
        self.permit
    }
    /// Whether the Agent should stop this attempt.
    pub const fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }
}
/// A task receipt, start request, or bounded execution result; none proves applied state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskEvent {
    /// The complete signed offer was received and verified.
    Received,
    /// Request a fresh start permit immediately before executing the task.
    Start,
    /// Cancellation was observed and the process stopped or never started.
    Cancelled,
    /// Process evidence. Successful exit alone does not prove the requested side effect.
    Result(TaskResult),
    /// A bounded fragment of a collection output; never a terminal snapshot.
    OutputChunk(crate::runtime::OutputChunk),
    /// Terminal evidence whose output must be fully assembled and verified.
    ChunkedResult(crate::runtime::ChunkedTaskResult),
    /// Independent software detection evidence after local software-plan execution.
    SoftwareResult(SoftwareTaskResult),
    /// Only the enrollment UI outcome; active MDM registration is server-owned.
    EnrollmentResult {
        /// Closed platform outcome.
        outcome: crate::runtime::EnrollmentEntryOutcome,
    },
}
#[path = "tasks/export.rs"]
mod export;
pub use export::*;
#[path = "tasks/results.rs"]
mod results;
pub use results::*;
/// Output completeness controls whether collection facts may be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutputQuality {
    /// Complete successful capture within all budgets.
    Complete,
    /// Only a subset was collected.
    Partial,
    /// A configured output or row limit was reached.
    Truncated,
    /// Execution or capture failed.
    Failed,
}
/// Closed executor failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailure {
    /// The executor process could not be launched.
    LaunchFailed,
    /// The configured execution deadline elapsed.
    TimedOut,
    /// Execution was cancelled before a complete result was produced.
    Cancelled,
    /// The process exited with a non-zero status.
    NonZeroExit,
    /// A configured output or row limit was reached.
    OutputLimit,
    /// The executor could not capture a complete result.
    CaptureFailed,
}
/// Private bounded process diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "DiagnosticsInput", into = "DiagnosticsInput")]
pub struct TaskDiagnostics(DiagnosticsInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiagnosticsInput {
    #[schemars(length(max = MAX_TASK_DIAGNOSTIC_BYTES), regex(pattern = "^[^\\u0000]*$"))]
    stdout: String,
    #[schemars(length(max = MAX_TASK_DIAGNOSTIC_BYTES), regex(pattern = "^[^\\u0000]*$"))]
    stderr: String,
    #[schemars(range(max = MAX_TASK_DURATION_MS))]
    duration_ms: u64,
    #[schemars(range(min = 1))]
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    executed_at: i64,
    #[serde(deserialize_with = "required_option")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<TaskFailure>"
    )]
    failure: Option<TaskFailure>,
}
impl From<TaskDiagnostics> for DiagnosticsInput {
    fn from(value: TaskDiagnostics) -> Self {
        value.0
    }
}
impl TryFrom<DiagnosticsInput> for TaskDiagnostics {
    type Error = WireError;
    fn try_from(value: DiagnosticsInput) -> Result<Self, Self::Error> {
        Self::new(
            value.stdout,
            value.stderr,
            value.duration_ms,
            value.executed_at,
            value.failure,
        )
    }
}
impl TaskDiagnostics {
    /// Construct bounded diagnostic streams and timing evidence.
    pub fn new(
        stdout: String,
        stderr: String,
        duration_ms: u64,
        executed_at: i64,
        failure: Option<TaskFailure>,
    ) -> Result<Self, WireError> {
        if stdout.len() > MAX_TASK_DIAGNOSTIC_BYTES
            || stderr.len() > MAX_TASK_DIAGNOSTIC_BYTES
            || stdout.contains('\0')
            || stderr.contains('\0')
            || duration_ms > MAX_TASK_DURATION_MS
            || executed_at < 1
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(DiagnosticsInput {
            stdout,
            stderr,
            duration_ms,
            executed_at,
            failure,
        }))
    }
    /// Captured standard output after the Agent's secret-protection policy.
    pub fn stdout(&self) -> &str {
        &self.0.stdout
    }
    /// Captured standard error after the Agent's secret-protection policy.
    pub fn stderr(&self) -> &str {
        &self.0.stderr
    }
    /// Executor wall-clock duration in milliseconds.
    pub const fn duration_ms(&self) -> u64 {
        self.0.duration_ms
    }
    /// Unix timestamp in seconds when execution began.
    pub const fn executed_at(&self) -> i64 {
        self.0.executed_at
    }
    /// Executor failure classification, if any.
    pub const fn failure(&self) -> Option<TaskFailure> {
        self.0.failure
    }
}
/// Private validated execution result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "ResultInput", into = "ResultInput")]
pub struct TaskResult(ResultInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(transform = crate::runtime::tasks::result_constraints)]
struct ResultInput {
    #[serde(deserialize_with = "required_option")]
    #[schemars(required, schema_with = "crate::self_service::nullable_schema::<i32>")]
    exit_code: Option<i32>,
    quality: OutputQuality,
    output: Value,
    diagnostics: TaskDiagnostics,
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    collected_at: i64,
}
impl From<TaskResult> for ResultInput {
    fn from(value: TaskResult) -> Self {
        value.0
    }
}
impl TryFrom<ResultInput> for TaskResult {
    type Error = WireError;
    fn try_from(value: ResultInput) -> Result<Self, Self::Error> {
        Self::new(
            value.exit_code,
            value.quality,
            value.output,
            value.diagnostics,
            value.collected_at,
        )
    }
}
impl TaskResult {
    /// Construct coherent process evidence with a bounded structured output.
    pub fn new(
        exit_code: Option<i32>,
        quality: OutputQuality,
        output: Value,
        diagnostics: TaskDiagnostics,
        collected_at: i64,
    ) -> Result<Self, WireError> {
        let quality_is_coherent = match quality {
            OutputQuality::Complete => exit_code == Some(0) && diagnostics.failure().is_none(),
            OutputQuality::Failed => diagnostics.failure().is_some(),
            OutputQuality::Truncated => diagnostics.failure() == Some(TaskFailure::OutputLimit),
            OutputQuality::Partial => true,
        };
        let failure_is_coherent = match diagnostics.failure() {
            Some(TaskFailure::NonZeroExit) => exit_code.is_some_and(|code| code != 0),
            Some(TaskFailure::LaunchFailed) => exit_code.is_none(),
            _ => true,
        };
        if collected_at < diagnostics.executed_at()
            || !quality_is_coherent
            || !failure_is_coherent
            || serde_json::to_vec(&output)
                .map_err(|_| WireError::InvalidValue)?
                .len()
                > crate::runtime::OUTPUT_MAX_BYTES
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ResultInput {
            exit_code,
            quality,
            output,
            diagnostics,
            collected_at,
        }))
    }
    /// Agent-native timestamp of completed capture.
    pub const fn collected_at(&self) -> i64 {
        self.0.collected_at
    }
    /// Process exit code, if the process produced one.
    pub const fn exit_code(&self) -> Option<i32> {
        self.0.exit_code
    }
    /// Completeness of the captured output.
    pub const fn quality(&self) -> OutputQuality {
        self.0.quality
    }
    /// Parsed JSON output.
    pub const fn output(&self) -> &Value {
        &self.0.output
    }
    /// Bounded process diagnostics.
    pub const fn diagnostics(&self) -> &TaskDiagnostics {
        &self.0.diagnostics
    }
}
/// Private validated event envelope, with no client-asserted tenant/device/generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "EventInput", into = "EventInput")]
pub struct TaskEventRequest(EventInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventInput {
    #[schemars(schema_with = "crate::runtime::version_schema")]
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    operation_id: Uuid,
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    attempt_id: Uuid,
    event: TaskEvent,
    execution_context: SoftwareExecutionContext,
}
impl From<TaskEventRequest> for EventInput {
    fn from(v: TaskEventRequest) -> Self {
        v.0
    }
}
impl TryFrom<EventInput> for TaskEventRequest {
    type Error = WireError;
    fn try_from(v: EventInput) -> Result<Self, WireError> {
        if v.wire_version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        Self::new(v.operation_id, v.attempt_id, v.event, v.execution_context)
    }
}
impl TaskEventRequest {
    /// Validate a retry identity, attempt and bounded event.
    pub fn new(
        operation_id: Uuid,
        attempt_id: Uuid,
        event: TaskEvent,
        execution_context: SoftwareExecutionContext,
    ) -> Result<Self, WireError> {
        execution_context.validate()?;
        if operation_id.is_nil() || attempt_id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        if let TaskEvent::SoftwareResult(result) = &event {
            result.validate()?;
        }
        let input = EventInput {
            wire_version: WIRE_VERSION,
            operation_id,
            attempt_id,
            event,
            execution_context,
        };
        if serde_json::to_vec(&input)
            .map_err(|_| WireError::InvalidValue)?
            .len()
            > MAX_TASK_REQUEST_BYTES
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(input))
    }
    /// Exact current context included in the operation fingerprint.
    pub fn execution_context(&self) -> &SoftwareExecutionContext {
        &self.0.execution_context
    }
    /// Idempotent event identity.
    pub fn operation_id(&self) -> Uuid {
        self.0.operation_id
    }
    /// Attempt selected by the server's claim receipt.
    pub fn attempt_id(&self) -> Uuid {
        self.0.attempt_id
    }
    /// Exact evidence or requested transition.
    pub fn event(&self) -> &TaskEvent {
        &self.0.event
    }
}
/// Idempotent task poll. The server derives all identity from the credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "ClaimInput", into = "ClaimInput")]
pub struct TaskClaimRequest(ClaimInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimInput {
    #[schemars(schema_with = "crate::runtime::version_schema")]
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    operation_id: Uuid,
    #[schemars(extend("maxItems" = 4, "uniqueItems" = true, "items" = serde_json::json!({"enum":["power_shell7","posix_sh","bash","osquery"]})))]
    profiles: Vec<ExecutorProfile>,
    execution_context: SoftwareExecutionContext,
}
impl From<TaskClaimRequest> for ClaimInput {
    fn from(v: TaskClaimRequest) -> Self {
        v.0
    }
}
impl TryFrom<ClaimInput> for TaskClaimRequest {
    type Error = WireError;
    fn try_from(v: ClaimInput) -> Result<Self, WireError> {
        if v.wire_version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        Self::new(v.operation_id, v.profiles, v.execution_context)
    }
}
impl TaskClaimRequest {
    /// Construct one bounded poll with a stable retry identity.
    pub fn new(
        operation_id: Uuid,
        profiles: Vec<ExecutorProfile>,
        execution_context: SoftwareExecutionContext,
    ) -> Result<Self, WireError> {
        execution_context.validate()?;
        if operation_id.is_nil()
            || profiles.len() > 4
            || profiles
                .iter()
                .enumerate()
                .any(|(i, p)| profiles[..i].contains(p))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ClaimInput {
            wire_version: WIRE_VERSION,
            operation_id,
            profiles,
            execution_context,
        }))
    }
    /// Currently configured controlled executors; an empty list still receives cancellations.
    pub fn profiles(&self) -> &[ExecutorProfile] {
        &self.0.profiles
    }
    /// Exact current context included in the operation fingerprint.
    pub fn execution_context(&self) -> &SoftwareExecutionContext {
        &self.0.execution_context
    }
    /// Poll replay identity.
    pub fn operation_id(&self) -> Uuid {
        self.0.operation_id
    }
}
/// Fixed executor identity. There is no arbitrary command string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorProfile {
    /// PowerShell 7 on Windows.
    PowerShell7,
    /// POSIX sh on macOS.
    PosixSh,
    /// Bash on macOS.
    Bash,
    /// Bound query from a published read-only SQL template.
    Osquery,
}
/// Required operating-system execution identity.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIdentity {
    /// Service identity.
    System,
    /// Current logged-in user, without fallback.
    LoggedInUser,
}
/// Signed message purpose prevents reusing a received offer as execution permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskPermit {
    /// Content download and acknowledgement only.
    Offer,
    /// Start exactly this attempt before the signed expiry.
    Start,
}
/// Signed, exact content coordinates. The task route supplies download authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskContent {
    /// Expected byte count.
    #[schemars(extend("minimum" = 1, "maximum" = 16777216))]
    pub length: u64,
    /// SHA-256 of exact content bytes.
    pub sha256: [u8; 32],
}
/// Frozen executor inputs carried inside the signature; output semantics stay server-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(extend("allOf" = serde_json::json!([{"if":{"properties":{"profile":{"const":"osquery"}}},"then":{"required":["sqlParameters"],"properties":{"arguments":{"maxItems":0},"environment":{"maxProperties":0},"runAs":{"const":"system"},"sqlParameters":{"type":"object"}}},"else":{"properties":{"sqlParameters":{"type":"null"}}}}])))]
pub struct TaskSpec {
    /// Exact wire major.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Server-selected tenant.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Server-selected device identity.
    #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\p{Cc}]+$"))]
    pub device_id: String,
    /// Selected artifact operating system.
    pub platform: TaskPlatform,
    /// Selected artifact architecture.
    pub architecture: TaskArchitecture,
    /// Current registration at approval/claim.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration_id: Uuid,
    /// Registration generation.
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    pub generation: u64,
    /// Immutable run identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub task_id: Uuid,
    /// Exact execution attempt.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub attempt_id: Uuid,
    /// Signature purpose.
    pub permit: TaskPermit,
    /// Nonnegative Unix expiry, checked against a trusted clock by the consumer.
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    pub expires_at: i64,
    /// Exact Resource version digest, including its full execution interface.
    pub resource_digest: [u8; 32],
    /// Exact selected Resource coordinates.
    pub resource: super::TaskResource,
    /// Trusted server authorization decision.
    pub authorization: super::TaskAuthorization,
    /// Complete resolved values, covered by the task signature.
    #[schemars(extend("maxProperties" = 32, "propertyNames" = serde_json::json!({"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_]+$"}), "additionalProperties" = serde_json::json!({"anyOf":[{"type":"string","pattern":"^[^\\u0000]*$"},{"type":"boolean"},{"type":"integer","minimum":-9223372036854775808i64,"maximum":9223372036854775807i64}]})))]
    pub parameters: BTreeMap<String, Value>,
    /// Absolute Run deadline, independent of the permit expiry.
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    pub deadline: i64,
    /// Exact downloadable artifact.
    pub content: TaskContent,
    /// Fixed interpreter profile.
    pub profile: ExecutorProfile,
    /// Literal parameters for the signed SQL template artifact; no free-form query text.
    #[schemars(extend("maxProperties" = 32, "propertyNames" = serde_json::json!({"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-zA-Z0-9_]+$"}), "additionalProperties" = serde_json::json!({"oneOf":[{"type":"string","maxLength":4096,"pattern":"^[^\\u0000]*$"},{"type":"boolean"},{"type":"integer","minimum":-9223372036854775808i64,"maximum":9223372036854775807i64}]})))]
    pub sql_parameters: Option<BTreeMap<String, serde_json::Value>>,
    /// Required execution identity.
    pub run_as: ExecutionIdentity,
    /// Exact effect target covered by the same signature as the script inputs.
    pub execution_target: SoftwareExecutionTarget,
    /// Literal arguments, with no shell interpolation.
    #[schemars(extend("maxItems" = 64, "items" = serde_json::json!({"type":"string","minLength":0,"maxLength":65536,"pattern":"^[^\\u0000]*$"})))]
    pub arguments: Vec<String>,
    /// Only explicit product parameter variables.
    #[schemars(extend("maxProperties" = 32, "propertyNames" = serde_json::json!({"type":"string","minLength":11,"maxLength":64,"pattern":"^RSS_PARAM_[A-Za-z0-9_]+$"}), "additionalProperties" = serde_json::json!({"type":"string","minLength":0,"maxLength":65536,"pattern":"^[^\\u0000]*$"})))]
    pub environment: BTreeMap<String, String>,
    /// Wall-time limit.
    #[schemars(extend("minimum" = 1, "maximum" = 3600))]
    pub timeout_seconds: u32,
    /// Output byte budget.
    #[schemars(extend("minimum" = 1, "maximum" = 16777216))]
    pub output_bytes: u32,
    /// Maximum output rows.
    #[schemars(extend("minimum" = 1, "maximum" = 65535))]
    pub max_rows: u16,
}
impl TaskSpec {
    /// Validate the signed closed profile without authenticating it.
    pub fn validate(&self) -> Result<(), WireError> {
        self.authorization.validate(self.tenant_id)?;
        self.execution_target.validate_for(self.platform)?;
        match (&self.execution_target, self.run_as) {
            (SoftwareExecutionTarget::Device, ExecutionIdentity::System) => (),
            (
                SoftwareExecutionTarget::User {
                    identity,
                    session_id,
                },
                ExecutionIdentity::LoggedInUser,
            ) if !identity.is_empty() && !session_id.is_nil() => (),
            _ => return Err(WireError::InvalidValue),
        }

        if self.deadline < self.expires_at
            || self.parameters.len() > 32
            || serde_json::to_vec(&self.parameters)
                .map_err(|_| WireError::InvalidValue)?
                .len()
                > 65_536
            || self.parameters.values().any(|v| {
                !(v.is_string() || v.is_boolean() || v.as_i64().is_some())
                    || v.as_str().is_some_and(|s| s.contains('\0'))
            })
            || [
                &self.resource.id,
                &self.resource.version,
                &self.resource.variant,
            ]
            .iter()
            .any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                    || s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
            })
        {
            return Err(WireError::InvalidValue);
        }
        if self.wire_version != WIRE_VERSION
            || self.tenant_id.is_nil()
            || self.registration_id.is_nil()
            || self.task_id.is_nil()
            || self.attempt_id.is_nil()
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || matches!(
                (self.profile, self.platform),
                (ExecutorProfile::PowerShell7, TaskPlatform::Macos)
                    | (
                        ExecutorProfile::PosixSh | ExecutorProfile::Bash,
                        TaskPlatform::Windows
                    )
            )
            || self.device_id.is_empty()
            || self.device_id.len() > 1024
            || self.device_id.chars().any(char::is_control)
            || self.expires_at < 0
            || self.content.length == 0
            || self.content.length > 16_777_216
            || !(1..=3600).contains(&self.timeout_seconds)
            || !(1..=16_777_216).contains(&self.output_bytes)
            || self.max_rows == 0
            || self.arguments.len() > 64
            || self.environment.len() > 32
            || self
                .arguments
                .iter()
                .chain(self.environment.values())
                .any(|v| v.len() > 65_536 || v.contains('\0'))
            || self.environment.keys().any(|key| {
                !key.starts_with("RSS_PARAM_")
                    || key.len() <= 10
                    || key.len() > 64
                    || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            || (self.profile == ExecutorProfile::Osquery
                && (!self.arguments.is_empty()
                    || !self.environment.is_empty()
                    || self.sql_parameters.as_ref().is_none_or(|p| {
                        p.len() > 32
                            || !serde_json::to_vec(p).is_ok_and(|b| b.len() <= 65536)
                            || p.iter().any(|(k, v)| {
                                k.is_empty()
                                    || k.len() > 64
                                    || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                                    || match v {
                                        serde_json::Value::String(s) => {
                                            s.len() > 4096 || s.contains('\0')
                                        }
                                        serde_json::Value::Bool(_) => false,
                                        serde_json::Value::Number(n) => n.as_i64().is_none(),
                                        _ => true,
                                    }
                            })
                    })
                    || self.run_as != ExecutionIdentity::System))
            || (self.profile != ExecutorProfile::Osquery && self.sql_parameters.is_some())
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Exact domain-separated signed bytes. Keys and argument order are deterministic.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-agent-script-task-v1-ed25519\0".to_vec();
        bytes.extend((key_id.len() as u32).to_be_bytes());
        bytes.extend(key_id.as_bytes());
        bytes.extend(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?);
        if bytes.len() > 131_072 {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}
/// Software operation selected by the server; detection remains independent evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskIntent {
    /// Install the frozen version.
    Install,
    /// Detect the current local state without installation.
    Detect,
    /// Remove the owned installation using the approved removal definition.
    Uninstall,
}
/// Whether a signed task can start automatically or awaits trusted local user action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareStartMode {
    /// Policy-required task may start when offered and locally admitted.
    Automatic,
    /// Agent must wait for a local user choice before requesting Start.
    UserInitiated,
}
/// One exact artifact needed by an executable software step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskArtifact {
    /// Opaque task-local key in the content endpoint.
    #[schemars(extend("minLength" = 1, "maxLength" = 132, "pattern" = "^(?!\\.{1,2}(?:/|$))(?!.*\\/\\.{1,2}(?:/|$))[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"))]
    pub key: String,
    /// Exact byte count.
    #[schemars(extend("minimum" = 1, "maximum" = 1099511627776u64))]
    pub length: u64,
    /// Exact SHA-256 digest.
    pub sha256: [u8; 32],
}
/// Current executable values are maintained by the sole software wire owner.
#[path = "tasks/software.rs"]
mod software;
pub use software::*;
/// Permitted reboot handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskReboot {
    /// Reboot requirement fails the task.
    Forbid,
    /// Report required reboot for separate authorization.
    Report,
}
/// Exact downgrade permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTaskDowngrade {
    /// Block downgrade.
    Deny,
    /// Permit the exact approved downgrade.
    Allow,
}
/// A declared member of a bounded bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskBundleEntry {
    /// Uncompressed member size.
    #[schemars(extend("minimum" = 0, "maximum" = 1099511627776u64))]
    pub length: u64,
    /// Member content digest.
    pub sha256: [u8; 32],
}
/// Complete platform-bound bundle manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskBundle {
    /// Bundle schema major.
    #[schemars(extend("minimum" = 0, "maximum" = 4294967295u64))]
    pub schema: u32,
    /// Target operating system.
    pub platform: TaskPlatform,
    /// Target architecture.
    pub architecture: TaskArchitecture,
    /// Complete declared member set.
    #[schemars(extend("maxProperties" = 4096))]
    pub entries: BTreeMap<String, SoftwareTaskBundleEntry>,
}
/// Complete executable action. No independently selectable format or executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoftwareTaskAction {
    /// Exact ecosystem package identity.
    #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\p{Cc}]*$"))]
    pub package: String,
    /// Exact package version.
    #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\p{Cc}]*$"))]
    pub version: String,
    /// Format-specific closed executable plan.
    pub behavior: SoftwareTaskBehavior,
    /// Explicit signature requirements; empty allows unsigned content subject to OS prerequisites.
    #[schemars(extend("maxItems" = 64))]
    pub signatures: Vec<SoftwareTaskSignature>,
    /// Approved reboot reporting.
    pub reboot: SoftwareTaskReboot,
    /// Exact downgrade permission.
    pub downgrade: SoftwareTaskDowngrade,
}
impl SoftwareTaskAction {
    /// One concrete format/scope/execution-context capability; no generic fallback.
    pub fn required_profile(&self, platform: TaskPlatform) -> Option<super::Capability> {
        use super::Capability as C;
        use SoftwareTaskBehavior as B;
        use SoftwareTaskScope as S;
        if matches!(
            &self.behavior,
            B::Msi(_) | B::Winget(_) | B::Exe(_) | B::Msix(_)
        ) && platform != TaskPlatform::Windows
            || matches!(&self.behavior, B::Pkg(_) | B::Brew(_) | B::Dmg(_))
                && platform != TaskPlatform::Macos
        {
            return None;
        }
        let native = |scope: S, system: C, user: C| {
            Some(match scope {
                S::System => system,
                S::User => user,
            })
        };
        match &self.behavior {
            B::Msi(n) => native(n.scope, C::SoftwareMsiSystemV1, C::SoftwareMsiUserV1),
            B::Pkg(n) if n.scope == S::System => Some(C::SoftwarePkgSystemV1),
            B::Pkg(_) => None,
            B::Winget(n) => native(n.scope, C::SoftwareWingetSystemV1, C::SoftwareWingetUserV1),
            B::Brew(n) if n.scope == S::User => Some(C::SoftwareBrewBottleUserV1),
            B::Brew(_) => None,
            B::Exe(n) => native(n.scope, C::SoftwareExeSystemV1, C::SoftwareExeUserV1),
            B::Bundle(n) => Some(match (platform, n.install.invocation.run_as) {
                (TaskPlatform::Windows, ExecutionIdentity::System) => {
                    C::SoftwareBundleWindowsSystemV1
                }
                (TaskPlatform::Windows, ExecutionIdentity::LoggedInUser) => {
                    C::SoftwareBundleWindowsUserV1
                }
                (TaskPlatform::Macos, ExecutionIdentity::System) => C::SoftwareBundleMacosSystemV1,
                (TaskPlatform::Macos, ExecutionIdentity::LoggedInUser) => {
                    C::SoftwareBundleMacosUserV1
                }
            }),
            B::Dmg(n) => match (&n.payload, n.scope) {
                (SoftwareTaskDmgPayload::AppCopy { .. }, S::System) => {
                    Some(C::SoftwareDmgAppSystemV1)
                }
                (SoftwareTaskDmgPayload::AppCopy { .. }, S::User) => Some(C::SoftwareDmgAppUserV1),
                (SoftwareTaskDmgPayload::ContainedPkg { .. }, S::System) => {
                    Some(C::SoftwareDmgPkgSystemV1)
                }
                _ => None,
            },
            B::Msix(n) => Some(match n.deployment {
                SoftwareTaskMsixDeployment::TargetUserRegistration { .. } => {
                    C::SoftwareMsixRegistrationUserV1
                }
                SoftwareTaskMsixDeployment::DeviceProvisioning => {
                    C::SoftwareMsixProvisioningSystemV1
                }
            }),
        }
    }
    fn validate(&self) -> Result<(), WireError> {
        software::validate_action(self)
    }
}
/// One locally executable step; the server has already ordered fixed prerequisites.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskStep {
    /// Device action and independent detector without Catalog source or dependency graph.
    pub action: SoftwareTaskAction,
    /// Task-local artifacts for this step.
    #[schemars(extend("minItems" = 1, "maxItems" = 64))]
    pub artifacts: Vec<SoftwareTaskArtifact>,
    /// Frozen readonly native source or direct native artifact consumption.
    pub export: SoftwareTaskExport,
    /// Exact effect target and live login generation.
    pub target: SoftwareExecutionTarget,
}
/// Signed software task with ordered executable steps and no Policy or Catalog model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskSpec {
    /// Exact wire major.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Server-selected tenant.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant_id: Uuid,
    /// Server-selected device.
    #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\p{Cc}]+$"))]
    pub device_id: String,
    /// Target platform.
    pub platform: TaskPlatform,
    /// Target architecture.
    pub architecture: TaskArchitecture,
    /// Current registration.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration_id: Uuid,
    /// Registration generation.
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    pub generation: u64,
    /// Immutable run.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub task_id: Uuid,
    /// Exact attempt.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub attempt_id: Uuid,
    /// Offer or Start authority.
    pub permit: TaskPermit,
    /// Unix expiry.
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    pub expires_at: i64,
    /// Current execution environment, frozen across Offer and Start.
    pub execution_context: SoftwareExecutionContext,
    /// Same server-owned origin decision as script tasks, covered by the signature.
    pub authorization: super::TaskAuthorization,
    /// Ordered prerequisites followed by the requested action.
    #[schemars(extend("minItems" = 1, "maxItems" = 32))]
    pub steps: Vec<SoftwareTaskStep>,
    /// SHA-256 of canonical serialized steps.
    pub definition_digest: [u8; 32],
    /// Requested local operation.
    pub intent: SoftwareTaskIntent,
    /// Local start behavior; no Policy or rollout details are exposed.
    pub start_mode: SoftwareStartMode,
}
impl SoftwareTaskSpec {
    /// Validate all signed coordinates and the bounded, self-contained execution plan.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid_id = |s: &str, max: usize| {
            !s.is_empty()
                && s.len() <= max
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                && s.split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        };
        if self.wire_version != WIRE_VERSION
            || self.tenant_id.is_nil()
            || self.registration_id.is_nil()
            || self.task_id.is_nil()
            || self.attempt_id.is_nil()
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.expires_at < 0
            || self.device_id.is_empty()
            || self.device_id.len() > 1024
            || self.device_id.chars().any(char::is_control)
            || self.steps.is_empty()
            || self.steps.len() > 32
        {
            return Err(WireError::InvalidValue);
        }
        self.authorization.validate(self.tenant_id)?;
        let self_service = matches!(
            self.authorization,
            super::TaskAuthorization::SelfService { .. }
        );
        if (self.start_mode == SoftwareStartMode::UserInitiated) != self_service
            || (self_service
                && (self.intent != SoftwareTaskIntent::Install
                    || !matches!(
                        self.authorization,
                        super::TaskAuthorization::SelfService { risk_level: 2, .. }
                    )))
        {
            return Err(WireError::InvalidValue);
        }
        self.execution_context.validate_for(self.platform)?;
        let encoded = serde_json::to_vec(&self.steps).map_err(|_| WireError::InvalidValue)?;
        if encoded.len() > 4_194_304
            || sha2::Sha256::digest(&encoded).as_slice() != self.definition_digest
        {
            return Err(WireError::InvalidValue);
        }
        let mut keys = std::collections::BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            step.action.validate()?;
            step.target.validate_for(self.platform)?;
            if !matches!(
                (step.action.behavior.invocation().run_as, &step.target),
                (ExecutionIdentity::System, SoftwareExecutionTarget::Device)
                    | (
                        ExecutionIdentity::LoggedInUser,
                        SoftwareExecutionTarget::User { .. }
                    )
            ) || matches!(&step.action.behavior,SoftwareTaskBehavior::Msix(n) if matches!(n.deployment,SoftwareTaskMsixDeployment::TargetUserRegistration{target:SoftwareTaskUser::ActiveInteractive}))
            {
                return Err(WireError::InvalidValue);
            }
            software::validate_step(step, index, self.platform, self.architecture)?;
            step.export.validate_for(step, self.tenant_id)?;
            if step.artifacts.is_empty() || keys.len() + step.artifacts.len() > 64 {
                return Err(WireError::InvalidValue);
            }
            for artifact in &step.artifacts {
                if !valid_id(&artifact.key, 132)
                    || !artifact.key.starts_with(&format!("{index}/"))
                    || !keys.insert(&artifact.key)
                    || artifact.length == 0
                    || artifact.length > 1_099_511_627_776
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        Ok(())
    }
    /// Domain-separated bytes bound to the selected key.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-agent-software-task-v1-ed25519\0".to_vec();
        bytes.extend((key_id.len() as u32).to_be_bytes());
        bytes.extend(key_id.as_bytes());
        bytes.extend(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?);
        Ok(bytes)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum RawTaskPayload {
    Script(Box<TaskSpec>),
    Software(Box<SoftwareTaskSpec>),
    /// Standard MDM enrollment entry.
    Enrollment(crate::runtime::EnrollmentTaskSpec),
}
/// Validated immutable script or software task payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "RawTaskPayload", into = "RawTaskPayload")]
pub enum TaskPayload {
    /// Existing script task, upgraded to the current wire major.
    Script(Box<TaskSpec>),
    /// Approved software task.
    Software(Box<SoftwareTaskSpec>),
    /// Standard MDM enrollment entry.
    Enrollment(crate::runtime::EnrollmentTaskSpec),
}
impl TryFrom<RawTaskPayload> for TaskPayload {
    type Error = WireError;
    fn try_from(value: RawTaskPayload) -> Result<Self, Self::Error> {
        match value {
            RawTaskPayload::Script(v) => {
                v.signing_bytes("validation")?;
                Ok(Self::Script(v))
            }
            RawTaskPayload::Enrollment(v) => {
                v.signing_bytes("validation")?;
                Ok(Self::Enrollment(v))
            }
            RawTaskPayload::Software(v) => {
                v.signing_bytes("validation")?;
                Ok(Self::Software(v))
            }
        }
    }
}
impl From<TaskPayload> for RawTaskPayload {
    fn from(value: TaskPayload) -> Self {
        match value {
            TaskPayload::Script(v) => Self::Script(v),
            TaskPayload::Software(v) => Self::Software(v),
            TaskPayload::Enrollment(v) => Self::Enrollment(v),
        }
    }
}
impl TryFrom<TaskSpec> for TaskPayload {
    type Error = WireError;
    fn try_from(value: TaskSpec) -> Result<Self, WireError> {
        value.signing_bytes("validation")?;
        Ok(Self::Script(Box::new(value)))
    }
}
impl TryFrom<SoftwareTaskSpec> for TaskPayload {
    type Error = WireError;
    fn try_from(value: SoftwareTaskSpec) -> Result<Self, Self::Error> {
        value.signing_bytes("validation")?;
        Ok(Self::Software(Box::new(value)))
    }
}
impl TryFrom<crate::runtime::EnrollmentTaskSpec> for TaskPayload {
    type Error = WireError;
    fn try_from(value: crate::runtime::EnrollmentTaskSpec) -> Result<Self, Self::Error> {
        value.signing_bytes("validation")?;
        Ok(Self::Enrollment(value))
    }
}
impl TaskPayload {
    /// Exact task identity.
    pub fn task_id(&self) -> Uuid {
        match self {
            Self::Script(v) => v.task_id,
            Self::Software(v) => v.task_id,
            Self::Enrollment(v) => v.task_id,
        }
    }
    /// Exact attempt identity.
    pub fn attempt_id(&self) -> Uuid {
        match self {
            Self::Script(v) => v.attempt_id,
            Self::Software(v) => v.attempt_id,
            Self::Enrollment(v) => v.attempt_id,
        }
    }
    /// Signed expiry.
    pub fn expires_at(&self) -> i64 {
        match self {
            Self::Script(v) => v.expires_at,
            Self::Software(v) => v.expires_at,
            Self::Enrollment(v) => v.expires_at,
        }
    }
    /// Selected permission.
    pub fn permit(&self) -> TaskPermit {
        match self {
            Self::Script(v) => v.permit,
            Self::Software(v) => v.permit,
            Self::Enrollment(v) => v.permit,
        }
    }
    /// Exact operating system.
    pub fn platform(&self) -> TaskPlatform {
        match self {
            Self::Script(v) => v.platform,
            Self::Software(v) => v.platform,
            Self::Enrollment(v) => v.platform,
        }
    }
    /// Exact architecture.
    pub fn architecture(&self) -> TaskArchitecture {
        match self {
            Self::Script(v) => v.architecture,
            Self::Software(v) => v.architecture,
            Self::Enrollment(v) => v.architecture,
        }
    }
    /// Sign validated bytes for this task family.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        match self {
            Self::Script(v) => v.signing_bytes(key_id),
            Self::Software(v) => v.signing_bytes(key_id),
            Self::Enrollment(v) => v.signing_bytes(key_id),
        }
    }
}

/// Exact operating system of the selected immutable artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskPlatform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
}
/// Exact processor architecture of the selected artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskArchitecture {
    /// x86-64.
    X86_64,
    /// ARM64.
    Aarch64,
}
/// Ed25519 signature envelope. A trusted key must be selected by key ID out of band.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTask {
    /// Exact task inputs and authority coordinates.
    pub payload: TaskPayload,
    /// Key identifier from the configured trust set.
    #[schemars(extend("minLength" = 1, "maxLength" = 128))]
    pub key_id: String,
    /// Unpadded base64url 64-byte Ed25519 signature.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{85}[AQgw]$"))]
    pub signature: String,
}

pub(crate) fn result_constraints(schema: &mut schemars::Schema) {
    schema.insert("allOf".into(), serde_json::json!([{"if":{"properties":{"quality":{"const":"complete"}}},"then":{"properties":{"exitCode":{"const":0},"diagnostics":{"properties":{"failure":{"type":"null"}}}}}},{"if":{"properties":{"diagnostics":{"properties":{"failure":{"const":"non_zero_exit"}}}}},"then":{"properties":{"exitCode":{"type":"integer","not":{"const":0}}}}},{"if":{"properties":{"diagnostics":{"properties":{"failure":{"const":"launch_failed"}}}}},"then":{"properties":{"exitCode":{"type":"null"}}}},{"if":{"properties":{"quality":{"const":"failed"}}},"then":{"properties":{"diagnostics":{"properties":{"failure":{"type":"string"}}}}}},{"if":{"properties":{"quality":{"const":"truncated"}}},"then":{"properties":{"diagnostics":{"properties":{"failure":{"const":"output_limit"}}}}}}]));
}

fn cancellations<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<TaskCancellation>, D::Error> {
    let value = Vec::deserialize(d)?;
    if value.len() > MAX_TASK_CANCELLATIONS {
        return Err(serde::de::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
