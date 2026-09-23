//! Strict task messages. Authentication and durable authority remain server responsibilities.
use super::{WIRE_VERSION, WireError, strict_uuid};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Maximum encoded task event, including a 1 MiB result and bounded envelope.
pub const MAX_TASK_REQUEST_BYTES: usize = 1_114_112;
/// Maximum cancellation coordinates returned by one task claim.
pub const MAX_TASK_CANCELLATIONS: usize = 128;

fn version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
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
/// Cancellation applies only to this exact task attempt; it asserts no rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskCancellation {
    /// Task identity.
    #[serde(with = "strict_uuid")]
    pub task_id: Uuid,
    /// Attempt to stop.
    #[serde(with = "strict_uuid")]
    pub attempt_id: Uuid,
}
/// Poll response; the offer still requires signature verification and a separate start permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskClaimResponse {
    /// Sole supported major.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// At most one offered task.
    pub task: Option<SignedTask>,
    /// Authenticated cancellation requests.
    pub cancellations: Vec<TaskCancellation>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawTaskClaimResponse {
    #[serde(deserialize_with = "version")]
    wire_version: u8,
    task: Option<SignedTask>,
    cancellations: Vec<TaskCancellation>,
}
impl<'de> Deserialize<'de> for TaskClaimResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawTaskClaimResponse::deserialize(deserializer)?;
        if raw.cancellations.len() > MAX_TASK_CANCELLATIONS {
            return Err(serde::de::Error::custom("too many task cancellations"));
        }
        Ok(Self {
            wire_version: raw.wire_version,
            task: raw.task,
            cancellations: raw.cancellations,
        })
    }
}
/// A durable event receipt. Acceptance alone cannot authorize process execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEventAck {
    /// Sole supported major.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// The event was durably accepted.
    #[serde(deserialize_with = "accepted")]
    pub accepted: bool,
    /// Only Start may return a freshly signed start permit.
    pub permit: Option<SignedTask>,
    /// Stop this attempt; execution effects may remain unknown.
    pub cancel_requested: bool,
}
/// A task receipt, start request, or bounded execution result; none proves applied state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    Result {
        /// Process exit code; absent if the process could not produce one.
        exit_code: Option<i32>,
        /// Completeness of the captured output.
        quality: OutputQuality,
        /// Parsed JSON output; raw diagnostics or secret-bearing stderr are excluded.
        output: Value,
    },
}
/// Output completeness controls whether collection facts may be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
/// Private validated event envelope, with no client-asserted tenant/device/generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EventInput", into = "EventInput")]
pub struct TaskEventRequest(EventInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventInput {
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    operation_id: Uuid,
    #[serde(with = "strict_uuid")]
    attempt_id: Uuid,
    event: TaskEvent,
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
        Self::new(v.operation_id, v.attempt_id, v.event)
    }
}
impl TaskEventRequest {
    /// Validate a retry identity, attempt and bounded event.
    pub fn new(operation_id: Uuid, attempt_id: Uuid, event: TaskEvent) -> Result<Self, WireError> {
        if operation_id.is_nil() || attempt_id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        if let TaskEvent::Result { output, .. } = &event
            && serde_json::to_vec(output)
                .map_err(|_| WireError::InvalidValue)?
                .len()
                > 1_048_576
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(EventInput {
            wire_version: WIRE_VERSION,
            operation_id,
            attempt_id,
            event,
        }))
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ClaimInput", into = "ClaimInput")]
pub struct TaskClaimRequest(ClaimInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimInput {
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    operation_id: Uuid,
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
        Self::new(v.operation_id)
    }
}
impl TaskClaimRequest {
    /// Construct one bounded poll with a stable retry identity.
    pub fn new(operation_id: Uuid) -> Result<Self, WireError> {
        if operation_id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ClaimInput {
            wire_version: WIRE_VERSION,
            operation_id,
        }))
    }
    /// Poll replay identity.
    pub fn operation_id(&self) -> Uuid {
        self.0.operation_id
    }
}
/// Fixed executor identity. There is no arbitrary command string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorProfile {
    /// PowerShell 7 on Windows.
    PowerShell7,
    /// POSIX sh on macOS.
    PosixSh,
    /// Bash on macOS.
    Bash,
    /// Fixed version-only osquery query.
    OsqueryInfoV1,
}
/// Required operating-system execution identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIdentity {
    /// Service identity.
    System,
    /// Current logged-in user, without fallback.
    LoggedInUser,
}
/// Signed message purpose prevents reusing a received offer as execution permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPermit {
    /// Content download and acknowledgement only.
    Offer,
    /// Start exactly this attempt before the signed expiry.
    Start,
}
/// Signed, exact content coordinates. The task route supplies download authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskContent {
    /// Expected byte count.
    pub length: u64,
    /// SHA-256 of exact content bytes.
    pub sha256: [u8; 32],
}
/// Frozen executor inputs carried inside the signature; output semantics stay server-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSpec {
    /// Exact wire major.
    pub wire_version: u8,
    /// Server-selected tenant.
    #[serde(with = "strict_uuid")]
    pub tenant_id: Uuid,
    /// Server-selected device identity.
    pub device_id: String,
    /// Selected artifact operating system.
    pub platform: TaskPlatform,
    /// Selected artifact architecture.
    pub architecture: TaskArchitecture,
    /// Current registration at approval/claim.
    #[serde(with = "strict_uuid")]
    pub registration_id: Uuid,
    /// Registration generation.
    pub generation: u64,
    /// Immutable run identity.
    #[serde(with = "strict_uuid")]
    pub task_id: Uuid,
    /// Exact execution attempt.
    #[serde(with = "strict_uuid")]
    pub attempt_id: Uuid,
    /// Signature purpose.
    pub permit: TaskPermit,
    /// Nonnegative Unix expiry, checked against a trusted clock by the consumer.
    pub expires_at: i64,
    /// Exact Resource version digest, including its full execution interface.
    pub resource_digest: [u8; 32],
    /// Exact downloadable artifact.
    pub content: TaskContent,
    /// Fixed interpreter profile.
    pub profile: ExecutorProfile,
    /// Required execution identity.
    pub run_as: ExecutionIdentity,
    /// Literal arguments, with no shell interpolation.
    pub arguments: Vec<String>,
    /// Only explicit product parameter variables.
    pub environment: BTreeMap<String, String>,
    /// Wall-time limit.
    pub timeout_seconds: u32,
    /// Output byte budget.
    pub output_bytes: u32,
    /// Maximum output rows.
    pub max_rows: u16,
}
impl TaskSpec {
    /// Validate the signed closed profile without authenticating it.
    pub fn validate(&self) -> Result<(), WireError> {
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
            || !(1..=1_048_576).contains(&self.output_bytes)
            || !(1..=1000).contains(&self.max_rows)
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
            || (self.profile == ExecutorProfile::OsqueryInfoV1
                && (!self.arguments.is_empty()
                    || !self.environment.is_empty()
                    || self.max_rows != 1
                    || self.run_as != ExecutionIdentity::System))
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
        let mut bytes = b"rss-mdm-agent-task-v2-ed25519\0".to_vec();
        bytes.extend((key_id.len() as u32).to_be_bytes());
        bytes.extend(key_id.as_bytes());
        bytes.extend(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?);
        if bytes.len() > 131_072 {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}
/// Validated immutable task payload. Deserialization rejects invalid budgets and coordinates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TaskSpec", into = "TaskSpec")]
pub struct TaskPayload(TaskSpec);
impl TryFrom<TaskSpec> for TaskPayload {
    type Error = WireError;
    fn try_from(value: TaskSpec) -> Result<Self, WireError> {
        value.signing_bytes("validation")?;
        Ok(Self(value))
    }
}
impl From<TaskPayload> for TaskSpec {
    fn from(value: TaskPayload) -> Self {
        value.0
    }
}
impl std::ops::Deref for TaskPayload {
    type Target = TaskSpec;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Exact operating system of the selected immutable artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPlatform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
}
/// Exact processor architecture of the selected artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskArchitecture {
    /// x86-64.
    X86_64,
    /// ARM64.
    Aarch64,
}
/// Ed25519 signature envelope. A trusted key must be selected by key ID out of band.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTask {
    /// Exact task inputs and authority coordinates.
    pub payload: TaskPayload,
    /// Key identifier from the configured trust set.
    pub key_id: String,
    /// Unpadded base64url 64-byte Ed25519 signature.
    pub signature: String,
}
/// Trusted local identity and key selection, never populated from the received message.
pub struct TaskVerification<'a> {
    /// Expected key identifier from the configured trust set.
    pub key_id: &'a str,
    /// Trusted Ed25519 public key.
    pub public_key: &'a [u8],
    /// Locally enrolled tenant.
    pub tenant_id: Uuid,
    /// Locally enrolled device identity.
    pub device_id: &'a str,
    /// Actual local operating system.
    pub platform: TaskPlatform,
    /// Actual local processor architecture.
    pub architecture: TaskArchitecture,
    /// Locally enrolled current registration.
    pub registration_id: Uuid,
    /// Locally enrolled generation.
    pub generation: u64,
    /// Task identity being accepted.
    pub task_id: Uuid,
    /// Attempt identity being accepted.
    pub attempt_id: Uuid,
    /// Required permission; an offer cannot authorize start.
    pub permit: TaskPermit,
    /// Trusted current Unix time.
    pub now: i64,
}
/// Authenticated payload for the exact local context. Only verification constructs this value.
pub struct VerifiedTask<'a>(&'a TaskPayload);
impl VerifiedTask<'_> {
    /// Borrow the verified immutable executor inputs.
    pub fn payload(&self) -> &TaskPayload {
        self.0
    }
}
impl SignedTask {
    /// Authenticate exact bytes, signing key identity, expiry and all local authority coordinates.
    pub fn verify(&self, context: &TaskVerification<'_>) -> Result<VerifiedTask<'_>, WireError> {
        let p = &self.payload;
        if self.key_id != context.key_id
            || context.now < 0
            || context.now >= p.expires_at
            || p.permit != context.permit
            || p.tenant_id != context.tenant_id
            || p.device_id != context.device_id
            || p.platform != context.platform
            || p.architecture != context.architecture
            || p.registration_id != context.registration_id
            || p.generation != context.generation
            || p.task_id != context.task_id
            || p.attempt_id != context.attempt_id
            || self.signature.len() != 86
        {
            return Err(WireError::InvalidValue);
        }
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| WireError::InvalidValue)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, context.public_key)
            .verify(&p.signing_bytes(&self.key_id)?, &signature)
            .map_err(|_| WireError::InvalidValue)?;
        Ok(VerifiedTask(p))
    }
}
