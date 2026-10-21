//! Agent enrollment API v1, independent of runtime payload versions.
/// Complete reusable configuration and fixed installation contracts.
pub mod configuration;
use crate::runtime::{
    Capability, Secret, SoftwareExecutionContext, TaskArchitecture, TaskPlatform,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported enrollment API version.
pub const API_VERSION: u8 = 1;
/// Canonical enrollment schema manifest.
pub const SCHEMA_FINGERPRINT: &str =
    "50aa50fee734ded419a72a7a4b7c8fd61b6420f343f3a5e02e21fddbcd821b15";
/// Canonical enrollment schema manifest.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/enroll/manifest.json");
/// A bounded runtime profile, frozen when a grant is consumed.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProfile {
    /// Runtime capability profile; independent of enrollment version.
    #[schemars(length(min = 1, max = 20), extend("uniqueItems" = true))]
    pub capabilities: Vec<Capability>,
    /// Operating system asserted by the client.
    pub platform: TaskPlatform,
    /// Processor architecture asserted by the client.
    pub architecture: TaskArchitecture,
    /// Current execution environment.
    pub execution_context: SoftwareExecutionContext,
}
impl RuntimeProfile {
    /// Validate exactly the currently supported runtime capability profile.
    pub fn validate(&self) -> Result<(), crate::runtime::WireError> {
        if !crate::runtime::supported_capabilities(&self.capabilities) {
            return Err(crate::runtime::WireError::InvalidValue);
        }
        self.execution_context.validate_for(self.platform)
    }
}
/// CSR-bound machine materials for user authorization, renewal or recovery.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Caller-selected stable request and retry identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Caller-generated secret, delivered in protected bootstrap material.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{43}$"))]
    pub secret: Secret,
    /// Requested platform, fixed by authorization.
    pub platform: TaskPlatform,
    /// Base64 DER CSR signed by the locally held machine key.
    #[schemars(extend("minLength" = 1, "maxLength" = 43692))]
    pub csr: String,
}
/// Persisted authorization lifecycle.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Waiting for an authenticated user to approve the exact client request.
    Pending,
    /// Authorized and not yet consumed.
    Available,
    /// Bound to one certificate operation and public key.
    Consumed,
    /// Explicitly cancelled or revoked.
    Revoked,
    /// Original authorization deadline has elapsed.
    Expired,
}
/// Public progress; never includes the bootstrap secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantReceipt {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Server-held request/grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub grant_id: Uuid,
    /// Current authorization state.
    pub state: GrantState,
    /// Original authorization deadline, Unix seconds.
    #[schemars(extend("minimum" = 1))]
    pub expires_at: i64,
    /// Authorized platform.
    pub platform: TaskPlatform,
}
/// Consume a grant for exactly one CSR and runtime profile.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Stable signing operation; do not replace after unknown results.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Authorized grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub grant_id: Uuid,
    /// Bootstrap secret; never a runtime credential.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{43}$"))]
    pub secret: Secret,
    /// Base64 DER CSR signed by the locally held key.
    #[schemars(extend("minLength" = 1, "maxLength" = 43692))]
    pub csr: String,
    /// Exact runtime profile frozen by this operation.
    pub runtime: RuntimeProfile,
}
/// A durable certificate candidate; not an active device identity.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Fixed server signing attempt identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub issuance_id: Uuid,
    /// Original client signing operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Leaf-first base64 DER chain, already validated by the server.
    #[schemars(extend("minItems" = 1, "maxItems" = 4, "items" = serde_json::json!({"type":"string","minLength":1,"maxLength":43692})))]
    pub certificate_chain: Vec<String>,
    /// The original grant deadline; a long certificate does not extend it.
    #[schemars(extend("minimum" = 1))]
    pub activate_before: i64,
}
/// Presented over real candidate mTLS to activate that exact certificate.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Persisted candidate identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub issuance_id: Uuid,
    /// Stable activation retry identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
}
/// Durable activation result, including an independently versioned runtime binding.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationReceipt {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Exact activated issuance.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub issuance_id: Uuid,
    /// Activation operation identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Runtime binding and collection definitions selected by the server.
    pub runtime: crate::runtime::BindingProfile,
}
/// Poll only the request identified by the secret and original operation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub grant_id: Uuid,
    /// Original creation operation identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Polling/bootstrap secret.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{43}$"))]
    pub secret: Secret,
}
/// Find only an already committed renewal grant after its response was lost.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalStatusRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Original renewal grant operation; querying never creates a grant.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Original protected bootstrap secret, independent of the old mTLS identity.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"))]
    pub secret: Secret,
}
/// Signing and activation progress for an authorized caller.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Progress {
    /// Authorization progress.
    pub grant: GrantReceipt,
    /// Persisted signing attempt, when consumed.
    #[serde(deserialize_with = "optional_uuid")]
    #[schemars(required, schema_with = "crate::runtime::nullable_uuid_schema")]
    pub issuance_id: Option<Uuid>,
    /// Signing is unknown; retry/status never causes another CA request.
    pub issuance_unknown: bool,
    /// Already committed activation result, if any.
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<ActivationReceipt>"
    )]
    pub activation: Option<ActivationReceipt>,
}
/// Administrator attaches the original CA result to a persisted unknown attempt.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverIssuance {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Idempotent administrative operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Original base64 DER certificate chain obtained from the CA.
    #[schemars(extend("minItems" = 1, "maxItems" = 4, "items" = serde_json::json!({"type":"string","minLength":1,"maxLength":43692})))]
    pub certificate_chain: Vec<String>,
}
/// Closed lifecycle errors, distinct from runtime payload errors.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Invalid or unsupported enrollment request.
    MalformedRequest,
    /// Bootstrap material or transport identity is invalid.
    InvalidIdentity,
    /// Current authorization does not permit this operation.
    PermissionDenied,
    /// Grant was explicitly revoked.
    GrantRevoked,
    /// Grant expired before activation.
    GrantExpired,
    /// New enrollment is paused; preserve the original operation and expiry.
    EnrollmentPaused,
    /// Per-user registration capacity is exhausted.
    RegistrationLimit,
    /// The same operation was reused for different content/key.
    OperationConflict,
    /// Original CA signing result is unknown.
    IssuanceUnknown,
    /// Activation transaction settlement is unknown.
    ActivationUnknown,
    /// Runtime registration or credential is revoked.
    CredentialRevoked,
    /// Certificate expired.
    CertificateExpired,
    /// Credential was retired by a later activation.
    CredentialRetired,
    /// Required persistence, audit or CA is unavailable.
    ServiceUnavailable,
}
/// Enrollment error projection, without internal diagnostic values.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorBody {
    /// Closed error category.
    pub code: ErrorCode,
    /// Original signing attempt when a CA result is unknown.
    #[serde(deserialize_with = "optional_uuid")]
    #[schemars(required, schema_with = "crate::runtime::nullable_uuid_schema")]
    pub issuance_id: Option<Uuid>,
}

/// An exact native installation requests bootstrap authority, never an active credential.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeGrantRequest {
    /// Independent enrollment API version.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "crate::runtime::version_schema")]
    pub wire_version: u8,
    /// Stable bootstrap operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Frozen, dispatched native installation.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub installation_operation: Uuid,
    /// Agent-generated one-time secret.
    #[schemars(extend("pattern" = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"))]
    pub secret: Secret,
    /// Locally held key's base64 DER CSR.
    #[schemars(extend("minLength" = 1, "maxLength" = 43692))]
    pub csr: String,
    /// Runtime profile, fixed through signing and activation.
    pub runtime: RuntimeProfile,
}
impl NativeGrantRequest {
    /// Parse a closed versioned native grant request.
    pub fn decode(bytes: &[u8]) -> Result<Self, ErrorCode> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::MalformedRequest)?;
        value.validate().map_err(|_| ErrorCode::MalformedRequest)?;
        Ok(value)
    }
    /// Validate producer-created requests as well as parsed input.
    pub fn validate(&self) -> Result<(), crate::runtime::WireError> {
        if self.wire_version != API_VERSION
            || self.operation_id.is_nil()
            || self.installation_operation.is_nil()
            || self.csr.len() > 43692
        {
            return Err(crate::runtime::WireError::InvalidValue);
        }
        self.runtime.validate()
    }
}

fn version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let v = u8::deserialize(d)?;
    if v != API_VERSION {
        return Err(serde::de::Error::custom(
            "unsupported enrollment API version",
        ));
    }
    Ok(v)
}

fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
fn optional_uuid<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Uuid>, D::Error> {
    #[derive(Deserialize, schemars::JsonSchema)]
    #[serde(transparent)]
    struct Strict(
        #[serde(with = "crate::runtime::strict_uuid")]
        #[schemars(schema_with = "crate::runtime::uuid_schema")]
        Uuid,
    );
    Ok(Option::<Strict>::deserialize(d)?.map(|v| v.0))
}

/// Exchange a started signed enrollment task for one short-lived OS handoff.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentRequest {
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    /// Stable exchange operation retained across unknown results.
    pub operation_id: Uuid,
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    /// Exact started task attempt.
    pub attempt_id: Uuid,
    /// Locally generated handoff secret; preserved for exact retry, never in a URL.
    pub password: Secret,
}
/// Non-secret native protocol coordinates. Opening the entry is not completion.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentReceipt {
    /// Server-owned native registration request.
    pub enrollment_id: Uuid,
    /// Original handoff deadline in Unix seconds.
    pub expires_at: i64,
    /// Standard OS entry fixed by the organization.
    pub entry: crate::runtime::EnrollmentEntry,
    /// Windows protocol username; absent on macOS.
    pub username: Option<String>,
    /// macOS profile POST location; absent on Windows.
    pub profile_url: Option<String>,
}
