//! Agent enrollment API v1, independent of runtime payload versions.
use crate::runtime::{
    Capability, Secret, SoftwareExecutionContext, TaskArchitecture, TaskPlatform,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported enrollment API version.
pub const API_VERSION: u8 = 1;
/// Canonical enrollment schema manifest.
pub const SCHEMA_FINGERPRINT: &str =
    "398717eb37090a417234758ec0e5ef9c87a86b1fa4fcd85bc3b65022c6746a6d";
/// Canonical enrollment schema manifest.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/enroll/manifest.json");
/// A bounded runtime profile, frozen when a grant is consumed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProfile {
    /// Runtime capability profile; independent of enrollment version.
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
/// A user download grant or an unauthenticated client authorization request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Caller-selected stable request and retry identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Caller-generated secret, delivered in protected bootstrap material.
    pub secret: Secret,
    /// Requested platform, fixed by authorization.
    pub platform: TaskPlatform,
    /// Optional shorter lifetime; tenant policy remains the upper bound.
    pub lifetime_seconds: Option<u32>,
    /// Base64 DER CSR; required for a client browser-authorization request.
    pub csr: Option<String>,
}
/// Persisted authorization lifecycle.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantReceipt {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Server-held request/grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub grant_id: Uuid,
    /// Current authorization state.
    pub state: GrantState,
    /// Original authorization deadline, Unix seconds.
    pub expires_at: i64,
    /// Authorized platform.
    pub platform: TaskPlatform,
}
/// Consume a grant for exactly one CSR and runtime profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Stable signing operation; do not replace after unknown results.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Authorized grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub grant_id: Uuid,
    /// Bootstrap secret; never a runtime credential.
    pub secret: Secret,
    /// Base64 DER CSR signed by the locally held key.
    pub csr: String,
    /// Exact runtime profile frozen by this operation.
    pub runtime: RuntimeProfile,
}
/// A durable certificate candidate; not an active device identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Candidate {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Fixed server signing attempt identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub issuance_id: Uuid,
    /// Original client signing operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Leaf-first base64 DER chain, already validated by the server.
    pub certificate_chain: Vec<String>,
    /// The original grant deadline; a long certificate does not extend it.
    pub activate_before: i64,
}
/// Presented over real candidate mTLS to activate that exact certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Persisted candidate identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub issuance_id: Uuid,
    /// Stable activation retry identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
}
/// Durable activation result, including an independently versioned runtime binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationReceipt {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Exact activated issuance.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub issuance_id: Uuid,
    /// Activation operation identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Runtime binding and collection definitions selected by the server.
    pub runtime: crate::runtime::BindingProfile,
}
/// Poll only the request identified by the secret and original operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusRequest {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Grant identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub grant_id: Uuid,
    /// Original creation operation identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Polling/bootstrap secret.
    pub secret: Secret,
}
/// Signing and activation progress for an authorized caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Progress {
    /// Authorization progress.
    pub grant: GrantReceipt,
    /// Persisted signing attempt, when consumed.
    #[serde(deserialize_with = "optional_uuid")]
    pub issuance_id: Option<Uuid>,
    /// Signing is unknown; retry/status never causes another CA request.
    pub issuance_unknown: bool,
    /// Already committed activation result, if any.
    #[serde(deserialize_with = "required_nullable")]
    pub activation: Option<ActivationReceipt>,
}
/// Administrator attaches the original CA result to a persisted unknown attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverIssuance {
    /// Enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Idempotent administrative operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Original base64 DER certificate chain obtained from the CA.
    pub certificate_chain: Vec<String>,
}
/// Closed lifecycle errors, distinct from runtime payload errors.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorBody {
    /// Closed error category.
    pub code: ErrorCode,
    /// Original signing attempt when a CA result is unknown.
    #[serde(deserialize_with = "optional_uuid")]
    pub issuance_id: Option<Uuid>,
}

/// An exact native installation requests bootstrap authority, never an active credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeGrantRequest {
    /// Independent enrollment API version.
    #[serde(deserialize_with = "version")]
    pub wire_version: u8,
    /// Stable bootstrap operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub operation_id: Uuid,
    /// Frozen, dispatched native installation.
    #[serde(with = "crate::runtime::strict_uuid")]
    pub installation_operation: Uuid,
    /// Agent-generated one-time secret.
    pub secret: Secret,
    /// Locally held key's base64 DER CSR.
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

/// Secret-free preview of the exact CSR a browser user is approving.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationRequest {
    /// Current request state and deadline.
    pub grant: GrantReceipt,
    /// SHA-256 of the verified CSR public key, encoded as lowercase hexadecimal.
    pub public_key_fingerprint: String,
}

fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
fn optional_uuid<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Uuid>, D::Error> {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Strict(#[serde(with = "crate::runtime::strict_uuid")] Uuid);
    Ok(Option::<Strict>::deserialize(d)?.map(|v| v.0))
}
