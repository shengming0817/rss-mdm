//! Signature and expected-coordinate assertions for backend delivery tests.
use base64::Engine;
use rss_mdm_agent_wire::runtime::*;
use uuid::Uuid;
/// Trusted local identity and key selection, never populated from the received message.
pub(crate) struct TaskVerification<'a> {
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
pub(crate) fn verify(signed: &SignedTask, context: &TaskVerification<'_>) -> Result<(), WireError> {
    let p = &signed.payload;
    let (tenant, device, registration, generation) = match p {
        TaskPayload::Collection(v) => (
            v.tenant_id,
            v.device_id.as_str(),
            v.registration_id,
            v.generation,
        ),
        TaskPayload::Script(v) => (
            v.tenant_id,
            v.device_id.as_str(),
            v.registration_id,
            v.generation,
        ),
        TaskPayload::Enrollment(v) => (
            v.tenant_id,
            v.device_id.as_str(),
            v.registration_id,
            v.generation,
        ),
        TaskPayload::Software(v) => (
            v.tenant_id,
            v.device_id.as_str(),
            v.registration_id,
            v.generation,
        ),
    };
    if signed.key_id != context.key_id
        || context.now < 0
        || context.now >= p.expires_at()
        || p.permit() != context.permit
        || tenant != context.tenant_id
        || device != context.device_id
        || p.platform() != context.platform
        || p.architecture() != context.architecture
        || registration != context.registration_id
        || generation != context.generation
        || p.task_id() != context.task_id
        || p.attempt_id() != context.attempt_id
        || signed.signature.len() != 86
    {
        return Err(WireError::InvalidValue);
    }
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| WireError::InvalidValue)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, context.public_key)
        .verify(&p.signing_bytes(&signed.key_id)?, &signature)
        .map_err(|_| WireError::InvalidValue)?;
    Ok(())
}
