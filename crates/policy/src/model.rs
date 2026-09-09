use rss_request_context::TenantId;
use std::{cmp::Ordering, fmt, num::NonZeroU64};

/// Policy-owned object identity, not a device-registration or authorization claim.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectKey {
    tenant: TenantId,
    value: String,
}
impl ObjectKey {
    pub fn new(tenant: TenantId, value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(PolicyError::InvalidKey);
        }
        Ok(Self { tenant, value })
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn value(&self) -> &str {
        &self.value
    }
}
impl Ord for ObjectKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), &self.value).cmp(&(other.tenant.octets(), &other.value))
    }
}
impl PartialOrd for ObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectKey")
            .field("tenant", &self.tenant.to_string())
            .field("value", &self.value)
            .finish()
    }
}

/// Immutable, caller-resolved content reference. Never a download URL or credential.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PayloadRef {
    object: ObjectKey,
    revision: NonZeroU64,
    digest: [u8; 32],
}
impl PayloadRef {
    pub fn new(object: ObjectKey, revision: u64, digest: [u8; 32]) -> Result<Self, PolicyError> {
        Ok(Self {
            object,
            revision: nonzero(revision)?,
            digest,
        })
    }
    pub fn object(&self) -> &ObjectKey {
        &self.object
    }
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
/// The implemented removal contract. No implicit cleanup/rollback is supported.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RemovalRule {
    CancelOutstandingRetainEffects,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version {
    policy: ObjectKey,
    number: NonZeroU64,
    payload: PayloadRef,
    removal: RemovalRule,
}
impl Version {
    pub fn new(
        policy: ObjectKey,
        number: u64,
        payload: PayloadRef,
        removal: RemovalRule,
    ) -> Result<Self, PolicyError> {
        if policy.tenant() != payload.object.tenant() {
            return Err(PolicyError::TenantMismatch);
        }
        Ok(Self {
            policy,
            number: nonzero(number)?,
            payload,
            removal,
        })
    }
    pub fn policy(&self) -> &ObjectKey {
        &self.policy
    }
    pub fn number(&self) -> u64 {
        self.number.get()
    }
    pub fn payload(&self) -> &PayloadRef {
        &self.payload
    }
    pub fn removal(&self) -> RemovalRule {
        self.removal
    }
}
/// Structured semantic identity: request IDs and evaluation time are not executions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExecutionKey {
    policy: ObjectKey,
    version: NonZeroU64,
    device: ObjectKey,
    action: Action,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Action {
    Apply,
}
impl ExecutionKey {
    pub(crate) fn new(version: &Version, device: ObjectKey) -> Self {
        Self {
            policy: version.policy.clone(),
            version: version.number,
            device,
            action: Action::Apply,
        }
    }
    pub fn policy(&self) -> &ObjectKey {
        &self.policy
    }
    pub fn version(&self) -> u64 {
        self.version.get()
    }
    pub fn device(&self) -> &ObjectKey {
        &self.device
    }
    pub fn action(&self) -> Action {
        self.action
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Progress {
    Planned,
    Running,
    Unknown,
    Succeeded,
    Failed,
    Cancelled,
}
impl Progress {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
/// Execution success is not verification of the device's actual effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Effect {
    Unverified,
    Unknown,
    VerifiedPresent,
    VerifiedAbsent,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExecutionRecord {
    version: Version,
    device: ObjectKey,
    progress: Progress,
    effect: Effect,
}
impl ExecutionRecord {
    pub fn new(
        version: Version,
        device: ObjectKey,
        progress: Progress,
        effect: Effect,
    ) -> Result<Self, PolicyError> {
        if version.policy.tenant() != device.tenant() {
            return Err(PolicyError::TenantMismatch);
        }
        Ok(Self {
            version,
            device,
            progress,
            effect,
        })
    }
    pub fn key(&self) -> ExecutionKey {
        ExecutionKey::new(&self.version, self.device.clone())
    }
    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn device(&self) -> &ObjectKey {
        &self.device
    }
    pub fn progress(&self) -> Progress {
        self.progress
    }
    pub fn effect(&self) -> Effect {
        self.effect
    }
}
pub(crate) fn nonzero(n: u64) -> Result<NonZeroU64, PolicyError> {
    NonZeroU64::new(n).ok_or(PolicyError::InvalidRevision)
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid object key")]
    InvalidKey,
    #[error("revision must be nonzero")]
    InvalidRevision,
    #[error("policy input contains a foreign tenant")]
    TenantMismatch,
    #[error("policy identity does not match")]
    PolicyMismatch,
    #[error("expected policy revision does not match")]
    RevisionConflict,
    #[error("policy revision overflow")]
    RevisionOverflow,
    #[error("invalid lifecycle transition or snapshot")]
    InvalidTransition,
    #[error("policy version is stale")]
    StaleVersion,
    #[error("immutable version contents conflict")]
    VersionConflict,
    #[error("immutable payload contents conflict")]
    PayloadConflict,
    #[error("target snapshot is incomplete")]
    IncompleteTargets,
    #[error("execution snapshots contradict each other")]
    ConflictingExecution,
}
