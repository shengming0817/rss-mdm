use crate::{DeviceId, PayloadId, PolicyId};
use std::num::NonZeroU64;

/// Immutable, caller-resolved content reference. Never a download URL or credential.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PayloadRef {
    object: PayloadId,
    revision: NonZeroU64,
    digest: [u8; 32],
}
impl PayloadRef {
    pub fn new(object: PayloadId, revision: u64, digest: [u8; 32]) -> Result<Self, PolicyError> {
        Ok(Self {
            object,
            revision: nonzero(revision)?,
            digest,
        })
    }
    pub fn object(&self) -> &PayloadId {
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
    policy: PolicyId,
    number: NonZeroU64,
    payload: PayloadRef,
    removal: RemovalRule,
}
impl Version {
    pub fn new(
        policy: PolicyId,
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
    pub fn policy(&self) -> &PolicyId {
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
    policy: PolicyId,
    version: NonZeroU64,
    device: DeviceId,
    action: Action,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Action {
    Apply,
}
impl ExecutionKey {
    pub(crate) fn new(version: &Version, device: DeviceId) -> Self {
        Self {
            policy: version.policy.clone(),
            version: version.number,
            device,
            action: Action::Apply,
        }
    }
    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
    pub fn version(&self) -> u64 {
        self.version.get()
    }
    pub fn device(&self) -> &DeviceId {
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
    device: DeviceId,
    progress: Progress,
    effect: Effect,
}
impl ExecutionRecord {
    pub fn new(
        version: Version,
        device: DeviceId,
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
    pub fn device(&self) -> &DeviceId {
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
/// Closed reasons for rejecting an execution fact; the enclosing error retains its key.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutionFailure {
    #[error("execution belongs to a foreign tenant")]
    TenantMismatch,
    #[error("execution belongs to another policy")]
    PolicyMismatch,
    #[error("execution version is newer than the policy")]
    FutureVersion { latest: u64 },
    #[error("execution version contents conflict")]
    VersionConflict,
    #[error("execution payload contents conflict")]
    PayloadConflict { object: PayloadId, revision: u64 },
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
    RevisionConflict { expected: u64, actual: u64 },
    #[error("policy revision overflow")]
    RevisionOverflow,
    #[error("invalid lifecycle transition or snapshot")]
    InvalidTransition {
        status: crate::Status,
        operation: crate::TransitionKind,
    },
    #[error("invalid policy snapshot")]
    InvalidSnapshot {
        status: crate::Status,
        revision: u64,
    },
    #[error("policy version is stale")]
    StaleVersion { requested: u64, latest: u64 },
    #[error("immutable version contents conflict")]
    VersionConflict { version: u64 },
    #[error("immutable payload contents conflict")]
    PayloadConflict { object: PayloadId, revision: u64 },
    #[error("target snapshot is incomplete")]
    IncompleteTargets,
    #[error("{reason}")]
    InvalidExecution {
        execution: Box<ExecutionKey>,
        reason: ExecutionFailure,
    },
    #[error("execution snapshots contradict each other")]
    ConflictingExecution { execution: ExecutionKey },
}
