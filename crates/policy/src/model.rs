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
    /// Bind an object, nonzero revision and caller-supplied 32-byte digest.
    /// Zero revision returns [`PolicyError::InvalidRevision`]. Does not fetch content
    /// or verify that the digest matches bytes.
    pub fn new(object: PayloadId, revision: u64, digest: [u8; 32]) -> Result<Self, PolicyError> {
        Ok(Self {
            object,
            revision: nonzero(revision)?,
            digest,
        })
    }
    /// Borrow the tenant-scoped payload identity.
    pub fn object(&self) -> &PayloadId {
        &self.object
    }
    /// Return the positive immutable payload revision.
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    /// Borrow the caller-supplied content digest.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
/// The implemented removal contract. No implicit cleanup/rollback is supported.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RemovalRule {
    /// Request cancellation of nonterminal work while preserving all recorded device effects.
    CancelOutstandingRetainEffects,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Immutable same-tenant policy version and payload reference; no device execution occurs.
pub struct Version {
    policy: PolicyId,
    number: NonZeroU64,
    payload: PayloadRef,
    removal: RemovalRule,
}
impl Version {
    /// Bind a positive policy version to a same-tenant payload.
    /// Returns [`PolicyError::TenantMismatch`] for a foreign payload and
    /// [`PolicyError::InvalidRevision`] for zero. Does not persist or publish the version.
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
    /// Borrow the owning policy identity.
    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
    /// Return the positive immutable policy version number.
    pub fn number(&self) -> u64 {
        self.number.get()
    }
    /// Borrow the exact immutable payload reference.
    pub fn payload(&self) -> &PayloadRef {
        &self.payload
    }
    /// Return the declared cancellation/effect-retention rule.
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
/// Action component of the stable semantic execution identity.
pub enum Action {
    /// Apply the version's payload; cancellation is a separate planning intent.
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
    /// Borrow the policy identity in the execution key.
    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
    /// Return the positive policy version in the execution key.
    pub fn version(&self) -> u64 {
        self.version.get()
    }
    /// Borrow the exact target device identity.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    /// Return the semantic action, independent of requests or evaluation time.
    pub fn action(&self) -> Action {
        self.action
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Caller-reported execution progress, independent of verified device effects.
pub enum Progress {
    /// Execution has been planned but not reported running.
    Planned,
    /// Execution is reported in progress.
    Running,
    /// Execution outcome is unresolved; existence suppresses another automatic Add.
    Unknown,
    /// Execution is reported successful; this does not imply a verified present effect.
    Succeeded,
    /// Execution is reported failed; no implicit retry is authorized.
    Failed,
    /// Execution is reported cancelled; existing external effects may remain.
    Cancelled,
}
impl Progress {
    /// Whether progress is Succeeded, Failed or Cancelled; Unknown is nonterminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
/// Execution success is not verification of the device's actual effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Effect {
    /// No verification of the device effect has been supplied.
    Unverified,
    /// Verification cannot currently establish whether the effect is present.
    Unknown,
    /// The caller attests verification that the intended effect is present.
    VerifiedPresent,
    /// The caller attests verification that the intended effect is absent.
    VerifiedAbsent,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Caller-attested execution and effect facts for one exact policy version/device.
/// Construction checks tenant agreement, not authenticity or a valid progress history.
pub struct ExecutionRecord {
    version: Version,
    device: DeviceId,
    progress: Progress,
    effect: Effect,
}
impl ExecutionRecord {
    /// Record supplied facts after checking version/device tenant agreement.
    /// A mismatch returns [`PolicyError::TenantMismatch`]. Progress and effect are
    /// independent assertions; the caller must authenticate and verify their evidence.
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
    /// Derive the stable policy/version/device/action execution identity.
    pub fn key(&self) -> ExecutionKey {
        ExecutionKey::new(&self.version, self.device.clone())
    }
    /// Borrow the full immutable version represented by this execution.
    pub fn version(&self) -> &Version {
        &self.version
    }
    /// Borrow the device to which these facts apply.
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    /// Return reported execution progress without inferring effect presence.
    pub fn progress(&self) -> Progress {
        self.progress
    }
    /// Return the independently reported effect verification state.
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
    /// The execution version is owned by a foreign tenant.
    TenantMismatch,
    #[error("execution belongs to another policy")]
    /// The execution version belongs to another policy.
    PolicyMismatch,
    #[error("execution version is newer than the policy")]
    /// The execution version exceeds the latest policy version.
    FutureVersion {
        /// Latest version allowed by the policy snapshot.
        latest: u64,
    },
    #[error("execution version contents conflict")]
    /// Repeated policy version numbers carry different immutable content.
    VersionConflict,
    #[error("execution payload contents conflict")]
    /// Repeated payload identity/revision pairs carry different digests.
    PayloadConflict {
        /// Payload identity whose immutable content conflicts.
        object: PayloadId,
        /// Payload revision reused with a different digest.
        revision: u64,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed rejection of policy lifecycle or planning input; no external effects are performed.
pub enum PolicyError {
    #[error("stream input count overflow")]
    /// An input stream exceeded the representable record count; never wraps.
    InputCountOverflow,
    #[error("invalid object key")]
    /// A role/device identifier violates its constructor's character or byte-length limits.
    InvalidKey,
    #[error("revision must be nonzero")]
    /// A version or snapshot revision that must be positive is zero.
    InvalidRevision,
    #[error("policy input contains a foreign tenant")]
    /// An input belongs to another tenant.
    TenantMismatch,
    #[error("policy identity does not match")]
    /// A version belongs to a different policy.
    PolicyMismatch,
    #[error("expected policy revision does not match")]
    /// The expected revision differs from the in-memory policy revision.
    RevisionConflict {
        /// Revision supplied by the caller.
        expected: u64,
        /// Revision held by the policy snapshot.
        actual: u64,
    },
    #[error("policy revision overflow")]
    /// Advancing the policy revision would overflow `u64`.
    RevisionOverflow,
    #[error("invalid lifecycle transition or snapshot")]
    /// The requested operation is not allowed from the current lifecycle state.
    InvalidTransition {
        /// Lifecycle state that caused rejection.
        status: crate::Status,
        /// Requested lifecycle operation.
        operation: crate::TransitionKind,
    },
    #[error("invalid policy snapshot")]
    /// Stored status/revision/version presence is inconsistent.
    InvalidSnapshot {
        /// Lifecycle state that caused rejection.
        status: crate::Status,
        /// Stored aggregate revision inconsistent with its state.
        revision: u64,
    },
    #[error("policy version is stale")]
    /// Activation did not provide a strictly newer version.
    StaleVersion {
        /// Activation version requested by the caller.
        requested: u64,
        /// Latest version already held by the policy.
        latest: u64,
    },
    #[error("immutable version contents conflict")]
    /// An immutable version number was reused with changed content.
    VersionConflict {
        /// Immutable policy version number reused with changed content.
        version: u64,
    },
    #[error("immutable payload contents conflict")]
    /// An immutable payload identity/revision was reused with a different digest.
    PayloadConflict {
        /// Payload identity whose immutable content conflicts.
        object: PayloadId,
        /// Payload revision reused with a different digest.
        revision: u64,
    },
    #[error("{reason}")]
    /// An execution fact fails policy, tenant, version or payload validation.
    InvalidExecution {
        /// Stable identity of the rejected execution.
        execution: Box<ExecutionKey>,
        /// Closed cause of rejection for that identity.
        reason: ExecutionFailure,
    },
}
