use crate::{
    DeviceId, ExecutionFailure, ExecutionKey, ExecutionRecord, PayloadId, PayloadRef, Policy,
    PolicyError, Status, Version,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// An intended semantic execution and its exact payload, without dispatch authority.
pub struct DesiredExecution {
    key: ExecutionKey,
    payload: PayloadRef,
}
impl DesiredExecution {
    fn new(version: &Version, target: DeviceId) -> Self {
        Self {
            key: ExecutionKey::new(version, target),
            payload: version.payload().clone(),
        }
    }
    /// Borrow the stable policy/version/device/action identity.
    pub fn key(&self) -> &ExecutionKey {
        &self.key
    }
    /// Borrow the immutable content reference to be applied.
    pub fn payload(&self) -> &PayloadRef {
        &self.payload
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Why an existing execution fact remains in the plan.
pub enum RetainReason {
    /// Execution belongs to the current version and target set.
    Current,
    /// Current execution is retained while Apply scheduling is paused.
    Paused,
    /// Terminal execution is preserved after archival, scope exit or supersession.
    Historical,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Why outstanding execution work should be cancelled without reverting effects.
pub enum CancelReason {
    /// The device is absent from the complete current target set.
    ScopeExit,
    /// The policy has been archived.
    Archived,
    /// A different current policy version replaces this execution's version.
    Superseded,
}
/// Intents never rewrite the supplied execution/effect facts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Intent {
    /// Preserve the supplied execution and effect facts.
    Retain {
        /// Existing facts retained without rewriting progress or effect evidence.
        execution: ExecutionRecord,
        /// Reason the facts are retained.
        reason: RetainReason,
    },
    /// Request cancellation of nonterminal work; this does not undo external effects.
    Cancel {
        /// Existing facts retained without rewriting progress or effect evidence.
        execution: ExecutionRecord,
        /// Reason cancellation should be requested.
        reason: CancelReason,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Versioned stream digest of policy, target and execution semantics; request/time metadata is excluded.
/// The digest is an identity, not authentication or proof of a persisted plan.
pub struct PlanId(pub(crate) [u8; 32]);
impl PlanId {
    /// Reconstruct a stored digest; does not authenticate its plan inputs.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow the raw 32-byte semantic plan digest.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Summary obtained by streaming one device's immutable execution history.
/// Current takes precedence over Previous; any current progress suppresses re-addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPresence {
    /// No execution record exists for this device and policy.
    Absent,
    /// Only earlier policy versions have execution records.
    Previous,
    /// An execution for the current version already exists.
    Current,
}
/// A desired action without materializing all prior execution keys. A Supersede
/// links to the frozen history; consumers enumerate those links through pages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredIntent {
    /// First desired execution for this device.
    Add(DesiredExecution),
    /// Replacement desired execution with historical predecessors.
    Supersede(DesiredExecution),
}
/// Decide one target using bounded history evidence. Produces intentions only;
/// saving them does not create execution facts or grant execution authority.
pub fn desired_for_device(
    policy: &Policy,
    device: &DeviceId,
    targeted: bool,
    history: ExecutionPresence,
) -> Result<Option<DesiredIntent>, PolicyError> {
    if device.tenant() != policy.key().tenant() {
        return Err(PolicyError::TenantMismatch);
    }
    if !targeted || policy.status() != Status::Active || history == ExecutionPresence::Current {
        return Ok(None);
    }
    let Some(version) = policy.version() else {
        return Ok(None);
    };
    let desired = DesiredExecution::new(version, device.clone());
    Ok(Some(match history {
        ExecutionPresence::Previous => DesiredIntent::Supersede(desired),
        _ => DesiredIntent::Add(desired),
    }))
}
/// Validate and classify one execution fact. The persistence owner additionally
/// enforces cross-record immutable version/payload consistency using its canonical
/// version records; no unbounded in-memory history map is required here.
pub fn classify_record(
    policy: &Policy,
    targeted: bool,
    fact: &ExecutionRecord,
) -> Result<Intent, PolicyError> {
    let mut versions = BTreeMap::new();
    let mut payloads = BTreeMap::new();
    if let Some(version) = policy.version() {
        versions.insert(version.number(), version.clone());
        let payload = version.payload();
        payloads.insert(
            (payload.object().clone(), payload.revision()),
            payload.clone(),
        );
    }
    validate_execution(policy, fact, &mut versions, &mut payloads).map_err(|reason| {
        PolicyError::InvalidExecution {
            execution: Box::new(fact.key()),
            reason,
        }
    })?;
    Ok(classify_validated(policy, targeted, fact))
}
fn validate_execution(
    policy: &Policy,
    record: &ExecutionRecord,
    versions: &mut BTreeMap<u64, Version>,
    payloads: &mut BTreeMap<(PayloadId, u64), PayloadRef>,
) -> Result<(), ExecutionFailure> {
    let v = record.version();
    if v.policy().tenant() != policy.key().tenant() {
        return Err(ExecutionFailure::TenantMismatch);
    }
    if v.policy() != policy.key() {
        return Err(ExecutionFailure::PolicyMismatch);
    }
    let latest = policy.version().map_or(0, Version::number);
    if v.number() > latest {
        return Err(ExecutionFailure::FutureVersion { latest });
    }
    if versions.get(&v.number()).is_some_and(|old| old != v) {
        return Err(ExecutionFailure::VersionConflict);
    }
    let p = v.payload();
    let key = (p.object().clone(), p.revision());
    if payloads.get(&key).is_some_and(|old| old != p) {
        return Err(ExecutionFailure::PayloadConflict {
            object: p.object().clone(),
            revision: p.revision(),
        });
    }
    versions.insert(v.number(), v.clone());
    payloads.insert(key, p.clone());
    Ok(())
}
fn classify_validated(policy: &Policy, targeted: bool, fact: &ExecutionRecord) -> Intent {
    let reason = if policy.status() == Status::Archived {
        Some(CancelReason::Archived)
    } else if !targeted {
        Some(CancelReason::ScopeExit)
    } else if policy
        .version()
        .is_some_and(|v| v.number() != fact.version().number())
    {
        Some(CancelReason::Superseded)
    } else {
        None
    };
    let execution = fact.clone();
    if let Some(reason) = reason {
        if !fact.progress().is_terminal() {
            Intent::Cancel { execution, reason }
        } else {
            Intent::Retain {
                execution,
                reason: RetainReason::Historical,
            }
        }
    } else {
        let reason = if policy.status() == Status::Paused {
            RetainReason::Paused
        } else {
            RetainReason::Current
        };
        Intent::Retain { execution, reason }
    }
}
