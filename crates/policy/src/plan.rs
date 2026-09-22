use crate::{
    DeviceId, ExecutionFailure, ExecutionKey, ExecutionRecord, PayloadId, PayloadRef, Policy,
    PolicyError, PolicyId, RequestId, Status, TargetSnapshotId, Version,
};
use rss_contract::Timepoint;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Caller assertion about the target universe, not source authentication.
pub enum SnapshotCompleteness {
    /// The supplied members describe the full candidate universe, including an empty one.
    Complete,
    /// Partial targets, rejected rather than interpreted as a complete empty set.
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Validated complete same-tenant target snapshot with sorted, deduplicated devices.
pub struct TargetSnapshot {
    key: TargetSnapshotId,
    revision: NonZeroU64,
    members: BTreeSet<DeviceId>,
}
impl TargetSnapshot {
    /// Validate a complete target universe and positive revision; sort and deduplicate members.
    /// Returns [`PolicyError::IncompleteTargets`], [`PolicyError::TenantMismatch`] or
    /// [`PolicyError::InvalidRevision`] for invalid inputs. Does not resolve sources or
    /// verify the caller's completeness assertion.
    pub fn new(
        key: TargetSnapshotId,
        revision: u64,
        completeness: SnapshotCompleteness,
        members: Vec<DeviceId>,
    ) -> Result<Self, PolicyError> {
        if completeness == SnapshotCompleteness::Incomplete {
            return Err(PolicyError::IncompleteTargets);
        }
        if members.iter().any(|m| m.tenant() != key.tenant()) {
            return Err(PolicyError::TenantMismatch);
        }
        Ok(Self {
            key,
            revision: crate::model::nonzero(revision)?,
            members: members.into_iter().collect(),
        })
    }
    /// Borrow the snapshot identity and tenant.
    pub fn key(&self) -> &TargetSnapshotId {
        &self.key
    }
    /// Return the positive target snapshot revision used as a plan precondition.
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    /// Borrow the complete canonical device set.
    pub fn members(&self) -> &BTreeSet<DeviceId> {
        &self.members
    }
}
/// Borrowed planning facts plus caller-selected request and time metadata.
pub struct PlanInput<'a> {
    /// Current policy aggregate whose revision must be checked when persisting the plan.
    pub policy: &'a Policy,
    /// Complete target snapshot whose identity and revision must remain bound to the plan.
    pub targets: &'a TargetSnapshot,
    /// One current fact per execution; exact duplicates are accepted, contradictions rejected.
    pub executions: &'a [ExecutionRecord],
    /// Same-tenant request identity, retained as metadata rather than execution identity.
    pub request: RequestId,
    /// Caller-selected evaluation time, retained without reading a system clock.
    pub as_of: Timepoint,
}
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
    /// Create a previously absent desired execution after storage preconditions hold.
    Add(DesiredExecution),
    /// Preserve the supplied execution and effect facts.
    Retain {
        /// Existing facts retained without rewriting progress or effect evidence.
        execution: ExecutionRecord,
        /// Reason the facts are retained.
        reason: RetainReason,
    },
    /// Old nonterminal executions also receive explicit Cancel intents.
    /// Create a new version's execution while recording the prior semantic identities.
    Supersede {
        /// New desired execution; not yet persisted or dispatched.
        replacement: DesiredExecution,
        /// Prior-version execution keys for the same device, including terminal history.
        previous: Vec<ExecutionKey>,
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
/// V1 digest of policy, target and execution semantics; request/time metadata is excluded.
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
#[derive(Clone, Debug, Eq, PartialEq)]
/// Deterministic, ordered intents and storage preconditions; no effects have been applied.
pub struct Plan {
    id: PlanId,
    policy: PolicyId,
    expected_revision: u64,
    targets: TargetSnapshotId,
    target_revision: u64,
    scheduling_open: bool,
    intents: Vec<Intent>,
    request: RequestId,
    as_of: Timepoint,
}
impl Plan {
    /// Return the deterministic semantic identity of the plan.
    pub fn id(&self) -> PlanId {
        self.id
    }
    /// Borrow the policy identity.
    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
    /// Return the policy revision the persistence owner must check atomically.
    pub fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    /// Borrow the target snapshot identity bound to the plan.
    pub fn targets(&self) -> &TargetSnapshotId {
        &self.targets
    }
    /// Return the target revision the persistence owner must check atomically.
    pub fn target_revision(&self) -> u64 {
        self.target_revision
    }
    /// Applies to starting/progressing Apply executions, not persisting Cancel intents.
    pub fn scheduling_open(&self) -> bool {
        self.scheduling_open
    }
    /// Borrow the canonically sorted intents; these are decisions, not execution receipts.
    pub fn intents(&self) -> &[Intent] {
        &self.intents
    }
    /// Borrow request metadata; it does not change the semantic execution/plan identities.
    pub fn request(&self) -> &RequestId {
        &self.request
    }
    /// Return caller-supplied time metadata without implying a freshness check.
    pub fn as_of(&self) -> Timepoint {
        self.as_of
    }
}

/// Compute a plan after validating tenant, policy, immutable versions and execution facts.
/// Exact duplicates collapse; contradictory facts or identities return [`PolicyError`]
/// without a partial plan. Existing execution identities, including Unknown or Failed,
/// suppress automatic re-addition. Archived/out-of-scope/superseded nonterminal work
/// receives Cancel; terminal history remains. No device call, retry or persistence occurs.
/// The adapter must atomically persist/check preconditions before acting on these intents.
pub fn reconcile(input: PlanInput<'_>) -> Result<Plan, PolicyError> {
    let facts = validate(&input)?;
    let mut intents = Vec::new();
    if input.policy.status() == Status::Active
        && let Some(version) = input.policy.version()
    {
        add_desired(version, input.targets, &facts, &mut intents);
    }
    for fact in facts.values() {
        classify_existing(input.policy, input.targets, fact, &mut intents);
    }
    intents.sort();
    Ok(Plan {
        id: crate::fingerprint::plan_id(input.policy, input.targets, &facts),
        policy: input.policy.key().clone(),
        expected_revision: input.policy.revision(),
        targets: input.targets.key.clone(),
        target_revision: input.targets.revision(),
        scheduling_open: input.policy.status() == Status::Active,
        intents,
        request: input.request,
        as_of: input.as_of,
    })
}
type Facts = BTreeMap<ExecutionKey, ExecutionRecord>;
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
fn validate(input: &PlanInput<'_>) -> Result<Facts, PolicyError> {
    let tenant = input.policy.key().tenant();
    if input.request.tenant() != tenant || input.targets.key.tenant() != tenant {
        return Err(PolicyError::TenantMismatch);
    }
    let mut versions = BTreeMap::new();
    let mut payloads = BTreeMap::new();
    if let Some(current) = input.policy.version() {
        versions.insert(current.number(), current.clone());
        let payload = current.payload();
        payloads.insert(
            (payload.object().clone(), payload.revision()),
            payload.clone(),
        );
    }
    let mut facts = BTreeMap::new();
    for record in input.executions {
        let key = record.key();
        validate_execution(input.policy, record, &mut versions, &mut payloads).map_err(
            |reason| PolicyError::InvalidExecution {
                execution: Box::new(key.clone()),
                reason,
            },
        )?;
        if facts.get(&key).is_some_and(|old| old != record) {
            return Err(PolicyError::ConflictingExecution { execution: key });
        }
        facts.insert(key, record.clone());
    }
    Ok(facts)
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
fn add_desired(
    version: &Version,
    targets: &TargetSnapshot,
    facts: &Facts,
    intents: &mut Vec<Intent>,
) {
    // Index once instead of rescanning all executions for each target.
    let mut previous: BTreeMap<&DeviceId, Vec<ExecutionKey>> = BTreeMap::new();
    for fact in facts
        .values()
        .filter(|f| f.version().number() < version.number())
    {
        previous.entry(fact.device()).or_default().push(fact.key());
    }
    for target in &targets.members {
        let replacement = DesiredExecution::new(version, target.clone());
        if facts.contains_key(replacement.key()) {
            continue;
        }
        if let Some(old) = previous.get(target) {
            intents.push(Intent::Supersede {
                replacement,
                previous: old.clone(),
            });
        } else {
            intents.push(Intent::Add(replacement));
        }
    }
}
fn classify_existing(
    policy: &Policy,
    targets: &TargetSnapshot,
    fact: &ExecutionRecord,
    intents: &mut Vec<Intent>,
) {
    intents.push(classify_validated(
        policy,
        targets.members.contains(fact.device()),
        fact,
    ));
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
