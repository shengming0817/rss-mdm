use crate::{
    ExecutionKey, ExecutionRecord, ObjectKey, PayloadRef, Policy, PolicyError, Status, Version,
};
use rss_contract::Timepoint;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetSnapshot {
    key: ObjectKey,
    revision: NonZeroU64,
    complete: bool,
    members: BTreeSet<ObjectKey>,
}
impl TargetSnapshot {
    pub fn new(
        key: ObjectKey,
        revision: u64,
        complete: bool,
        members: Vec<ObjectKey>,
    ) -> Result<Self, PolicyError> {
        if members.iter().any(|m| m.tenant() != key.tenant()) {
            return Err(PolicyError::TenantMismatch);
        }
        Ok(Self {
            key,
            revision: crate::model::nonzero(revision)?,
            complete,
            members: members.into_iter().collect(),
        })
    }
    pub fn key(&self) -> &ObjectKey {
        &self.key
    }
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    pub fn members(&self) -> &BTreeSet<ObjectKey> {
        &self.members
    }
}
pub struct PlanInput<'a> {
    pub policy: &'a Policy,
    pub targets: &'a TargetSnapshot,
    /// One current fact per execution; exact duplicates are accepted, contradictions rejected.
    pub executions: &'a [ExecutionRecord],
    pub request: ObjectKey,
    pub as_of: Timepoint,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DesiredExecution {
    key: ExecutionKey,
    payload: PayloadRef,
}
impl DesiredExecution {
    fn new(version: &Version, target: ObjectKey) -> Self {
        Self {
            key: ExecutionKey::new(version, target),
            payload: version.payload().clone(),
        }
    }
    pub fn key(&self) -> &ExecutionKey {
        &self.key
    }
    pub fn payload(&self) -> &PayloadRef {
        &self.payload
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetainReason {
    Current,
    Paused,
    Historical,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CancelReason {
    ScopeExit,
    Archived,
    Superseded,
}
/// Intents never rewrite the supplied execution/effect facts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Intent {
    Add(DesiredExecution),
    Retain {
        execution: ExecutionRecord,
        reason: RetainReason,
    },
    /// Old nonterminal executions also receive explicit Cancel intents.
    Supersede {
        replacement: DesiredExecution,
        previous: Vec<ExecutionKey>,
    },
    Cancel {
        execution: ExecutionRecord,
        reason: CancelReason,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanId(pub(crate) [u8; 32]);
impl PlanId {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    id: PlanId,
    policy: ObjectKey,
    expected_revision: u64,
    targets: ObjectKey,
    target_revision: u64,
    scheduling_open: bool,
    intents: Vec<Intent>,
    request: ObjectKey,
    as_of: Timepoint,
}
impl Plan {
    pub fn id(&self) -> PlanId {
        self.id
    }
    pub fn policy(&self) -> &ObjectKey {
        &self.policy
    }
    pub fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    pub fn targets(&self) -> &ObjectKey {
        &self.targets
    }
    pub fn target_revision(&self) -> u64 {
        self.target_revision
    }
    /// Applies to starting/progressing Apply executions, not persisting Cancel intents.
    pub fn scheduling_open(&self) -> bool {
        self.scheduling_open
    }
    pub fn intents(&self) -> &[Intent] {
        &self.intents
    }
    pub fn request(&self) -> &ObjectKey {
        &self.request
    }
    pub fn as_of(&self) -> Timepoint {
        self.as_of
    }
}

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
fn validate(input: &PlanInput<'_>) -> Result<Facts, PolicyError> {
    let tenant = input.policy.key().tenant();
    if input.request.tenant() != tenant || input.targets.key.tenant() != tenant {
        return Err(PolicyError::TenantMismatch);
    }
    if !input.targets.complete {
        return Err(PolicyError::IncompleteTargets);
    }
    let mut versions = BTreeMap::new();
    let mut payloads = BTreeMap::new();
    if let Some(current) = input.policy.version() {
        register_version(current, &mut versions, &mut payloads)?;
    }
    let mut facts = BTreeMap::new();
    for record in input.executions {
        crate::lifecycle::check_policy(input.policy.key(), record.version())?;
        if input
            .policy
            .version()
            .is_none_or(|v| record.version().number() > v.number())
        {
            return Err(PolicyError::StaleVersion);
        }
        register_version(record.version(), &mut versions, &mut payloads)?;
        let key = record.key();
        if facts.get(&key).is_some_and(|old| old != record) {
            return Err(PolicyError::ConflictingExecution);
        }
        facts.insert(key, record.clone());
    }
    Ok(facts)
}
fn register_version(
    v: &Version,
    versions: &mut BTreeMap<u64, Version>,
    payloads: &mut BTreeMap<(ObjectKey, u64), PayloadRef>,
) -> Result<(), PolicyError> {
    if versions.get(&v.number()).is_some_and(|old| old != v) {
        return Err(PolicyError::VersionConflict);
    }
    let p = v.payload();
    let key = (p.object().clone(), p.revision());
    if payloads.get(&key).is_some_and(|old| old != p) {
        return Err(PolicyError::PayloadConflict);
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
    let mut previous: BTreeMap<&ObjectKey, Vec<ExecutionKey>> = BTreeMap::new();
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
    let reason = if policy.status() == Status::Archived {
        Some(CancelReason::Archived)
    } else if !targets.members.contains(fact.device()) {
        Some(CancelReason::ScopeExit)
    } else if policy.status() == Status::Active
        && policy
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
            intents.push(Intent::Cancel { execution, reason });
        } else {
            intents.push(Intent::Retain {
                execution,
                reason: RetainReason::Historical,
            });
        }
    } else {
        let reason = if policy.status() == Status::Paused {
            RetainReason::Paused
        } else {
            RetainReason::Current
        };
        intents.push(Intent::Retain { execution, reason });
    }
}
