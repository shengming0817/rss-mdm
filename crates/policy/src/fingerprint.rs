//! V1 plan identity encoding. Never hash Debug output, memory layout or request time.
use crate::{DeviceId, PolicyError, PolicyId, TargetSnapshotId};
use crate::{
    Effect, ExecutionKey, ExecutionRecord, PayloadRef, PlanId, Policy, Progress, RemovalRule,
    Status, TargetSnapshot, Version,
};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Chain {
    state: [u8; 32],
    count: u64,
}
impl Chain {
    fn new(domain: &[u8]) -> Self {
        Self {
            state: Sha256::digest(domain).into(),
            count: 0,
        }
    }
    fn push(&mut self, write: impl FnOnce(&mut Encoding)) -> Result<(), PolicyError> {
        let count = self
            .count
            .checked_add(1)
            .ok_or(PolicyError::InputCountOverflow)?;
        let mut encoded = Encoding(Sha256::new());
        encoded.0.update(self.state);
        write(&mut encoded);
        self.state = encoded.0.finalize().into();
        self.count = count;
        Ok(())
    }
}
/// Bounded canonical fold of strictly ordered, unique target identities. The
/// storage owner enforces ordering/uniqueness and checkpoints state WITH the page.
#[derive(Clone, Debug)]
pub struct TargetDigest {
    tenant: TenantId,
    chain: Chain,
}
impl TargetDigest {
    /// Start a target stream belonging to one tenant.
    pub fn empty(tenant: TenantId) -> Self {
        Self {
            tenant,
            chain: Chain::new(b"rss-mdm-policy/targets/v2"),
        }
    }
    /// Resume an integrity-checked checkpoint; this does not authenticate supplied bytes.
    pub fn restore(tenant: TenantId, state: [u8; 32], count: u64) -> Self {
        Self {
            tenant,
            chain: Chain { state, count },
        }
    }
    /// Append one canonical identity. Page boundaries never enter the encoding.
    pub fn push(&mut self, device: &DeviceId) -> Result<(), PolicyError> {
        if device.tenant() != self.tenant {
            return Err(PolicyError::TenantMismatch);
        }
        self.chain
            .push(|e| e.object(device.tenant(), device.value()))
    }
    /// Durable checkpoint hash, stored atomically with the page cursor.
    pub fn state(&self) -> [u8; 32] {
        self.chain.state
    }
    /// Number of identities in this checkpoint.
    pub fn count(&self) -> u64 {
        self.chain.count
    }
}
/// Canonical fold of execution records ordered by their full semantic key.
/// Immutable version/payload consistency belongs to the owner admitting records.
#[derive(Clone, Debug)]
pub struct ExecutionDigest {
    policy: PolicyId,
    chain: Chain,
}
impl ExecutionDigest {
    /// Start an execution stream for one policy.
    pub fn empty(policy: PolicyId) -> Self {
        Self {
            policy,
            chain: Chain::new(b"rss-mdm-policy/executions/v2"),
        }
    }
    /// Resume a digest-verified persistent checkpoint, without reading all history.
    pub fn restore(policy: PolicyId, state: [u8; 32], count: u64) -> Self {
        Self {
            policy,
            chain: Chain { state, count },
        }
    }
    /// Append an execution record without retaining a history vector.
    pub fn push(&mut self, fact: &ExecutionRecord) -> Result<(), PolicyError> {
        if fact.version().policy() != &self.policy {
            return Err(PolicyError::PolicyMismatch);
        }
        self.chain.push(|e| e.fact(fact))
    }
    /// Durable checkpoint hash.
    pub fn state(&self) -> [u8; 32] {
        self.chain.state
    }
    /// Number of records incorporated so far; not limited by current device capacity.
    pub fn count(&self) -> u64 {
        self.chain.count
    }
}
/// Produce the sole streamed plan identity after BOTH input streams are sealed.
/// This is an identity, not authorization or evidence that a candidate was saved.
pub fn stream_plan_id(
    policy: &Policy,
    targets: &TargetSnapshotId,
    revision: u64,
    members: &TargetDigest,
    executions: &ExecutionDigest,
) -> Result<PlanId, PolicyError> {
    if revision == 0 {
        return Err(PolicyError::InvalidRevision);
    }
    if targets.tenant() != policy.key().tenant() || members.tenant != policy.key().tenant() {
        return Err(PolicyError::TenantMismatch);
    }
    if &executions.policy != policy.key() {
        return Err(PolicyError::PolicyMismatch);
    }
    let mut e = Encoding(Sha256::new());
    e.bytes(b"rss-mdm-policy/plan/v2");
    e.object(policy.key().tenant(), policy.key().value());
    e.number(policy.revision());
    e.number(match policy.status() {
        Status::Draft => 0,
        Status::Active => 1,
        Status::Paused => 2,
        Status::Archived => 3,
    });
    if let Some(version) = policy.version() {
        e.number(1);
        e.version(version);
    } else {
        e.number(0);
    }
    e.object(targets.tenant(), targets.value());
    e.number(revision);
    e.number(members.count());
    e.0.update(members.state());
    e.number(executions.count());
    e.0.update(executions.state());
    Ok(PlanId(e.0.finalize().into()))
}
struct Encoding(Sha256);
impl Encoding {
    fn number(&mut self, n: u64) {
        self.0.update(n.to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.number(value.len() as u64);
        self.0.update(value);
    }
    fn object(&mut self, tenant: rss_request_context::TenantId, value: &str) {
        self.0.update(tenant.octets());
        self.bytes(value.as_bytes());
    }
    fn payload(&mut self, p: &PayloadRef) {
        self.object(p.object().tenant(), p.object().value());
        self.number(p.revision());
        self.0.update(p.digest());
    }
    fn version(&mut self, v: &Version) {
        self.object(v.policy().tenant(), v.policy().value());
        self.number(v.number());
        self.payload(v.payload());
        match v.removal() {
            RemovalRule::CancelOutstandingRetainEffects => self.number(0),
        }
    }
    fn fact(&mut self, f: &ExecutionRecord) {
        self.version(f.version());
        self.object(f.device().tenant(), f.device().value());
        self.number(0); // Apply action in V1.
        self.number(match f.progress() {
            Progress::Planned => 0,
            Progress::Running => 1,
            Progress::Unknown => 2,
            Progress::Succeeded => 3,
            Progress::Failed => 4,
            Progress::Cancelled => 5,
        });
        self.number(match f.effect() {
            Effect::Unverified => 0,
            Effect::Unknown => 1,
            Effect::VerifiedPresent => 2,
            Effect::VerifiedAbsent => 3,
        });
    }
}
pub(crate) fn plan_id(
    policy: &Policy,
    targets: &TargetSnapshot,
    facts: &BTreeMap<ExecutionKey, ExecutionRecord>,
) -> PlanId {
    let mut e = Encoding(Sha256::new());
    e.bytes(b"rss-mdm-policy/plan/v1");
    e.object(policy.key().tenant(), policy.key().value());
    e.number(policy.revision());
    e.number(match policy.status() {
        Status::Draft => 0,
        Status::Active => 1,
        Status::Paused => 2,
        Status::Archived => 3,
    });
    if let Some(v) = policy.version() {
        e.number(1);
        e.version(v);
    } else {
        e.number(0);
    }
    e.object(targets.key().tenant(), targets.key().value());
    e.number(targets.revision());
    e.number(targets.members().len() as u64);
    for target in targets.members() {
        e.object(target.tenant(), target.value());
    }
    e.number(facts.len() as u64);
    for fact in facts.values() {
        e.fact(fact);
    }
    PlanId(e.0.finalize().into())
}
