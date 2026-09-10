//! V1 plan identity encoding. Never hash Debug output, memory layout or request time.
use crate::{
    Effect, ExecutionKey, ExecutionRecord, PayloadRef, PlanId, Policy, Progress, RemovalRule,
    Status, TargetSnapshot, Version,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
