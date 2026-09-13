use crate::{Rejection, codec, core::*, db::*};
use rss_contract::Timepoint;
use rss_transactional_messaging_postgres::PgError;
use serde_json::{Value, json};
/// Stored caller provenance; does not resolve or authorize a Group/Scope.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentReference {
    pub id: String,
    pub revision: u64,
}
#[derive(Clone, Debug)]
pub enum Command {
    Create {
        policy: PolicyId,
    },
    Transition {
        policy: PolicyId,
        transition: Transition,
    },
    SelectTargets {
        policy: PolicyId,
        snapshot: TargetSnapshot,
        references: Vec<AssignmentReference>,
    },
    ReplaceFacts {
        policy: PolicyId,
        facts: Vec<ExecutionRecord>,
    },
    Replan {
        policy: PolicyId,
    },
}
#[derive(Clone, Debug)]
pub struct Request {
    pub id: RequestId,
    pub expected_storage_revision: u64,
    pub as_of: Timepoint,
    pub command: Command,
}
impl Request {
    pub fn policy(&self) -> &PolicyId {
        match &self.command {
            Command::Create { policy }
            | Command::Transition { policy, .. }
            | Command::SelectTargets { policy, .. }
            | Command::ReplaceFacts { policy, .. }
            | Command::Replan { policy } => policy,
        }
    }
    pub(crate) fn document(&self) -> Result<Vec<u8>, PgError> {
        let command = match &self.command {
            Command::Create { .. } => json!([0]),
            Command::Transition { transition, .. } => match transition {
                Transition::Activate(v) => json!([1, codec::version(v)]),
                Transition::Pause => json!([2]),
                Transition::Resume => json!([3]),
                Transition::Archive => json!([4]),
            },
            Command::SelectTargets {
                snapshot,
                references,
                ..
            } => json!([5, codec::targets(snapshot), references]),
            Command::ReplaceFacts { facts, .. } => {
                json!([6, facts.iter().map(codec::fact).collect::<Vec<_>>()])
            }
            Command::Replan { .. } => json!([7]),
        };
        encode(&json!([
            1,
            self.id.tenant().to_string(),
            self.id.value(),
            self.policy().value(),
            self.expected_storage_revision,
            self.as_of.unix_seconds(),
            command
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub(crate) policy: Policy,
    pub(crate) revision: u64,
    pub(crate) targets: Option<TargetSnapshot>,
    pub(crate) references: Vec<AssignmentReference>,
    pub(crate) plan: Option<PlanId>,
    pub(crate) installed: Option<u64>,
    pub(crate) at: Option<Timepoint>,
}
impl Aggregate {
    pub fn draft(policy: PolicyId) -> Self {
        Self {
            policy: Policy::draft(policy),
            revision: 0,
            targets: None,
            references: vec![],
            plan: None,
            installed: None,
            at: None,
        }
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn storage_revision(&self) -> u64 {
        self.revision
    }
    pub fn targets(&self) -> Option<&TargetSnapshot> {
        self.targets.as_ref()
    }
    pub fn references(&self) -> &[AssignmentReference] {
        &self.references
    }
    pub fn current_plan_id(&self) -> Option<PlanId> {
        self.plan
    }
    pub fn plan_is_fresh(&self) -> bool {
        self.plan.is_some() && self.installed == Some(self.revision)
    }
    pub(crate) fn advance(&mut self) -> Result<(), Rejection> {
        self.revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Rejection::Conflict)?;
        Ok(())
    }
    pub(crate) fn document(&self) -> Result<Vec<u8>, PgError> {
        encode(&json!([
            1,
            codec::policy(&self.policy),
            self.revision,
            self.targets.as_ref().map(codec::targets),
            self.references,
            self.plan.map(|p| codec::hex(p.bytes())),
            self.installed,
            self.at.map(|t| t.unix_seconds())
        ]))
    }
    pub(crate) fn restore(bytes: &[u8]) -> Result<Self, PgError> {
        let v: Value = decode(bytes)?;
        let a = codec::array(&v, 8)?;
        if codec::number(&a[0])? != 1 {
            return Err(fault());
        }
        let policy = codec::read_policy(&a[1])?;
        let revision = codec::number(&a[2])?;
        let targets = if a[3].is_null() {
            None
        } else {
            Some(codec::read_targets(&a[3])?)
        };
        let references: Vec<AssignmentReference> = data(serde_json::from_value(a[4].clone()))?;
        let plan = if a[5].is_null() {
            None
        } else {
            Some(codec::plan_id(codec::text(&a[5])?)?)
        };
        let installed = data(serde_json::from_value::<Option<u64>>(a[6].clone()))?;
        let at = if a[7].is_null() {
            None
        } else {
            Some(codec::time(&a[7])?)
        };
        if targets
            .as_ref()
            .is_some_and(|t| t.key().tenant() != policy.key().tenant())
            || plan.is_some() != installed.is_some()
            || installed.is_some_and(|n| n > revision)
            || revision > i64::MAX as u64
        {
            return Err(fault());
        }
        let mut reference_ids = std::collections::BTreeSet::new();
        if policy.revision() > revision
            || references.len() > 256
            || references.iter().any(|r| {
                r.revision == 0
                    || RequestId::new(policy.key().tenant(), &r.id).is_err()
                    || !reference_ids.insert(&r.id)
            })
        {
            return Err(fault());
        }
        Ok(Self {
            policy,
            revision,
            targets,
            references,
            plan,
            installed,
            at,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub policy: String,
    pub request: String,
    pub storage_revision: u64,
    pub plan_id: Option<String>,
    pub plan_is_fresh: bool,
}
impl Receipt {
    pub(crate) fn new(a: &Aggregate, r: &Request) -> Self {
        Self {
            policy: a.policy.key().value().into(),
            request: r.id.value().into(),
            storage_revision: a.revision,
            plan_id: a.plan.map(|p| codec::hex(p.bytes())),
            plan_is_fresh: a.plan_is_fresh(),
        }
    }
}
