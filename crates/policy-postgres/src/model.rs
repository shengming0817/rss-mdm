use crate::{Rejection, STORAGE, codec, core::*};
use rss_contract::Timepoint;
use rss_transactional_messaging_postgres::PgError;
use serde_json::{Value, json};
/// Stored caller provenance; does not resolve or authorize a Group/Scope.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentReference {
    /// Stable identity; changing a request body under an existing request identity is rejected.
    pub id: String,
    /// Version or lifecycle revision recorded in this value.
    pub revision: u64,
}
/// Closed set of persistent aggregate mutations.
#[derive(Clone, Debug)]
pub enum Command {
    /// Create an initially empty aggregate.
    Create {
        /// Policy to create in this tenant.
        policy: PolicyId,
    },
    /// Apply a core lifecycle transition, invalidating any prior plan freshness.
    Transition {
        /// Policy to mutate in this tenant.
        policy: PolicyId,
        /// Checked core lifecycle transition.
        transition: Transition,
    },
    /// Select the complete immutable target snapshot and its assignment references.
    SelectTargets {
        /// Policy to mutate in this tenant.
        policy: PolicyId,
        /// Complete target set frozen under its own identity and revision.
        snapshot: TargetSnapshot,
        /// Caller-owned assignment identities and revisions.
        references: Vec<AssignmentReference>,
    },
    /// Record caller-confirmed execution admissions or progress. The host owns their authority; saving a plan never calls this command.
    RecordExecutions {
        /// Policy to mutate in this tenant.
        policy: PolicyId,
        /// Caller-confirmed snapshots for existing full execution keys.
        facts: Vec<ExecutionRecord>,
    },
    /// Explicitly compute and install a deterministic plan using current state, targets and facts.
    Replan {
        /// Policy whose current inputs are explicitly recomputed.
        policy: PolicyId,
    },
}
/// Complete, immutable caller request. Preserve identity, time, expected revision and command during recovery.
#[derive(Clone, Debug)]
pub struct Request {
    /// Stable identity; changing a request body under an existing request identity is rejected.
    pub id: RequestId,
    /// The sole expected aggregate CAS token; zero is required for creation.
    pub expected_storage_revision: u64,
    /// Caller-fixed observation time; preserve it on request replay.
    pub as_of: Timepoint,
    /// The complete requested mutation, included in the request fingerprint.
    pub command: Command,
}
impl Request {
    /// Return the policy identity or lifecycle represented by this value.
    pub fn policy(&self) -> &PolicyId {
        match &self.command {
            Command::Create { policy }
            | Command::Transition { policy, .. }
            | Command::SelectTargets { policy, .. }
            | Command::RecordExecutions { policy, .. }
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
            Command::RecordExecutions { facts, .. } => {
                json!([6, facts.iter().map(codec::fact).collect::<Vec<_>>()])
            }
            Command::Replan { .. } => json!([7]),
        };
        STORAGE.encode(&json!([
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
/// Validated Policy storage projection with a single CAS token and explicit plan installation.
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub(crate) policy: Policy,
    pub(crate) revision: u64,
    pub(crate) targets: Option<TargetSnapshot>,
    pub(crate) references: Vec<AssignmentReference>,
    pub(crate) plan: Option<PlanId>,
    pub(crate) installed: Option<u64>,
    pub(crate) installed_request: Option<RequestId>,
    pub(crate) at: Option<Timepoint>,
    pub(crate) references_current: bool,
}
impl Aggregate {
    /// Construct an unpersisted empty aggregate. Persist it through a Create request.
    pub fn draft(policy: PolicyId) -> Self {
        Self {
            policy: Policy::draft(policy),
            revision: 0,
            targets: None,
            references: vec![],
            plan: None,
            installed: None,
            installed_request: None,
            at: None,
            references_current: true,
        }
    }
    /// Return the policy identity or lifecycle represented by this value.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    /// Return the sole aggregate CAS token; it covers lifecycle, targets, facts and freshness.
    pub fn storage_revision(&self) -> u64 {
        self.revision
    }
    /// Return the selected complete target snapshot, if one has been supplied.
    pub fn targets(&self) -> Option<&TargetSnapshot> {
        self.targets.as_ref()
    }
    /// Return the caller-attested assignment references attached to the selected target snapshot.
    pub fn references(&self) -> &[AssignmentReference] {
        &self.references
    }
    /// Return the deterministic decision identity of the last explicit replan, even if stale.
    pub fn current_plan_id(&self) -> Option<PlanId> {
        self.plan
    }
    /// The request whose explicit replan installed the current decision.
    pub fn current_plan_request(&self) -> Option<&RequestId> {
        self.installed_request.as_ref()
    }
    /// Whether the last explicit installation still matches the current storage revision.
    pub fn plan_is_fresh(&self) -> bool {
        self.plan.is_some() && self.installed == Some(self.revision) && self.references_current
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
        STORAGE.encode(&json!([
            1,
            codec::policy(&self.policy),
            self.revision,
            self.targets.as_ref().map(codec::targets),
            self.references,
            self.plan.map(|p| codec::hex(p.bytes())),
            self.installed,
            self.at.map(|t| t.unix_seconds()),
            self.installed_request.as_ref().map(RequestId::value)
        ]))
    }
    pub(crate) fn restore(bytes: &[u8]) -> Result<Self, PgError> {
        let v: Value = STORAGE.decode(bytes)?;
        let a = codec::array(&v, 9)?;
        if codec::number(&a[0])? != 1 {
            return Err(STORAGE.fault("model::restore"));
        }
        let policy = codec::read_policy(&a[1])?;
        let revision = codec::number(&a[2])?;
        let targets = if a[3].is_null() {
            None
        } else {
            Some(codec::read_targets(&a[3])?)
        };
        let references: Vec<AssignmentReference> =
            STORAGE.json("model::restore", serde_json::from_value(a[4].clone()))?;
        let plan = if a[5].is_null() {
            None
        } else {
            Some(codec::plan_id(codec::text(&a[5])?)?)
        };
        let installed = STORAGE.json(
            "model::restore",
            serde_json::from_value::<Option<u64>>(a[6].clone()),
        )?;
        let at = if a[7].is_null() {
            None
        } else {
            Some(codec::time(&a[7])?)
        };
        let installed_request = if a[8].is_null() {
            None
        } else {
            Some(crate::error::decode_domain(
                "model::restore",
                RequestId::new(policy.key().tenant(), codec::text(&a[8])?),
            )?)
        };
        if targets
            .as_ref()
            .is_some_and(|t| t.key().tenant() != policy.key().tenant())
            || plan.is_some() != installed.is_some()
            || plan.is_some() != installed_request.is_some()
            || installed.is_some_and(|n| n > revision)
            || revision > i64::MAX as u64
        {
            return Err(STORAGE.fault("model::restore"));
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
            return Err(STORAGE.fault("model::restore"));
        }
        Ok(Self {
            policy,
            revision,
            targets,
            references,
            plan,
            installed,
            installed_request,
            at,
            references_current: true,
        })
    }
}
/// Immutable response to the original request; replay does not rewrite this snapshot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Tenant-scoped policy identity.
    pub policy: String,
    /// Original request identity associated with this receipt.
    pub request: String,
    /// Aggregate storage revision observed after the operation.
    pub storage_revision: u64,
    /// Deterministic decision digest, present after an explicit replan.
    pub plan_id: Option<String>,
    /// Freshness at the time this immutable receipt was committed.
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

/// Bounded execution facts and an opaque cursor for the next page.
#[derive(Clone, Debug)]
pub struct FactPage {
    /// Facts in persistent key order.
    pub records: Vec<ExecutionRecord>,
    /// Pass unchanged as `after`; absent when this read has no further rows.
    pub next: Option<String>,
}
