use crate::rule::{Criteria, Node};
use crate::{
    Budget, Error, Fact, FactState, LimitKind, ObjectKey, Op, Result, Rule, Scalar, Value,
};
use rss_contract::Timepoint;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Three-valued result; only Match is eligible for a new membership set.
pub enum Decision {
    /// The rule is satisfied; eligible for the replacement membership set.
    Match,
    /// The rule is definitively not satisfied.
    NoMatch,
    /// Available facts cannot decide the rule; not eligible for new membership.
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Distinct missing/empty/freshness/support causes; never substituted with zero values.
pub enum UnknownReason {
    /// An ordinary comparison encountered explicit null.
    Null,
    /// The fact is missing or the referenced field is outside partial coverage.
    Missing,
    /// The source explicitly deleted the value.
    Deleted,
    /// The source explicitly cannot provide this fact.
    Unsupported,
    /// Current sources disagree on the value.
    Conflict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A predicate result with its specific unknown reason.
pub enum Outcome {
    /// This predicate is satisfied.
    Match,
    /// This predicate is definitively not satisfied.
    NoMatch,
    /// This predicate cannot be decided for the stated reason.
    Unknown(UnknownReason),
}
impl Outcome {
    fn decision(self) -> Decision {
        match self {
            Self::Match => Decision::Match,
            Self::NoMatch => Decision::NoMatch,
            Self::Unknown(_) => Decision::Unknown,
        }
    }
    fn from_bool(value: bool) -> Self {
        if value { Self::Match } else { Self::NoMatch }
    }
}
/// AST child-index path identifies a predicate in the immutable input rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    /// Child indexes from the root; resolve with [`Rule::predicate_at`].
    pub path: Vec<usize>,
    /// Leaf comparison result, without copying the fact value.
    pub outcome: Outcome,
}
/// Provenance is stored once per referenced field, not duplicated for every predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// Caller-supplied resolved source identity.
    pub source: String,
    /// Caller-supplied source snapshot identity.
    pub snapshot_id: String,
    /// Observation timestamp retained for provenance only.
    pub observed_at: Timepoint,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Stable leaf explanations and once-per-field provenance; contains no fact values.
pub struct ObjectEvaluation {
    /// Complete tenant/object identity.
    pub key: ObjectKey,
    /// Combined three-valued rule result.
    pub decision: Decision,
    /// All leaf outcomes in tree traversal order, even after a decisive branch.
    pub explanations: Vec<Explanation>,
    /// One provenance record per referenced field actually present in the input.
    pub provenance: BTreeMap<String, Provenance>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Evidence for one bounded page; it never represents a complete membership set.
pub struct PageEvaluation {
    /// Coverage copied from the validated snapshot.
    pub coverage: BTreeSet<String>,
    /// Tenant common to the rule and snapshot.
    pub tenant: rss_request_context::TenantId,
    /// Rule evidence identity used for this evaluation.
    pub rule_version: String,
    /// Shared dictionary evidence identity.
    pub dictionary_version: String,
    /// Input snapshot identity.
    pub snapshot_id: String,
    /// Input snapshot revision identity.
    pub snapshot_version: String,
    /// Explicit caller-provided evaluation time.
    pub as_of: Timepoint,
    /// One result per unique object, sorted by complete object key.
    pub objects: Vec<ObjectEvaluation>,
}
impl Rule {
    /// Evaluate one strictly ordered page of a frozen universe, without claiming
    /// that this page is the complete universe. The caller persists snapshot
    /// identity, coverage and the exclusive cursor, and seals completeness only
    /// after every page has been stored. Missing rule coverage is rejected;
    /// explicit Missing/Deleted/Conflict facts retain the usual Unknown semantics.
    /// Existing byte, visit and explanation budgets still apply to each page.
    pub fn evaluate_page(
        &self,
        snapshot: &crate::PageInput<'_>,
        as_of: Timepoint,
    ) -> Result<PageEvaluation> {
        LimitKind::Objects.check(snapshot.objects.len())?;
        if !self.required.is_subset(snapshot.coverage) {
            return Err(Error::IncompleteSnapshot);
        }
        if snapshot
            .after
            .is_some_and(|key| key.tenant() != self.tenant)
        {
            return Err(Error::TenantMismatch);
        }
        let mut previous = snapshot.after;
        for object in snapshot.objects {
            if previous.is_some_and(|key| key >= &object.key) {
                return Err(Error::InvalidStructure);
            }
            previous = Some(&object.key);
        }
        self.evaluate_input(snapshot, as_of, &mut Budget::new(LimitKind::BatchBytes))
    }

    fn evaluate_input(
        &self,
        s: &crate::PageInput<'_>,
        as_of: Timepoint,
        budget: &mut Budget,
    ) -> Result<PageEvaluation> {
        if self.tenant != s.tenant {
            return Err(Error::TenantMismatch);
        }
        budget.identity(s.id)?;
        budget.identity(s.version)?;
        budget.identity(s.dictionary_version)?;
        if s.dictionary_version != self.dictionary_version {
            return Err(Error::VersionMismatch);
        }
        LimitKind::Fields.check(s.coverage.len())?;
        for key in s.coverage {
            budget.identity(key)?;
            if !self.fields.contains_key(key) {
                return Err(Error::UnknownField);
            }
        }
        LimitKind::Objects.check(s.objects.len())?;
        LimitKind::Visits.product(s.objects.len(), self.criteria.count)?;
        let mut objects = BTreeMap::new();
        for object in s.objects {
            if object.key.tenant() != s.tenant {
                return Err(Error::TenantMismatch);
            }
            budget.text(object.key.id())?;
            LimitKind::Fields.check(object.facts.len())?;
            for (key, fact) in &object.facts {
                budget.identity(key)?;
                let field = self.fields.get(key).ok_or(Error::UnknownField)?;
                if !s.coverage.contains(key) {
                    return Err(Error::InvalidStructure);
                }
                budget.identity(&fact.source)?;
                budget.identity(&fact.snapshot_id)?;
                match &fact.state {
                    FactState::Known(value) => {
                        value.validate(budget)?;
                        if value.kind() != field.kind {
                            return Err(Error::InvalidType);
                        }
                    }
                    FactState::Null if !field.nullable => return Err(Error::InvalidType),
                    FactState::Denied => return Err(Error::PermissionDenied),
                    _ => {}
                }
            }
            if !s.coverage.iter().all(|key| object.facts.contains_key(key)) {
                return Err(Error::IncompleteSnapshot);
            }
            if let Some(previous) = objects.insert(&object.key, object)
                && previous != object
            {
                return Err(Error::ConflictingObject);
            }
        }
        let leaves = leaf_count(&self.criteria);
        LimitKind::Explanations.product(objects.len(), leaves)?;
        let objects = objects
            .values()
            .map(|object| {
                let mut explanations = Vec::with_capacity(leaves);
                let decision = evaluate_node(
                    &self.criteria,
                    &object.facts,
                    as_of,
                    &mut Vec::new(),
                    &mut explanations,
                );
                let provenance = self
                    .required
                    .iter()
                    .filter_map(|key| {
                        object.facts.get(key).map(|f| {
                            (
                                key.clone(),
                                Provenance {
                                    source: f.source.clone(),
                                    snapshot_id: f.snapshot_id.clone(),
                                    observed_at: f.observed_at,
                                },
                            )
                        })
                    })
                    .collect();
                ObjectEvaluation {
                    key: object.key.clone(),
                    decision,
                    explanations,
                    provenance,
                }
            })
            .collect();
        Ok(PageEvaluation {
            coverage: s.coverage.clone(),
            tenant: s.tenant,
            rule_version: self.version.clone(),
            dictionary_version: self.dictionary_version.clone(),
            snapshot_id: s.id.to_owned(),
            snapshot_version: s.version.to_owned(),
            as_of,
            objects,
        })
    }
}
fn evaluate_node(
    c: &Criteria,
    facts: &BTreeMap<String, Fact>,
    now: Timepoint,
    path: &mut Vec<usize>,
    out: &mut Vec<Explanation>,
) -> Decision {
    match &c.node {
        Node::Predicate(p) => {
            let outcome = predicate(
                facts.get(&p.field),
                p.op,
                p.operand.as_ref().map(|o| &o.value),
                now,
            );
            out.push(Explanation {
                path: path.clone(),
                outcome,
            });
            outcome.decision()
        }
        Node::And(children) | Node::Or(children) => {
            let and = matches!(c.node, Node::And(_));
            let decisive = if and {
                Decision::NoMatch
            } else {
                Decision::Match
            };
            let mut result = if and {
                Decision::Match
            } else {
                Decision::NoMatch
            };
            for (i, child) in children.iter().enumerate() {
                path.push(i);
                let value = evaluate_node(child, facts, now, path, out);
                path.pop();
                if value == decisive || (value == Decision::Unknown && result != decisive) {
                    result = value;
                }
            }
            result
        }
    }
}
fn predicate(fact: Option<&Fact>, op: Op, operand: Option<&Value>, _now: Timepoint) -> Outcome {
    use UnknownReason::*;
    let unknown = Outcome::Unknown;
    let Some(fact) = fact else {
        return unknown(Missing);
    };
    match fact.state {
        FactState::Missing => return unknown(Missing),
        FactState::Deleted => return unknown(Deleted),
        FactState::Conflict => return unknown(Conflict),
        FactState::Unsupported => return unknown(Unsupported),
        FactState::Denied => unreachable!("all facts are validated before evaluation"),
        _ => {}
    }
    let null = matches!(fact.state, FactState::Null);
    if op == Op::IsNull {
        return Outcome::from_bool(null);
    }
    if op == Op::IsNotNull {
        return Outcome::from_bool(!null);
    }
    let FactState::Known(value) = &fact.state else {
        return unknown(Null);
    };
    let operand = operand.expect("validated non-null predicate has operand");
    use Op::*;
    let result = match (value, operand, op) {
        (Value::Scalar(a), Value::Scalar(b), Eq) => a == b,
        (Value::Scalar(a), Value::Scalar(b), Ne) => a != b,
        (Value::Scalar(a), Value::Scalar(b), Lt) => a < b,
        (Value::Scalar(a), Value::Scalar(b), Le) => a <= b,
        (Value::Scalar(a), Value::Scalar(b), Gt) => a > b,
        (Value::Scalar(a), Value::Scalar(b), Ge) => a >= b,
        (Value::Scalar(a), Value::Set { values, .. }, In | NotIn) => {
            values.contains(a) == (op == In)
        }
        (
            Value::Scalar(Scalar::String(a)),
            Value::Scalar(Scalar::String(b)),
            Contains | NotContains,
        ) => a.contains(b) == (op == Contains),
        (Value::Set { values: a, .. }, Value::Set { values: b, .. }, ContainsAny) => {
            !a.is_disjoint(b)
        }
        (Value::Set { values: a, .. }, Value::Set { values: b, .. }, ContainsAll) => b.is_subset(a),
        _ => unreachable!("rule and fact types are validated before evaluation"),
    };
    Outcome::from_bool(result)
}

fn leaf_count(c: &Criteria) -> usize {
    match &c.node {
        Node::Predicate(_) => 1,
        Node::And(children) | Node::Or(children) => children.iter().map(leaf_count).sum(),
    }
}
