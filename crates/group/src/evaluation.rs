use crate::model::{difference, members};
use crate::rule::{Criteria, Node};
use crate::{
    Error, Fact, FactState, ObjectKey, Op, Result, Rule, Scalar, Snapshot, Value, bound, identity,
    limits, text,
};
use rss_contract::Timepoint;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Match,
    NoMatch,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    Null,
    Missing,
    Stale,
    Unsupported,
    Future,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Match,
    NoMatch,
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
    pub path: Vec<usize>,
    pub outcome: Outcome,
}
/// Provenance is stored once per referenced field, not duplicated for every predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub source: String,
    pub snapshot_id: String,
    pub observed_at: Timepoint,
    pub valid_until: Option<Timepoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEvaluation {
    pub key: ObjectKey,
    pub decision: Decision,
    pub explanations: Vec<Explanation>,
    pub provenance: BTreeMap<String, Provenance>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub tenant: rss_request_context::TenantId,
    pub rule_version: String,
    pub dictionary_version: String,
    pub snapshot_id: String,
    pub snapshot_version: String,
    pub as_of: Timepoint,
    pub objects: Vec<ObjectEvaluation>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recalculation {
    pub evaluation: Evaluation,
    pub difference: crate::Difference,
    pub unknown: Vec<ObjectKey>,
}
impl Rule {
    /// Preview accepts partial coverage. Uncovered referenced fields produce Unknown(Missing).
    /// Every input is validated before any result is returned, including unused fields.
    pub fn evaluate(&self, snapshot: &Snapshot, as_of: Timepoint) -> Result<Evaluation> {
        self.evaluate_inner(snapshot, as_of, &mut 0)
    }
    /// Only a complete candidate universe may produce a replacement membership set.
    /// An old member now Unknown is removed and is also listed in `unknown`.
    pub fn recalculate(
        &self,
        snapshot: &Snapshot,
        as_of: Timepoint,
        old: &[ObjectKey],
    ) -> Result<Recalculation> {
        if !snapshot.complete || !self.required.is_subset(&snapshot.coverage) {
            return Err(Error::IncompleteSnapshot);
        }
        let mut bytes = 0;
        let old = members(snapshot.tenant, old, &mut bytes)?;
        let evaluation = self.evaluate_inner(snapshot, as_of, &mut bytes)?;
        let new: BTreeSet<_> = evaluation
            .objects
            .iter()
            .filter(|o| o.decision == Decision::Match)
            .map(|o| o.key.clone())
            .collect();
        let unknown = evaluation
            .objects
            .iter()
            .filter(|o| o.decision == Decision::Unknown)
            .map(|o| o.key.clone())
            .collect();
        Ok(Recalculation {
            difference: difference(&old, &new),
            evaluation,
            unknown,
        })
    }
    fn evaluate_inner(
        &self,
        s: &Snapshot,
        as_of: Timepoint,
        bytes: &mut usize,
    ) -> Result<Evaluation> {
        identity(&s.id, bytes)?;
        identity(&s.version, bytes)?;
        identity(&s.dictionary_version, bytes)?;
        if s.dictionary_version != self.dictionary_version {
            return Err(Error::VersionMismatch);
        }
        bound(s.coverage.len(), limits::FIELDS)?;
        for key in &s.coverage {
            identity(key, bytes)?;
            if !self.fields.contains_key(key) {
                return Err(Error::UnknownField);
            }
        }
        if s.complete && !self.required.is_subset(&s.coverage) {
            return Err(Error::IncompleteSnapshot);
        }
        bound(s.objects.len(), limits::OBJECTS)?;
        bound(
            s.objects
                .len()
                .checked_mul(self.criteria.count)
                .ok_or(Error::LimitExceeded)?,
            limits::VISITS,
        )?;
        let mut objects = BTreeMap::new();
        for object in &s.objects {
            if object.key.tenant() != s.tenant {
                return Err(Error::TenantMismatch);
            }
            text(object.key.id(), bytes)?;
            bound(object.facts.len(), limits::FIELDS)?;
            for (key, fact) in &object.facts {
                identity(key, bytes)?;
                let field = self.fields.get(key).ok_or(Error::UnknownField)?;
                if !s.coverage.contains(key) {
                    return Err(Error::InvalidStructure);
                }
                identity(&fact.source, bytes)?;
                identity(&fact.snapshot_id, bytes)?;
                if fact.valid_until.is_some_and(|end| end <= fact.observed_at) {
                    return Err(Error::InvalidTime);
                }
                match &fact.state {
                    FactState::Known(value) => {
                        value.validate(bytes)?;
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
            bound(*bytes, limits::BATCH_BYTES)?;
        }
        bound(*bytes, limits::BATCH_BYTES)?;
        let objects = objects
            .values()
            .map(|object| {
                let mut explanations = Vec::new();
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
                                    valid_until: f.valid_until,
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
        Ok(Evaluation {
            tenant: s.tenant,
            rule_version: self.version.clone(),
            dictionary_version: self.dictionary_version.clone(),
            snapshot_id: s.id.clone(),
            snapshot_version: s.version.clone(),
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
fn predicate(fact: Option<&Fact>, op: Op, operand: Option<&Value>, now: Timepoint) -> Outcome {
    use UnknownReason::*;
    let unknown = Outcome::Unknown;
    let Some(fact) = fact else {
        return unknown(Missing);
    };
    match fact.state {
        FactState::Missing => return unknown(Missing),
        FactState::Unsupported => return unknown(Unsupported),
        FactState::Denied => unreachable!("all facts are validated before evaluation"),
        _ => {}
    }
    if now < fact.observed_at {
        return unknown(Future);
    }
    if fact.valid_until.is_some_and(|end| now >= end) {
        return unknown(Stale);
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
