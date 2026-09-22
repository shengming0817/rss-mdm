//! The adapter's only storage encoding. Core validation remains authoritative.
use rss_contract::Timepoint;
use rss_mdm_group::*;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

/// Encoded storage budget, in addition to the core's semantic budgets.
pub(crate) const MAX_DOCUMENT: usize = 64 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
#[error("invalid Group storage document")]
pub(crate) struct Invalid;
type Result<T> = std::result::Result<T, Invalid>;
fn check(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Invalid) }
}
fn time(t: i64) -> Result<Timepoint> {
    t.try_into().map_err(|_| Invalid)
}
fn tenant(t: &str) -> Result<TenantId> {
    TenantId::parse(t).map_err(|_| Invalid)
}
pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(v).map_err(|_| Invalid)?;
    check(bytes.len() <= MAX_DOCUMENT)?;
    Ok(bytes)
}
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    check(bytes.len() <= MAX_DOCUMENT)?;
    serde_json::from_slice(bytes).map_err(|_| Invalid)
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Literal {
    String(String),
    Boolean(bool),
    Integer(i64),
    Time(i64),
}
fn literal(v: &Scalar) -> Literal {
    match v {
        Scalar::String(s) => Literal::String(s.clone()),
        Scalar::Boolean(b) => Literal::Boolean(*b),
        Scalar::Integer(i) => Literal::Integer(*i),
        Scalar::Time(t) => Literal::Time(t.unix_seconds()),
    }
}
fn scalar(v: Literal) -> Result<Scalar> {
    Ok(match v {
        Literal::String(s) => {
            check(s.len() <= limits::STRING_BYTES)?;
            Scalar::String(s)
        }
        Literal::Boolean(b) => Scalar::Boolean(b),
        Literal::Integer(i) => Scalar::Integer(i),
        Literal::Time(t) => Scalar::Time(time(t)?),
    })
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    String,
    Boolean,
    Integer,
    Time,
}
fn kind(k: ScalarType) -> Kind {
    match k {
        ScalarType::String => Kind::String,
        ScalarType::Boolean => Kind::Boolean,
        ScalarType::Integer => Kind::Integer,
        ScalarType::Time => Kind::Time,
    }
}
fn scalar_type(k: Kind) -> ScalarType {
    match k {
        Kind::String => ScalarType::String,
        Kind::Boolean => ScalarType::Boolean,
        Kind::Integer => ScalarType::Integer,
        Kind::Time => ScalarType::Time,
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Val {
    Scalar { value: Literal },
    Set { element: Kind, values: Vec<Literal> },
}
fn val(v: &Value) -> Val {
    match v {
        Value::Scalar(v) => Val::Scalar { value: literal(v) },
        Value::Set { element, values } => Val::Set {
            element: kind(*element),
            values: values.iter().map(literal).collect(),
        },
    }
}
fn value(v: Val) -> Result<Value> {
    Ok(match v {
        Val::Scalar { value: v } => Value::Scalar(scalar(v)?),
        Val::Set { element, values } => {
            check(values.len() <= limits::SET_ITEMS)?;
            let size = values.len();
            let values = values
                .into_iter()
                .map(scalar)
                .collect::<Result<BTreeSet<_>>>()?;
            check(values.len() == size && values.iter().all(|s| s.kind() == scalar_type(element)))?;
            Value::Set {
                element: scalar_type(element),
                values,
            }
        }
    })
}
fn op(o: Op) -> &'static str {
    match o {
        Op::Eq => "eq",
        Op::Ne => "ne",
        Op::In => "in",
        Op::NotIn => "not_in",
        Op::Lt => "lt",
        Op::Le => "le",
        Op::Gt => "gt",
        Op::Ge => "ge",
        Op::Contains => "contains",
        Op::NotContains => "not_contains",
        Op::ContainsAny => "contains_any",
        Op::ContainsAll => "contains_all",
        Op::IsNull => "is_null",
        Op::IsNotNull => "is_not_null",
    }
}
fn operation(s: &str) -> Result<Op> {
    Ok(match s {
        "eq" => Op::Eq,
        "ne" => Op::Ne,
        "in" => Op::In,
        "not_in" => Op::NotIn,
        "lt" => Op::Lt,
        "le" => Op::Le,
        "gt" => Op::Gt,
        "ge" => Op::Ge,
        "contains" => Op::Contains,
        "not_contains" => Op::NotContains,
        "contains_any" => Op::ContainsAny,
        "contains_all" => Op::ContainsAll,
        "is_null" => Op::IsNull,
        "is_not_null" => Op::IsNotNull,
        _ => return Err(Invalid),
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldDoc {
    key: String,
    element: Kind,
    set: bool,
    unit: Option<String>,
    operations: Vec<String>,
    nullable: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperandDoc {
    value: Val,
    unit: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NodeDoc {
    Predicate {
        field: String,
        op: String,
        operand: Option<OperandDoc>,
    },
    And {
        children: Vec<usize>,
    },
    Or {
        children: Vec<usize>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDoc {
    v: u8,
    tenant: String,
    version: String,
    dictionary_version: String,
    fields: Vec<FieldDoc>,
    nodes: Vec<NodeDoc>,
}
fn nodes(c: &Criteria, out: &mut Vec<NodeDoc>) -> usize {
    let node = match c.view() {
        CriteriaView::Predicate(p) => NodeDoc::Predicate {
            field: p.field.clone(),
            op: op(p.op).into(),
            operand: p.operand.as_ref().map(|o| OperandDoc {
                value: val(&o.value),
                unit: o.unit.clone(),
            }),
        },
        CriteriaView::And(children) => NodeDoc::And {
            children: children.iter().map(|c| nodes(c, out)).collect(),
        },
        CriteriaView::Or(children) => NodeDoc::Or {
            children: children.iter().map(|c| nodes(c, out)).collect(),
        },
    };
    let i = out.len();
    out.push(node);
    i
}
pub(crate) fn encode_rule(rule: &Rule) -> Result<Vec<u8>> {
    let v = rule.view();
    let mut tree = Vec::new();
    nodes(v.criteria, &mut tree);
    let fields = v
        .fields
        .values()
        .map(|f| {
            let (element, set) = match f.kind {
                FieldType::Scalar(t) => (kind(t), false),
                FieldType::Set(t) => (kind(t), true),
            };
            FieldDoc {
                key: f.key.clone(),
                element,
                set,
                unit: f.unit.clone(),
                operations: f.operations.iter().map(|o| op(*o).into()).collect(),
                nullable: f.nullable,
            }
        })
        .collect();
    encode(&RuleDoc {
        v: 1,
        tenant: v.tenant.to_string(),
        version: v.version.into(),
        dictionary_version: v.dictionary_version.into(),
        fields,
        nodes: tree,
    })
}
pub(crate) fn decode_rule(bytes: &[u8]) -> Result<Rule> {
    let d: RuleDoc = decode(bytes)?;
    check(
        d.v == 1
            && d.fields.len() <= limits::FIELDS
            && !d.nodes.is_empty()
            && d.nodes.len() <= limits::NODES,
    )?;
    let fields = d
        .fields
        .into_iter()
        .map(|f| {
            let kind = if f.set {
                FieldType::Set(scalar_type(f.element))
            } else {
                FieldType::Scalar(scalar_type(f.element))
            };
            Ok(Field {
                key: f.key,
                kind,
                unit: f.unit,
                operations: f
                    .operations
                    .iter()
                    .map(|s| operation(s))
                    .collect::<Result<_>>()?,
                nullable: f.nullable,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut built: Vec<Option<Criteria>> = Vec::new();
    for n in d.nodes {
        let c = match n {
            NodeDoc::Predicate { field, op, operand } => Criteria::predicate(Predicate {
                field,
                op: operation(&op)?,
                operand: operand
                    .map(|o| {
                        Ok(Operand {
                            value: value(o.value)?,
                            unit: o.unit,
                        })
                    })
                    .transpose()?,
            }),
            NodeDoc::And { children } => Criteria::and(take_children(children, &mut built)?),
            NodeDoc::Or { children } => Criteria::or(take_children(children, &mut built)?),
        }
        .map_err(|_| Invalid)?;
        built.push(Some(c));
    }
    let root = built.pop().flatten().ok_or(Invalid)?;
    check(built.iter().all(Option::is_none))?;
    Rule::new(
        tenant(&d.tenant)?,
        d.version,
        d.dictionary_version,
        fields,
        root,
    )
    .map_err(|_| Invalid)
}
fn take_children(indices: Vec<usize>, built: &mut [Option<Criteria>]) -> Result<Vec<Criteria>> {
    check(indices.len() <= limits::NODES)?;
    indices
        .into_iter()
        .map(|i| built.get_mut(i).and_then(Option::take).ok_or(Invalid))
        .collect()
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum State {
    Known(Val),
    Null,
    Missing,
    Unsupported,
    Denied,
    Deleted,
    Conflict,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactDoc {
    state: State,
    source: String,
    snapshot_id: String,
    observed_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectDoc {
    id: String,
    facts: BTreeMap<String, FactDoc>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDoc {
    v: u8,
    tenant: String,
    id: String,
    version: String,
    dictionary_version: String,
    complete: bool,
    coverage: BTreeSet<String>,
    objects: Vec<ObjectDoc>,
}
pub(crate) fn encode_snapshot(s: &Snapshot) -> Result<Vec<u8>> {
    check(s.objects.len() <= limits::OBJECTS)?;
    let mut unique = BTreeMap::new();
    for o in &s.objects {
        check(o.key.tenant() == s.tenant)?;
        if let Some(old) = unique.insert(o.key.clone(), o) {
            check(old == o)?;
        }
    }
    let objects = unique
        .values()
        .map(|o| ObjectDoc {
            id: o.key.id().into(),
            facts: o
                .facts
                .iter()
                .map(|(k, f)| {
                    let state = match &f.state {
                        FactState::Known(v) => State::Known(val(v)),
                        FactState::Null => State::Null,
                        FactState::Missing => State::Missing,
                        FactState::Unsupported => State::Unsupported,
                        FactState::Denied => State::Denied,
                        FactState::Deleted => State::Deleted,
                        FactState::Conflict => State::Conflict,
                    };
                    (
                        k.clone(),
                        FactDoc {
                            state,
                            source: f.source.clone(),
                            snapshot_id: f.snapshot_id.clone(),
                            observed_at: f.observed_at.unix_seconds(),
                        },
                    )
                })
                .collect(),
        })
        .collect();
    encode(&SnapshotDoc {
        v: 2,
        tenant: s.tenant.to_string(),
        id: s.id.clone(),
        version: s.version.clone(),
        dictionary_version: s.dictionary_version.clone(),
        complete: s.complete,
        coverage: s.coverage.clone(),
        objects,
    })
}
pub(crate) fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    let d: SnapshotDoc = decode(bytes)?;
    check(d.v == 2 && d.objects.len() <= limits::OBJECTS && d.coverage.len() <= limits::FIELDS)?;
    let tenant = tenant(&d.tenant)?;
    let objects = d
        .objects
        .into_iter()
        .map(|o| {
            check(o.facts.len() <= limits::FIELDS)?;
            let facts = o
                .facts
                .into_iter()
                .map(|(k, f)| {
                    let state = match f.state {
                        State::Known(v) => FactState::Known(value(v)?),
                        State::Null => FactState::Null,
                        State::Missing => FactState::Missing,
                        State::Unsupported => FactState::Unsupported,
                        State::Denied => FactState::Denied,
                        State::Deleted => FactState::Deleted,
                        State::Conflict => FactState::Conflict,
                    };
                    Ok((
                        k,
                        Fact {
                            state,
                            source: f.source,
                            snapshot_id: f.snapshot_id,
                            observed_at: time(f.observed_at)?,
                        },
                    ))
                })
                .collect::<Result<_>>()?;
            Ok(ObjectSnapshot {
                key: ObjectKey::new(tenant, o.id).map_err(|_| Invalid)?,
                facts,
            })
        })
        .collect::<Result<_>>()?;
    Ok(Snapshot {
        tenant,
        id: d.id,
        version: d.version,
        dictionary_version: d.dictionary_version,
        complete: d.complete,
        coverage: d.coverage,
        objects,
    })
}
fn outcome(o: Outcome) -> &'static str {
    match o {
        Outcome::Match => "match",
        Outcome::NoMatch => "no_match",
        Outcome::Unknown(r) => match r {
            UnknownReason::Null => "null",
            UnknownReason::Missing => "missing",
            UnknownReason::Deleted => "deleted",
            UnknownReason::Unsupported => "unsupported",
            UnknownReason::Conflict => "conflict",
        },
    }
}
fn read_outcome(s: &str) -> Result<Outcome> {
    Ok(match s {
        "match" => Outcome::Match,
        "no_match" => Outcome::NoMatch,
        "null" => Outcome::Unknown(UnknownReason::Null),
        "missing" => Outcome::Unknown(UnknownReason::Missing),
        "deleted" => Outcome::Unknown(UnknownReason::Deleted),
        "unsupported" => Outcome::Unknown(UnknownReason::Unsupported),
        "conflict" => Outcome::Unknown(UnknownReason::Conflict),
        _ => return Err(Invalid),
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionDoc {
    id: String,
    decision: String,
    leaves: Vec<(Vec<usize>, String)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultDoc {
    v: u8,
    objects: Vec<DecisionDoc>,
    added: Vec<String>,
    removed: Vec<String>,
}
pub(crate) fn encode_result(r: &Recalculation) -> Result<Vec<u8>> {
    let objects = r
        .evaluation
        .objects
        .iter()
        .map(|o| DecisionDoc {
            id: o.key.id().into(),
            decision: match o.decision {
                Decision::Match => "match",
                Decision::NoMatch => "no_match",
                Decision::Unknown => "unknown",
            }
            .into(),
            leaves: o
                .explanations
                .iter()
                .map(|e| (e.path.clone(), outcome(e.outcome).into()))
                .collect(),
        })
        .collect();
    encode(&ResultDoc {
        v: 2,
        objects,
        added: r.difference.added.iter().map(|o| o.id().into()).collect(),
        removed: r.difference.removed.iter().map(|o| o.id().into()).collect(),
    })
}
/// Read persisted decisions; deliberately never invokes Rule::evaluate/recalculate.
pub(crate) fn decode_result(
    bytes: &[u8],
    rule: &Rule,
    s: &Snapshot,
    as_of: Timepoint,
) -> Result<Recalculation> {
    let d: ResultDoc = decode(bytes)?;
    check(d.v == 2 && d.objects.len() <= limits::OBJECTS)?;
    let input: BTreeMap<_, _> = s.objects.iter().map(|o| (&o.key, o)).collect();
    let mut objects = Vec::new();
    let mut seen = BTreeSet::new();
    let mut explanations = 0usize;
    for o in d.objects {
        let key = ObjectKey::new(s.tenant, o.id).map_err(|_| Invalid)?;
        check(seen.insert(key.clone()))?;
        let original = input.get(&key).ok_or(Invalid)?;
        explanations = explanations.checked_add(o.leaves.len()).ok_or(Invalid)?;
        check(explanations <= limits::EXPLANATIONS)?;
        let mut provenance = BTreeMap::new();
        let leaves = o
            .leaves
            .into_iter()
            .map(|(path, result)| {
                check(path.len() <= limits::DEPTH)?;
                let p = rule.predicate_at(&path).ok_or(Invalid)?;
                if let Some(f) = original.facts.get(&p.field) {
                    provenance.insert(
                        p.field.clone(),
                        Provenance {
                            source: f.source.clone(),
                            snapshot_id: f.snapshot_id.clone(),
                            observed_at: f.observed_at,
                        },
                    );
                }
                Ok(Explanation {
                    path,
                    outcome: read_outcome(&result)?,
                })
            })
            .collect::<Result<_>>()?;
        let decision = match o.decision.as_str() {
            "match" => Decision::Match,
            "no_match" => Decision::NoMatch,
            "unknown" => Decision::Unknown,
            _ => return Err(Invalid),
        };
        objects.push(ObjectEvaluation {
            key,
            decision,
            explanations: leaves,
            provenance,
        });
    }
    check(seen.len() == input.len())?;
    let added = read_keys(s.tenant, d.added)?;
    let removed = read_keys(s.tenant, d.removed)?;
    let new: BTreeSet<_> = objects
        .iter()
        .filter(|o| o.decision == Decision::Match)
        .map(|o| o.key.clone())
        .collect();
    check(added.iter().all(|k| new.contains(k)) && removed.iter().all(|k| !new.contains(k)))?;
    let added_set: BTreeSet<_> = added.iter().cloned().collect();
    let unchanged = new.difference(&added_set).cloned().collect();
    let unknown = objects
        .iter()
        .filter(|o| o.decision == Decision::Unknown)
        .map(|o| o.key.clone())
        .collect();
    Ok(Recalculation {
        evaluation: Evaluation {
            complete: s.complete,
            coverage: s.coverage.clone(),
            tenant: s.tenant,
            rule_version: rule.view().version.into(),
            dictionary_version: s.dictionary_version.clone(),
            snapshot_id: s.id.clone(),
            snapshot_version: s.version.clone(),
            as_of,
            objects,
        },
        difference: Difference {
            tenant: s.tenant,
            added,
            removed,
            unchanged,
        },
        unknown,
    })
}
fn read_keys(tenant: TenantId, items: Vec<String>) -> Result<Vec<ObjectKey>> {
    check(items.len() <= limits::OBJECTS)?;
    let n = items.len();
    let keys = items
        .into_iter()
        .map(|id| ObjectKey::new(tenant, id).map_err(|_| Invalid))
        .collect::<Result<BTreeSet<_>>>()?;
    check(keys.len() == n)?;
    Ok(keys.into_iter().collect())
}
