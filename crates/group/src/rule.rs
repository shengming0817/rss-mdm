use crate::{Error, Field, FieldType, Op, Predicate, Result, ScalarType, bound, identity, limits};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    Predicate(Predicate),
    And(Vec<Criteria>),
    Or(Vec<Criteria>),
}
/// Bounded AST. Private nodes prevent constructing a deeply recursive unvalidated tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Criteria {
    pub(crate) node: Node,
    pub(crate) count: usize,
    depth: usize,
}
impl Criteria {
    pub fn predicate(predicate: Predicate) -> Result<Self> {
        let mut bytes = 0;
        identity(&predicate.field, &mut bytes)?;
        if let Some(operand) = &predicate.operand {
            operand.value.validate(&mut bytes)?;
            if let Some(unit) = &operand.unit {
                identity(unit, &mut bytes)?;
            }
        }
        bound(bytes, limits::RULE_BYTES)?;
        Ok(Self {
            node: Node::Predicate(predicate),
            count: 1,
            depth: 1,
        })
    }
    pub fn and(children: Vec<Self>) -> Result<Self> {
        Self::group(children, true)
    }
    pub fn or(children: Vec<Self>) -> Result<Self> {
        Self::group(children, false)
    }
    fn group(children: Vec<Self>, and: bool) -> Result<Self> {
        if children.is_empty() {
            return Err(Error::InvalidStructure);
        }
        bound(children.len(), limits::NODES - 1)?;
        let count = children.iter().try_fold(1usize, |n, c| {
            n.checked_add(c.count).ok_or(Error::LimitExceeded)
        })?;
        let depth = 1 + children.iter().map(|c| c.depth).max().unwrap_or(0);
        bound(count, limits::NODES)?;
        bound(depth, limits::DEPTH)?;
        Ok(Self {
            node: if and {
                Node::And(children)
            } else {
                Node::Or(children)
            },
            count,
            depth,
        })
    }
}
/// One immutable, completely validated rule/dictionary pair. Versions are opaque evidence IDs.
#[derive(Clone, Debug)]
pub struct Rule {
    pub(crate) version: String,
    pub(crate) dictionary_version: String,
    pub(crate) fields: BTreeMap<String, Field>,
    pub(crate) criteria: Criteria,
    pub(crate) required: BTreeSet<String>,
}
impl Rule {
    /// Resolve an explanation path without copying field names or values into every trace entry.
    pub fn predicate_at(&self, path: &[usize]) -> Option<&Predicate> {
        let mut current = &self.criteria;
        for index in path {
            current = match &current.node {
                Node::And(children) | Node::Or(children) => children.get(*index)?,
                Node::Predicate(_) => return None,
            };
        }
        match &current.node {
            Node::Predicate(p) => Some(p),
            _ => None,
        }
    }
    pub fn new(
        version: impl Into<String>,
        dictionary_version: impl Into<String>,
        fields: Vec<Field>,
        criteria: Criteria,
    ) -> Result<Self> {
        let (version, dictionary_version) = (version.into(), dictionary_version.into());
        let mut bytes = 0;
        identity(&version, &mut bytes)?;
        identity(&dictionary_version, &mut bytes)?;
        bound(fields.len(), limits::FIELDS)?;
        let mut dictionary = BTreeMap::new();
        for field in fields {
            identity(&field.key, &mut bytes)?;
            if let Some(unit) = &field.unit {
                identity(unit, &mut bytes)?;
            }
            if field.operations.is_empty() || field.operations.iter().any(|op| !allows(&field, *op))
            {
                return Err(Error::InvalidOperation);
            }
            if dictionary.insert(field.key.clone(), field).is_some() {
                return Err(Error::InvalidStructure);
            }
        }
        let mut rule = Self {
            version,
            dictionary_version,
            fields: dictionary,
            criteria,
            required: BTreeSet::new(),
        };
        validate(&rule.criteria, &rule.fields, &mut rule.required, &mut bytes)?;
        bound(bytes, limits::RULE_BYTES)?;
        Ok(rule)
    }
}
fn allows(field: &Field, op: Op) -> bool {
    use Op::*;
    match op {
        IsNull | IsNotNull => field.nullable,
        Eq | Ne | In | NotIn => matches!(field.kind, FieldType::Scalar(_)),
        Lt | Le | Gt | Ge => matches!(
            field.kind,
            FieldType::Scalar(ScalarType::Integer | ScalarType::Time)
        ),
        Contains | NotContains => field.kind == FieldType::Scalar(ScalarType::String),
        ContainsAny | ContainsAll => matches!(field.kind, FieldType::Set(_)),
    }
}
fn validate(
    c: &Criteria,
    fields: &BTreeMap<String, Field>,
    required: &mut BTreeSet<String>,
    bytes: &mut usize,
) -> Result<()> {
    match &c.node {
        Node::And(children) | Node::Or(children) => {
            for c in children {
                validate(c, fields, required, bytes)?;
            }
        }
        Node::Predicate(p) => {
            identity(&p.field, bytes)?;
            let field = fields.get(&p.field).ok_or(Error::UnknownField)?;
            required.insert(p.field.clone());
            if !field.operations.contains(&p.op) {
                return Err(Error::InvalidOperation);
            }
            if matches!(p.op, Op::IsNull | Op::IsNotNull) {
                if p.operand.is_some() {
                    return Err(Error::InvalidOperation);
                }
            } else {
                let operand = p.operand.as_ref().ok_or(Error::InvalidOperation)?;
                operand.value.validate(bytes)?;
                if let Some(unit) = &operand.unit {
                    identity(unit, bytes)?;
                }
                if operand.unit != field.unit {
                    return Err(Error::InvalidUnit);
                }
                let expected = match (p.op, field.kind) {
                    (Op::In | Op::NotIn, FieldType::Scalar(t)) => FieldType::Set(t),
                    _ => field.kind,
                };
                if operand.value.kind() != expected {
                    return Err(Error::InvalidType);
                }
            }
        }
    }
    Ok(())
}
