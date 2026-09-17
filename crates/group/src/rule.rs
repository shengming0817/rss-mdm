use crate::{Budget, Error, Field, FieldType, LimitKind, Op, Predicate, Result, ScalarType};
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
/// Read-only structural view. Construction still goes through the bounded builders.
#[derive(Clone, Copy, Debug)]
pub enum CriteriaView<'a> {
    /// One leaf comparison.
    Predicate(&'a Predicate),
    /// Nonempty conjunction; any NoMatch dominates Unknown.
    And(&'a [Criteria]),
    /// Nonempty disjunction; any Match dominates Unknown.
    Or(&'a [Criteria]),
}
impl Criteria {
    /// Borrow the validated tree without exposing mutable nodes or cached budgets.
    pub fn view(&self) -> CriteriaView<'_> {
        match &self.node {
            Node::Predicate(p) => CriteriaView::Predicate(p),
            Node::And(children) => CriteriaView::And(children),
            Node::Or(children) => CriteriaView::Or(children),
        }
    }
    /// Build one bounded leaf; dictionary/operator compatibility is checked by Rule::new.
    /// Rejects invalid identifiers, heterogeneous sets and string/collection budget overflow.
    pub fn predicate(predicate: Predicate) -> Result<Self> {
        let mut budget = Budget::new(LimitKind::RuleBytes);
        budget.identity(&predicate.field)?;
        if let Some(operand) = &predicate.operand {
            operand.value.validate(&mut budget)?;
            if let Some(unit) = &operand.unit {
                budget.identity(unit)?;
            }
        }
        Ok(Self {
            node: Node::Predicate(predicate),
            count: 1,
            depth: 1,
        })
    }
    /// Nonempty conjunction. Rejects node/depth overflow before constructing a recursive parent.
    pub fn and(children: Vec<Self>) -> Result<Self> {
        Self::group(children, true)
    }
    /// Nonempty disjunction with the same construction budgets as and.
    pub fn or(children: Vec<Self>) -> Result<Self> {
        Self::group(children, false)
    }
    fn group(children: Vec<Self>, and: bool) -> Result<Self> {
        if children.is_empty() {
            return Err(Error::InvalidStructure);
        }
        LimitKind::Nodes.check(children.len())?;
        let mut count = 1;
        for child in &children {
            LimitKind::Nodes.add(&mut count, child.count)?;
        }
        let depth = 1 + children.iter().map(|c| c.depth).max().unwrap_or(0);
        LimitKind::Depth.check(depth)?;
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
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) version: String,
    pub(crate) dictionary_version: String,
    pub(crate) fields: BTreeMap<String, Field>,
    pub(crate) criteria: Criteria,
    pub(crate) required: BTreeSet<String>,
}
/// Borrowed canonical inputs for persistence owned by a consumer.
#[derive(Clone, Copy, Debug)]
pub struct RuleView<'a> {
    /// Tenant to which this rule applies.
    pub tenant: rss_request_context::TenantId,
    /// Immutable rule evidence identity.
    pub version: &'a str,
    /// Dictionary evidence identity expected on input snapshots.
    pub dictionary_version: &'a str,
    /// Validated dictionary in field-key order.
    pub fields: &'a BTreeMap<String, Field>,
    /// Validated immutable bounded predicate tree.
    pub criteria: &'a Criteria,
}
impl Rule {
    /// Observe immutable validated inputs; this defines no storage format.
    pub fn view(&self) -> RuleView<'_> {
        RuleView {
            tenant: self.tenant,
            version: &self.version,
            dictionary_version: &self.dictionary_version,
            fields: &self.fields,
            criteria: &self.criteria,
        }
    }
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
    /// Bind a tenant and immutable evidence versions to a fully validated dictionary/AST.
    /// Rejects duplicate/unknown fields, incompatible operators/types/units and budget overflow.
    /// Versions identify caller-owned inputs; no legacy format or version dispatch is performed.
    pub fn new(
        tenant: rss_request_context::TenantId,
        version: impl Into<String>,
        dictionary_version: impl Into<String>,
        fields: Vec<Field>,
        criteria: Criteria,
    ) -> Result<Self> {
        let (version, dictionary_version) = (version.into(), dictionary_version.into());
        let mut budget = Budget::new(LimitKind::RuleBytes);
        budget.identity(&version)?;
        budget.identity(&dictionary_version)?;
        LimitKind::Fields.check(fields.len())?;
        let mut dictionary = BTreeMap::new();
        for field in fields {
            budget.identity(&field.key)?;
            if let Some(unit) = &field.unit {
                budget.identity(unit)?;
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
            tenant,
            version,
            dictionary_version,
            fields: dictionary,
            criteria,
            required: BTreeSet::new(),
        };
        validate(
            &rule.criteria,
            &rule.fields,
            &mut rule.required,
            &mut budget,
        )?;
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
    budget: &mut Budget,
) -> Result<()> {
    match &c.node {
        Node::And(children) | Node::Or(children) => {
            for c in children {
                validate(c, fields, required, budget)?;
            }
        }
        Node::Predicate(p) => {
            budget.identity(&p.field)?;
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
                operand.value.validate(budget)?;
                if let Some(unit) = &operand.unit {
                    budget.identity(unit)?;
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
