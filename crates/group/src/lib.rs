#![deny(missing_docs)]
//! Pure, tenant-scoped Group rules. Preview and recalculation share one evaluator.
//! No legacy expression/JSON/SQL interpreter, group references, I/O or system clock.
//! Snapshot completeness and authorization are caller assertions, not authentication.
//!
//! A minimal typed rule and complete snapshot, with caller-provided provenance and time:
//!
//! ```
//! use std::collections::{BTreeMap, BTreeSet};
//! use rss_mdm_group::*;
//! use rss_request_context::TenantId;
//! use rss_contract::Timepoint;
//! let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111")?;
//! let now = Timepoint::try_from(10)?;
//! let field = Field {
//!     key: "device.model".into(), kind: FieldType::Scalar(ScalarType::String),
//!     unit: None, operations: BTreeSet::from([Op::Eq]), nullable: false,
//! };
//! let value = Value::Scalar(Scalar::String("Laptop".into()));
//! let criteria = Criteria::predicate(Predicate { field: field.key.clone(), op: Op::Eq,
//!     operand: Some(Operand { value: value.clone(), unit: None }) })?;
//! let rule = Rule::new(tenant, "rule-1", "fields-1", vec![field], criteria)?;
//! let key = ObjectKey::new(tenant, "device-1")?;
//! let snapshot = Snapshot {
//!     tenant, id: "assets".into(), version: "revision-1".into(),
//!     dictionary_version: "fields-1".into(), complete: true,
//!     coverage: BTreeSet::from(["device.model".into()]),
//!     objects: vec![ObjectSnapshot { key: key.clone(), facts: BTreeMap::from([
//!         ("device.model".into(), Fact { state: FactState::Known(value),
//!             source: "inventory".into(), snapshot_id: "collection-1".into(),
//!             observed_at: now, valid_until: None })
//!     ]) }],
//! };
//! assert_eq!(rule.evaluate(&snapshot, now)?.objects[0].decision, Decision::Match);
//! let result = rule.recalculate(&snapshot, now, &[])?;
//! assert_eq!(result.difference.added, vec![key]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Standalone set difference also works without any rule:
//!
//! ```
//! use rss_mdm_group::{diff, ObjectKey};
//! use rss_request_context::TenantId;
//! let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111")?;
//! let device = ObjectKey::new(tenant, "device-1")?;
//! let change = diff(tenant, &[], std::slice::from_ref(&device))?;
//! assert_eq!(change.added, vec![device]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
mod evaluation;
mod model;
mod rule;
pub use evaluation::{
    Decision, Evaluation, Explanation, ObjectEvaluation, Outcome, Provenance, Recalculation,
    UnknownReason,
};
pub use model::{
    Difference, Fact, FactState, Field, FieldType, ObjectKey, ObjectSnapshot, Op, Operand,
    Predicate, Scalar, ScalarType, Snapshot, Value, diff,
};
pub use rule::{Criteria, CriteriaView, Rule, RuleView};

/// Closed diagnostics never contain fact values or caller-supplied strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An identity is blank or contains control characters.
    InvalidIdentity,
    /// A tree, dictionary or fact/coverage relationship is malformed.
    InvalidStructure,
    /// A predicate or snapshot names a field outside the dictionary.
    UnknownField,
    /// A value, set element or nullable fact has the wrong declared type.
    InvalidType,
    /// An operand unit differs from the dictionary; units are never converted.
    InvalidUnit,
    /// An operator or operand shape is not allowed by the field definition.
    InvalidOperation,
    /// An input explicitly contains a denied fact; the whole input is rejected.
    PermissionDenied,
    /// A validity interval ends at or before its observation time.
    InvalidTime,
    /// A rule, snapshot or member key belongs to another tenant.
    TenantMismatch,
    /// Required universe, coverage or explicit covered facts are missing.
    IncompleteSnapshot,
    /// Snapshot and rule dictionary versions differ.
    VersionMismatch,
    /// Repeated object keys carry different fact maps.
    ConflictingObject,
    /// A named fixed budget was exceeded; no truncated result is returned.
    LimitExceeded(LimitKind),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group input rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Group operation result with closed, value-free [`Error`] diagnostics.
pub type Result<T> = std::result::Result<T, Error>;

/// Fixed V1 input/work budgets; exceeding a budget never truncates output.
pub mod limits {
    /// Maximum AST depth, counting a predicate as one level.
    pub const DEPTH: usize = 16;
    /// Maximum AST nodes, including logical groups and predicates.
    pub const NODES: usize = 256;
    /// Maximum dictionary entries, coverage keys or facts per object.
    pub const FIELDS: usize = 128;
    /// Maximum scalar elements in one set.
    pub const SET_ITEMS: usize = 256;
    /// Maximum UTF-8 bytes in one string, including identities.
    pub const STRING_BYTES: usize = 4096;
    /// Maximum accumulated string bytes in a rule and dictionary validation.
    pub const RULE_BYTES: usize = 64 * 1024;
    /// Maximum entries in one snapshot or membership input list before deduplication.
    pub const OBJECTS: usize = 10_000;
    /// Maximum accumulated input string bytes in one evaluation/difference budget.
    pub const BATCH_BYTES: usize = 16 * 1024 * 1024;
    /// Maximum accumulated scalar items, including set elements and repeated inputs.
    pub const ITEMS: usize = 1_000_000;
    /// Maximum input-object count multiplied by AST node count.
    pub const VISITS: usize = 1_000_000;
    /// Maximum unique-object count multiplied by predicate count.
    pub const EXPLANATIONS: usize = 65_536;
}
/// Closed, low-cardinality budget identity; never carries caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// The [`limits::DEPTH`] budget.
    Depth,
    /// The [`limits::NODES`] budget.
    Nodes,
    /// The [`limits::FIELDS`] budget.
    Fields,
    /// The [`limits::SET_ITEMS`] budget.
    SetItems,
    /// The [`limits::STRING_BYTES`] budget.
    StringBytes,
    /// The [`limits::RULE_BYTES`] budget.
    RuleBytes,
    /// The [`limits::OBJECTS`] budget.
    Objects,
    /// The [`limits::BATCH_BYTES`] budget.
    BatchBytes,
    /// The [`limits::ITEMS`] budget.
    Items,
    /// The [`limits::VISITS`] budget.
    Visits,
    /// The [`limits::EXPLANATIONS`] budget.
    Explanations,
}
impl LimitKind {
    fn maximum(self) -> usize {
        match self {
            Self::Depth => limits::DEPTH,
            Self::Nodes => limits::NODES,
            Self::Fields => limits::FIELDS,
            Self::SetItems => limits::SET_ITEMS,
            Self::StringBytes => limits::STRING_BYTES,
            Self::RuleBytes => limits::RULE_BYTES,
            Self::Objects => limits::OBJECTS,
            Self::BatchBytes => limits::BATCH_BYTES,
            Self::Items => limits::ITEMS,
            Self::Visits => limits::VISITS,
            Self::Explanations => limits::EXPLANATIONS,
        }
    }
    pub(crate) fn check(self, n: usize) -> Result<()> {
        if n > self.maximum() {
            Err(Error::LimitExceeded(self))
        } else {
            Ok(())
        }
    }
    pub(crate) fn add(self, total: &mut usize, n: usize) -> Result<()> {
        let next = total.checked_add(n).ok_or(Error::LimitExceeded(self))?;
        self.check(next)?;
        *total = next;
        Ok(())
    }
    pub(crate) fn product(self, a: usize, b: usize) -> Result<()> {
        self.check(a.checked_mul(b).ok_or(Error::LimitExceeded(self))?)
    }
}

/// Shared by the entire rule or input batch, including duplicate/unused facts.
pub(crate) struct Budget {
    bytes: usize,
    byte_kind: LimitKind,
    items: usize,
}
impl Budget {
    pub(crate) fn new(byte_kind: LimitKind) -> Self {
        Self {
            bytes: 0,
            byte_kind,
            items: 0,
        }
    }
    pub(crate) fn items(&mut self, n: usize) -> Result<()> {
        LimitKind::Items.add(&mut self.items, n)
    }
    pub(crate) fn text(&mut self, s: &str) -> Result<()> {
        LimitKind::StringBytes.check(s.len())?;
        self.byte_kind.add(&mut self.bytes, s.len())
    }
    pub(crate) fn identity(&mut self, s: &str) -> Result<()> {
        self.text(s)?;
        if s.trim().is_empty() || s.chars().any(char::is_control) {
            return Err(Error::InvalidIdentity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_budget_arithmetic_preserves_the_limit_category() {
        for kind in [
            LimitKind::Nodes,
            LimitKind::RuleBytes,
            LimitKind::BatchBytes,
            LimitKind::Items,
        ] {
            let mut total = usize::MAX;
            assert_eq!(kind.add(&mut total, 1), Err(Error::LimitExceeded(kind)));
            assert_eq!(total, usize::MAX);
        }
        for kind in [LimitKind::Visits, LimitKind::Explanations] {
            assert_eq!(kind.product(usize::MAX, 2), Err(Error::LimitExceeded(kind)));
        }
    }

    #[test]
    fn every_scalar_kind_consumes_the_same_batch_item_budget() {
        for scalar in [
            Scalar::String(String::new()),
            Scalar::Boolean(false),
            Scalar::Integer(0),
            Scalar::Time(rss_contract::Timepoint::try_from(0).unwrap()),
        ] {
            let mut budget = Budget::new(LimitKind::BatchBytes);
            budget.items(limits::ITEMS - 1).unwrap();
            let value = Value::Scalar(scalar);
            assert_eq!(value.validate(&mut budget), Ok(()));
            assert_eq!(
                value.validate(&mut budget),
                Err(Error::LimitExceeded(LimitKind::Items))
            );
        }
    }

    #[test]
    fn set_reservation_rejects_over_budget_before_element_validation() {
        let mut budget = Budget::new(LimitKind::BatchBytes);
        budget.items(limits::ITEMS).unwrap();
        let invalid = Value::Set {
            element: ScalarType::Integer,
            values: std::collections::BTreeSet::from([Scalar::Boolean(false)]),
        };
        assert_eq!(
            invalid.validate(&mut budget),
            Err(Error::LimitExceeded(LimitKind::Items))
        );
    }
}
