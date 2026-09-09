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
pub use rule::{Criteria, Rule};

/// Closed diagnostics never contain fact values or caller-supplied strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    InvalidStructure,
    UnknownField,
    InvalidType,
    InvalidUnit,
    InvalidOperation,
    PermissionDenied,
    InvalidTime,
    TenantMismatch,
    IncompleteSnapshot,
    VersionMismatch,
    ConflictingObject,
    LimitExceeded,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group input rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Fixed V1 input/work budgets; exceeding a budget never truncates output.
pub mod limits {
    pub const DEPTH: usize = 16;
    pub const NODES: usize = 256;
    pub const FIELDS: usize = 128;
    pub const SET_ITEMS: usize = 256;
    pub const STRING_BYTES: usize = 4096;
    pub const RULE_BYTES: usize = 64 * 1024;
    pub const OBJECTS: usize = 10_000;
    pub const BATCH_BYTES: usize = 16 * 1024 * 1024;
    pub const VISITS: usize = 1_000_000;
    pub const EXPLANATIONS: usize = 65_536;
}
pub(crate) fn bound(n: usize, max: usize) -> Result<()> {
    if n > max {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}
pub(crate) fn text(s: &str, total: &mut usize) -> Result<()> {
    bound(s.len(), limits::STRING_BYTES)?;
    *total = total.checked_add(s.len()).ok_or(Error::LimitExceeded)?;
    Ok(())
}
pub(crate) fn identity(s: &str, total: &mut usize) -> Result<()> {
    text(s, total)?;
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(Error::InvalidIdentity);
    }
    Ok(())
}
