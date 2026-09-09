use crate::{Error, Result, bound, identity, limits, text};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

/// Complete business key. Device identity mapping belongs to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectKey {
    tenant: TenantId,
    id: String,
}
impl ObjectKey {
    /// Construct a key; rejects blank/control-character identifiers and overlong UTF-8 strings.
    pub fn new(tenant: TenantId, id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        identity(&id, &mut 0)?;
        Ok(Self { tenant, id })
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
impl Ord for ObjectKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tenant.octets(), &self.id).cmp(&(other.tenant.octets(), &other.id))
    }
}
impl PartialOrd for ObjectKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Supported primitive field types; no floating point or implicit coercions.
pub enum ScalarType {
    String,
    Boolean,
    Integer,
    Time,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A scalar or homogeneous set, including explicitly typed empty sets.
pub enum FieldType {
    Scalar(ScalarType),
    Set(ScalarType),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Typed literal; strings use exact UTF-8 equality and literal substring semantics.
pub enum Scalar {
    String(String),
    Boolean(bool),
    Integer(i64),
    Time(Timepoint),
}
impl Scalar {
    pub fn kind(&self) -> ScalarType {
        match self {
            Self::String(_) => ScalarType::String,
            Self::Boolean(_) => ScalarType::Boolean,
            Self::Integer(_) => ScalarType::Integer,
            Self::Time(_) => ScalarType::Time,
        }
    }
    pub(crate) fn validate(&self, bytes: &mut usize) -> Result<()> {
        if let Self::String(s) = self {
            text(s, bytes)?;
        }
        Ok(())
    }
}
/// Empty sets retain their element type. BTreeSet gives canonical set semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Scalar(Scalar),
    Set {
        element: ScalarType,
        values: BTreeSet<Scalar>,
    },
}
impl Value {
    pub fn kind(&self) -> FieldType {
        match self {
            Self::Scalar(v) => FieldType::Scalar(v.kind()),
            Self::Set { element, .. } => FieldType::Set(*element),
        }
    }
    pub(crate) fn validate(&self, bytes: &mut usize) -> Result<()> {
        match self {
            Self::Scalar(v) => v.validate(bytes)?,
            Self::Set { element, values } => {
                bound(values.len(), limits::SET_ITEMS)?;
                for v in values {
                    if v.kind() != *element {
                        return Err(Error::InvalidType);
                    }
                    v.validate(bytes)?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Closed V1 operator surface. Regex, legacy expressions and group references are absent.
pub enum Op {
    Eq,
    Ne,
    In,
    NotIn,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    NotContains,
    ContainsAny,
    ContainsAll,
    IsNull,
    IsNotNull,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Caller-owned dictionary entry. Units and allowed operations apply to every fact for this key.
pub struct Field {
    pub key: String,
    pub kind: FieldType,
    pub unit: Option<String>,
    pub operations: BTreeSet<Op>,
    pub nullable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Predicate value with the exact dictionary unit (None means unitless); never converted.
pub struct Operand {
    pub value: Value,
    pub unit: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Field comparison. IsNull/IsNotNull require no operand; all others require one.
pub struct Predicate {
    pub field: String,
    pub op: Op,
    pub operand: Option<Operand>,
}

/// Denied is an input error, not an unknown fact or an authorization proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactState {
    Known(Value),
    Null,
    Missing,
    Unsupported,
    Denied,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// One resolved source fact. Source selection is external; validity is [observed_at, valid_until).
pub struct Fact {
    pub state: FactState,
    pub source: String,
    pub snapshot_id: String,
    pub observed_at: Timepoint,
    pub valid_until: Option<Timepoint>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Facts for one complete tenant/device key. Each covered field must be present explicitly.
pub struct ObjectSnapshot {
    pub key: ObjectKey,
    pub facts: BTreeMap<String, Fact>,
}
/// Completeness describes the candidate universe, not whether all values are known.
/// In covered fields a missing value must be represented explicitly by FactState::Missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub tenant: TenantId,
    pub id: String,
    pub version: String,
    pub dictionary_version: String,
    pub complete: bool,
    pub coverage: BTreeSet<String>,
    pub objects: Vec<ObjectSnapshot>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Canonical set differences, retaining the tenant even when all three sets are empty.
pub struct Difference {
    pub tenant: TenantId,
    pub added: Vec<ObjectKey>,
    pub removed: Vec<ObjectKey>,
    pub unchanged: Vec<ObjectKey>,
}
pub(crate) fn members(
    tenant: TenantId,
    input: &[ObjectKey],
    bytes: &mut usize,
) -> Result<BTreeSet<ObjectKey>> {
    bound(input.len(), limits::OBJECTS)?;
    for key in input {
        if key.tenant != tenant {
            return Err(Error::TenantMismatch);
        }
        text(&key.id, bytes)?;
    }
    bound(*bytes, limits::BATCH_BYTES)?;
    Ok(input.iter().cloned().collect())
}
pub(crate) fn difference(
    tenant: TenantId,
    old: &BTreeSet<ObjectKey>,
    new: &BTreeSet<ObjectKey>,
) -> Difference {
    Difference {
        tenant,
        added: new.difference(old).cloned().collect(),
        removed: old.difference(new).cloned().collect(),
        unchanged: old.intersection(new).cloned().collect(),
    }
}
/// Pure set difference, including static members; no Criteria or persistence involved.
///
/// Returns TenantMismatch for any foreign key and LimitExceeded for list/string budgets.
/// Input order and duplicate keys do not affect the result.
pub fn diff(tenant: TenantId, old: &[ObjectKey], new: &[ObjectKey]) -> Result<Difference> {
    let mut bytes = 0;
    Ok(difference(
        tenant,
        &members(tenant, old, &mut bytes)?,
        &members(tenant, new, &mut bytes)?,
    ))
}
