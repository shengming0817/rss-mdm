use crate::{Budget, Error, LimitKind, Result};
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
    /// Bind a tenant to a nonblank identifier without control characters.
    /// Invalid text returns [`Error::InvalidIdentity`]; more than
    /// [`crate::limits::STRING_BYTES`] UTF-8 bytes returns [`Error::LimitExceeded`].
    /// Preserves the exact string and does not authenticate a device.
    pub fn new(tenant: TenantId, id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        Budget::new(LimitKind::BatchBytes).identity(&id)?;
        Ok(Self { tenant, id })
    }
    /// Return the tenant component of the key.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Borrow the exact caller-supplied object identifier.
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
    /// UTF-8 string, compared without case folding or normalization.
    String,
    /// Boolean value.
    Boolean,
    /// Signed 64-bit integer.
    Integer,
    /// Canonical UTC timepoint.
    Time,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A scalar or homogeneous set, including explicitly typed empty sets.
pub enum FieldType {
    /// One value of the selected primitive type.
    Scalar(ScalarType),
    /// A homogeneous set with the selected element type, including an empty set.
    Set(ScalarType),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Typed literal; strings use exact UTF-8 equality and literal substring semantics.
pub enum Scalar {
    /// Exact UTF-8 text; no regex or locale-specific comparison.
    String(String),
    /// Boolean literal.
    Boolean(bool),
    /// Signed 64-bit integer literal.
    Integer(i64),
    /// Canonical UTC timepoint literal.
    Time(Timepoint),
}
impl Scalar {
    /// Return the primitive type without converting the value.
    pub fn kind(&self) -> ScalarType {
        match self {
            Self::String(_) => ScalarType::String,
            Self::Boolean(_) => ScalarType::Boolean,
            Self::Integer(_) => ScalarType::Integer,
            Self::Time(_) => ScalarType::Time,
        }
    }
    pub(crate) fn validate(&self, budget: &mut Budget) -> Result<()> {
        if let Self::String(s) = self {
            budget.text(s)?;
        }
        Ok(())
    }
}
/// Empty sets retain their element type. BTreeSet gives canonical set semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// One typed scalar.
    Scalar(Scalar),
    /// A deduplicated ordered set whose elements must have the declared type.
    Set {
        /// Declared element type, retained even when the set is empty.
        element: ScalarType,
        /// Set members; heterogeneous values are rejected during rule/input validation.
        values: BTreeSet<Scalar>,
    },
}
impl Value {
    /// Return the declared field type; set element consistency is checked on validation.
    pub fn kind(&self) -> FieldType {
        match self {
            Self::Scalar(v) => FieldType::Scalar(v.kind()),
            Self::Set { element, .. } => FieldType::Set(*element),
        }
    }
    pub(crate) fn validate(&self, budget: &mut Budget) -> Result<()> {
        match self {
            Self::Scalar(v) => {
                budget.items(1)?;
                v.validate(budget)?;
            }
            Self::Set { element, values } => {
                LimitKind::SetItems.check(values.len())?;
                budget.items(values.len())?; // Reserve before traversing any scalar.
                for v in values {
                    if v.kind() != *element {
                        return Err(Error::InvalidType);
                    }
                    v.validate(budget)?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Closed V1 operator surface. Regex, legacy expressions and group references are absent.
pub enum Op {
    /// Scalar equality with an operand of the same type.
    Eq,
    /// Scalar inequality with an operand of the same type.
    Ne,
    /// A scalar belongs to the operand set of its type.
    In,
    /// A scalar does not belong to the operand set of its type.
    NotIn,
    /// Integer or time is strictly less than the operand.
    Lt,
    /// Integer or time is less than or equal to the operand.
    Le,
    /// Integer or time is strictly greater than the operand.
    Gt,
    /// Integer or time is greater than or equal to the operand.
    Ge,
    /// String contains the exact literal operand substring, including an empty one.
    Contains,
    /// String does not contain the exact literal operand substring.
    NotContains,
    /// Set intersects the operand set; an empty operand yields no match.
    ContainsAny,
    /// Set contains every operand element; an empty operand matches.
    ContainsAll,
    /// A nullable field is explicitly null; takes no operand.
    IsNull,
    /// A nullable field has a known non-null value; takes no operand.
    IsNotNull,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Caller-owned dictionary entry. Units and allowed operations apply to every fact for this key.
pub struct Field {
    /// Unique dictionary field identity.
    pub key: String,
    /// Required value and set-element type.
    pub kind: FieldType,
    /// Exact unit identity, or `None` for unitless values.
    pub unit: Option<String>,
    /// Nonempty allowed operator set, validated against kind and nullability.
    pub operations: BTreeSet<Op>,
    /// Whether explicit null facts and null-test operators are allowed.
    pub nullable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Predicate value with the exact dictionary unit (None means unitless); never converted.
pub struct Operand {
    /// Typed comparison value; set type is explicit even when empty.
    pub value: Value,
    /// Unit that must exactly match the field dictionary entry.
    pub unit: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Field comparison. IsNull/IsNotNull require no operand; all others require one.
pub struct Predicate {
    /// Dictionary key being compared.
    pub field: String,
    /// An operator permitted by the referenced field.
    pub op: Op,
    /// Absent for null tests; required with the appropriate type and unit otherwise.
    pub operand: Option<Operand>,
}

/// Denied is an input error, not an unknown fact or an authorization proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactState {
    /// A resolved typed value, validated against the dictionary.
    Known(Value),
    /// Explicit null on a nullable field; ordinary comparisons yield Unknown.
    Null,
    /// The source explicitly removed the value.
    Deleted,
    /// Current sources have conflicting values.
    Conflict,
    /// The field was covered but its value is missing.
    Missing,
    /// The source cannot provide this field.
    Unsupported,
    /// The caller could not access the fact; validation rejects the entire input.
    Denied,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// One resolved source fact. Source selection is external; times are provenance only.
pub struct Fact {
    /// Known value or explicit absence/support/permission condition.
    pub state: FactState,
    /// Caller-resolved source identity for provenance.
    pub source: String,
    /// Source snapshot identity for provenance.
    pub snapshot_id: String,
    /// Observation timestamp for provenance; never a validity window.
    pub observed_at: Timepoint,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Facts for one complete tenant/device key. Each covered field must be present explicitly.
pub struct ObjectSnapshot {
    /// Complete tenant/object key, which must match the snapshot tenant.
    pub key: ObjectKey,
    /// Explicit facts for every covered field, including missing-value markers.
    pub facts: BTreeMap<String, Fact>,
}
/// One bounded range of a frozen input. A page never asserts universe completeness.
/// The persistence owner binds all pages to the same input identity and seals the
/// result only after it has verified the complete source enumeration.
pub struct PageInput<'a> {
    /// Tenant shared by the rule, cursor and objects.
    pub tenant: TenantId,
    /// Frozen source identity.
    pub id: &'a str,
    /// Immutable source revision.
    pub version: &'a str,
    /// Dictionary identity used by all pages.
    pub dictionary_version: &'a str,
    /// Fields explicitly represented on every object, including Missing facts.
    pub coverage: &'a BTreeSet<String>,
    /// Strictly increasing objects; at most 1,000, further limited by work budgets.
    pub objects: &'a [ObjectSnapshot],
    /// Exclusive cursor confirmed by the previous durable page, if any.
    pub after: Option<&'a ObjectKey>,
}
/// Completeness describes the candidate universe, not whether all values are known.
/// In covered fields a missing value must be represented explicitly by FactState::Missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Tenant shared by rule and all objects.
    pub tenant: TenantId,
    /// Opaque source snapshot identity.
    pub id: String,
    /// Opaque immutable snapshot revision identity.
    pub version: String,
    /// Dictionary version that must equal the rule's version.
    pub dictionary_version: String,
    /// Caller assertion that the candidate universe is complete; not an authorization proof.
    pub complete: bool,
    /// Dictionary fields represented explicitly on every supplied object.
    pub coverage: BTreeSet<String>,
    /// Candidate facts; identical duplicate keys collapse, conflicting duplicates fail.
    pub objects: Vec<ObjectSnapshot>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// Canonical set differences, retaining the tenant even when all three sets are empty.
pub struct Difference {
    /// Tenant retained even for empty results.
    pub tenant: TenantId,
    /// Sorted keys in the new membership set but not the old set.
    pub added: Vec<ObjectKey>,
    /// Sorted keys in the old membership set but not the new set.
    pub removed: Vec<ObjectKey>,
    /// Sorted keys present in both sets.
    pub unchanged: Vec<ObjectKey>,
}
pub(crate) fn members(
    tenant: TenantId,
    input: &[ObjectKey],
    budget: &mut Budget,
) -> Result<BTreeSet<ObjectKey>> {
    LimitKind::Objects.check(input.len())?;
    for key in input {
        if key.tenant != tenant {
            return Err(Error::TenantMismatch);
        }
        budget.text(&key.id)?;
    }
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
    let mut budget = Budget::new(LimitKind::BatchBytes);
    Ok(difference(
        tenant,
        &members(tenant, old, &mut budget)?,
        &members(tenant, new, &mut budget)?,
    ))
}
